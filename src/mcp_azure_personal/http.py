"""HTTP entrypoint for the personal Azure MCP server — streamable-http
transport, layered auth.

Two layers gate inbound calls:

  1. **kube-rbac-proxy** (in front of this process): validates the
     caller's K8s SA token via TokenReview + SubjectAccessReview.
     "Some pod with an allowed SA is talking to me" — no human
     identity. Binding loopback so direct pod-IP:8080 access bypasses
     nothing.

  2. **auth.romaine.life JWT** (in this process): if the caller also
     presents an Authorization: Bearer JWT signed by auth.romaine.life,
     CallerJWTMiddleware verifies it against the IdP's JWKS and binds
     the resolved Caller (sub, email, role, actor_email) to a
     ContextVar. Tool handlers can attribute their work to a specific
     human via Caller.display_actor.

The JWT arrives either as ``Authorization: Bearer`` (workstation/admin callers)
or, from a Tank session pod, as the ``X-Auth-Romaine-Token`` header the
mcp-auth-proxy sidecar injects (because kube-rbac-proxy consumes ``Authorization``
for the SA-token check). The middleware accepts both.

  3. **Azure break-glass grant** (AzureBreakGlassMiddleware): when enforcement
     is on (``AZURE_BREAK_GLASS_ENFORCE``), the MCP surface is locked unless the
     caller is exempt (e.g. Hermes) or tank-operator reports an active azure
     break-glass grant for the caller's session. This is the boundary that
     makes azure-personal break-glass-only: it denies a direct in-cluster call,
     not just the localhost MCP path, because it lives in the server itself.

Layer 2 alone is best-effort attribution. Layer 3 is the real gate; with it on,
a request with no verified JWT or no active grant is refused (fail closed).
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

import anyio
import jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from romaine_auth import (
    CALLER,
    AuthRomaineLifeVerifier,
    default_verifier,
    warn_jwks_unreachable,
)
from .grant import AzureBreakGlassGate
from .tools import register_tools

log = logging.getLogger(__name__)


class CallerJWTMiddleware(BaseHTTPMiddleware):
    """Verify Authorization: Bearer JWT against auth.romaine.life's JWKS
    and bind the resolved Caller to a ContextVar.

    Verification is best-effort: missing or empty Authorization header
    leaves the Caller as None and proceeds (kube-rbac-proxy is still
    gating connectivity). A *present* but invalid JWT is rejected with
    401 — a malformed token is more suspect than no token.
    """

    # Routes that should bypass JWT verification entirely. /healthz is
    # the liveness probe path and shouldn't require auth.
    _BYPASS_PATHS = frozenset({"/healthz"})

    def __init__(self, app, verifier: AuthRomaineLifeVerifier | None = None):
        super().__init__(app)
        self._verifier = verifier

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._BYPASS_PATHS:
            return await call_next(request)

        # Tank session pods present the JWT as X-Auth-Romaine-Token (raw, no
        # "Bearer " prefix) because kube-rbac-proxy consumes Authorization for
        # the SA-token check. Workstation/admin callers use Authorization:
        # Bearer. Accept either; the forwarded header wins when both are set.
        token = request.headers.get("x-auth-romaine-token", "").strip()
        if not token:
            authz = request.headers.get("authorization", "")
            if not authz.lower().startswith("bearer "):
                # No JWT presented. kube-rbac-proxy is still doing its job;
                # we just don't get user attribution this call.
                return await call_next(request)
            token = authz[len("bearer "):].strip()

        if self._verifier is None:
            # Verifier not constructed (test env or misconfig). Skip
            # verification but log so we notice in production.
            log.warning("inbound bearer present but JWT verifier not configured; skipping")
            return await call_next(request)
        try:
            caller = self._verifier.verify(token)
        except (jwt.PyJWTError, ValueError) as exc:
            log.info("inbound JWT verification failed: %s", exc)
            return JSONResponse(
                {"error": "invalid auth.romaine.life JWT", "detail": str(exc)},
                status_code=401,
            )
        except Exception as exc:
            # PyJWKClient raises URLError / OSError on network failure.
            # Rate-limit the warning so a JWKS outage doesn't flood logs.
            warn_jwks_unreachable(
                os.environ.get("AUTH_ROMAINE_LIFE_JWKS_URL", "<default>"), exc
            )
            return JSONResponse(
                {"error": "JWKS unreachable; cannot verify inbound JWT"},
                status_code=503,
            )

        token_ctx = CALLER.set(caller)
        try:
            return await call_next(request)
        finally:
            CALLER.reset(token_ctx)


class AzureBreakGlassMiddleware(BaseHTTPMiddleware):
    """Lock the MCP surface behind an azure break-glass grant.

    Runs after CallerJWTMiddleware (so the verified Caller is bound). When the
    gate is enforcing, every MCP request must be backed by an active grant for
    the caller's session (or an exempt caller); otherwise it is refused with an
    MCP-shaped JSON-RPC error (HTTP 200) that points the agent at the
    request_azure_break_glass tool. We deliberately do NOT return a bare HTTP
    403: the Claude MCP SDK treats a 403 on the MCP endpoint as an OAuth
    challenge and falls into an `authenticate`/`complete_authentication` flow
    instead of cleanly reporting the locked state. /healthz and the DELETE
    session-teardown route are never gated.

    The grant check is synchronous (it calls tank-operator over HTTP) so it runs
    in a worker thread to avoid blocking the event loop; the gate caches results
    so steady-state calls do not hit the network.
    """

    _BYPASS_PATHS = frozenset({"/healthz", "/internal/grant-activated"})

    def __init__(self, app, gate: AzureBreakGlassGate):
        super().__init__(app)
        self._gate = gate

    async def dispatch(self, request: Request, call_next):
        if (
            not self._gate.enforce
            or request.method == "DELETE"
            or request.url.path in self._BYPASS_PATHS
        ):
            return await call_next(request)

        caller = CALLER.get()
        session_id = request.headers.get("x-tank-caller-session-id", "").strip()
        allowed = await anyio.to_thread.run_sync(self._gate.allowed, caller, session_id)
        if allowed:
            # Granted: pass straight through to the real MCP app (body untouched,
            # real handshake + real tools/list). A break-glass reconnect after a
            # grant lands here and surfaces the tools.
            return await call_next(request)

        # Locked. Synthesize MCP responses by method so the client connects
        # cleanly with ZERO tools — no error, no OAuth-trigger. azure-personal
        # stays in the session's .mcp.json from boot; while locked it is a
        # connected-but-tool-less server, and a reconnectMcpServer call after an
        # approved grant re-runs this dispatch with allowed=True, surfacing the
        # real tools live. We never call_next while locked, so the request body
        # is read only here (avoids BaseHTTPMiddleware draining it downstream).
        method = None
        rpc_id = None
        proto = "2025-06-18"
        try:
            payload = json.loads(await request.body())
            if isinstance(payload, dict):
                method = payload.get("method")
                rpc_id = payload.get("id")
                params = payload.get("params")
                if isinstance(params, dict) and params.get("protocolVersion"):
                    proto = str(params["protocolVersion"])
        except Exception:
            pass

        if method == "initialize":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": proto,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "azure-personal-mcp", "version": "0.0.0"},
                    },
                },
                status_code=200,
            )
        if isinstance(method, str) and method.startswith("notifications/"):
            return Response(status_code=202)
        if method == "tools/list":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": []}},
                status_code=200,
            )
        # tools/call (and anything else) while locked: clean MCP-shaped refusal
        # at HTTP 200 — never a bare 403, which the SDK treats as an OAuth challenge.
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32010,
                    "message": (
                        "azure-personal MCP is locked: an approved Tank azure "
                        "break-glass grant is required. Call request_azure_break_glass "
                        "for an admin approval URL; the tools surface for this session "
                        "once a grant is approved."
                    ),
                },
            },
            status_code=200,
        )


def build_app(
    gate: AzureBreakGlassGate | None = None,
    verifier: AuthRomaineLifeVerifier | None = None,
    grant_activated_principals: frozenset[str] | None = None,
) -> Starlette:
    mcp = FastMCP(
        "azure-personal-mcp",
        stateless_http=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    register_tools(mcp)

    async def healthz(_: Request) -> Response:
        return Response("ok", media_type="text/plain")

    async def delete_session(_: Request) -> Response:
        # FastMCP stateless mode returns 405 for DELETE, but Claude Code's MCP
        # client treats 405 as fatal. Return 200 so it can reconnect cleanly.
        return Response(status_code=200)

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    # JWT verifier shared across all inbound requests. Construction
    # touches no network — PyJWKClient defers JWKS fetch until first
    # verify — so it's safe at import time. If env points it at a
    # broken JWKS URL, the first verify fails with 503 (handled in
    # CallerJWTMiddleware) and the absence of a JWT on subsequent
    # requests is tolerated.
    if verifier is None:
        verifier = default_verifier()
    if gate is None:
        gate = AzureBreakGlassGate.from_env()
    if grant_activated_principals is None:
        grant_activated_principals = frozenset(
            p.strip()
            for p in os.environ.get("AZURE_GRANT_ACTIVATED_PRINCIPALS", "").split(",")
            if p.strip()
        )
    if gate.enforce:
        log.info("azure break-glass enforcement is ON; MCP surface requires an active grant")
    else:
        log.warning("azure break-glass enforcement is OFF; MCP surface is open")

    async def grant_activated(request: Request) -> Response:
        """Invalidate this session's grant cache after Tank records a grant.

        This does not grant access and does not push MCP notifications. It only
        clears azure-personal's short negative cache so the runner's next normal
        reconnect/rebuild immediately re-reads the durable grant from
        tank-operator.
        """
        caller = CALLER.get()
        if caller is None:
            return JSONResponse(
                {"ok": False, "reason": "auth.romaine.life service JWT required"},
                status_code=401,
            )
        if getattr(caller, "role", None) != "service":
            return JSONResponse({"ok": False, "reason": "requires role=service"}, status_code=403)
        if grant_activated_principals:
            identities = {
                (getattr(caller, "sub", "") or "").strip(),
                (getattr(caller, "actor_email", "") or "").strip(),
                (getattr(caller, "email", "") or "").strip(),
            }
            if not (identities & grant_activated_principals):
                log.info(
                    "grant-activated: rejected caller sub=%s (not an allowed principal)",
                    getattr(caller, "sub", None),
                )
                return JSONResponse(
                    {"ok": False, "reason": "caller not an allowed grant-activated principal"},
                    status_code=403,
                )
        try:
            body = await request.json()
        except Exception:
            body = {}
        session_id = str((body or {}).get("session_id", "") or "").strip()
        if not session_id:
            return JSONResponse({"ok": False, "reason": "session_id required"}, status_code=400)
        cache_invalidated = gate.invalidate_grant_cache(session_id)
        log.info(
            "grant-activated: invalidated grant cache for session %s",
            session_id,
            extra={"cache_entry_present": cache_invalidated},
        )
        return JSONResponse({"ok": True, "cache_invalidated": cache_invalidated})

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/internal/grant-activated", grant_activated, methods=["POST"]),
            Route("/", delete_session, methods=["DELETE"]),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        # Order matters: CallerJWTMiddleware (outermost) verifies the JWT and
        # binds the Caller, then AzureBreakGlassMiddleware enforces the grant.
        middleware=[
            Middleware(CallerJWTMiddleware, verifier=verifier),
            Middleware(AzureBreakGlassMiddleware, gate=gate),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", "8080"))
    uvicorn_kwargs = {"host": "127.0.0.1", "port": port}

    import uvicorn

    uvicorn.run(build_app(), **uvicorn_kwargs)


if __name__ == "__main__":
    main()
