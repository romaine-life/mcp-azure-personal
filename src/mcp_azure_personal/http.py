"""HTTP entrypoint for the personal Azure MCP server — stateful streamable-http,
layered auth, break-glass-gated tools that surface live on grant.

Auth layers:
  1. **kube-rbac-proxy** (in front of this process): validates the caller's K8s
     SA token via TokenReview + SubjectAccessReview. Binds loopback so direct
     pod-IP access bypasses nothing.
  2. **auth.romaine.life JWT** (CallerJWTMiddleware): verifies the inbound JWT
     against the IdP JWKS and binds the resolved Caller to a ContextVar for tool
     attribution. Arrives as ``Authorization: Bearer`` (workstation/admin) or the
     ``X-Auth-Romaine-Token`` header the mcp-auth-proxy sidecar injects.
  3. **Azure break-glass grant** (the real gate): enforced *inside* the MCP tool
     handlers, not as a blanket request middleware — so the MCP connection can
     stay healthy and stateful while the tools themselves are hidden + locked.

Break-glass surfacing model (why this server is stateful):
  - The server runs **stateful** streamable-http and advertises
    ``tools.listChanged``.
  - While a session has no active grant, ``list_tools`` returns **zero** tools
    and ``call_tool`` refuses with a JSON-RPC ``-32010``. (The mcp-auth-proxy
    still injects the ``request_azure_break_glass`` tool into the tools/list it
    forwards, so the agent always knows how to ask.) The connection is healthy.
  - On grant, the orchestrator POSTs ``/internal/grant-activated {session_id}``;
    the server fires ``notifications/tools/list_changed`` on that session's
    stream. The Claude MCP client auto-refreshes tools/list — which now returns
    the real tools — so they surface **live**, no reconnect, no restart. This is
    the SDK's native dynamic-tools path; empirically it is the mechanism that
    works (a mid-session reconnect does not re-register tools).

Layer 2 alone is best-effort attribution. Layer 3 is the boundary: a request
with no verified JWT or no active grant gets zero tools and refused calls
(fail closed).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import anyio
import jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.session import ServerSession
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData
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

# JSON-RPC error returned for a call while locked. Deliberately NOT a bare HTTP
# 403: the Claude MCP SDK treats a 403 on the MCP endpoint as an OAuth challenge.
_LOCKED_CODE = -32010
_LOCKED_MESSAGE = (
    "azure-personal MCP is locked: an approved Tank azure break-glass grant is "
    "required. Call request_azure_break_glass for an admin approval URL; the "
    "tools surface for this session automatically once a grant is approved."
)


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


def build_app(
    gate: AzureBreakGlassGate | None = None,
    verifier: AuthRomaineLifeVerifier | None = None,
    grant_activated_principals: frozenset[str] | None = None,
) -> Starlette:
    mcp = FastMCP(
        "azure-personal-mcp",
        # Stateful: the server keeps a per-session stream it can push
        # notifications/tools/list_changed on. Required for live surfacing.
        stateless_http=False,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    register_tools(mcp)

    # FastMCP advertises tools.listChanged=False by default (its
    # create_initialization_options() uses NotificationOptions(tools_changed=
    # False)). Force it True so the MCP client subscribes to
    # notifications/tools/list_changed — without this the client ignores the
    # surfacing notification and the tools never appear on grant.
    _orig_init_opts = mcp._mcp_server.create_initialization_options

    def _init_opts_tools_changed(notification_options=None, *args, **kwargs):
        return _orig_init_opts(
            notification_options or NotificationOptions(tools_changed=True),
            *args,
            **kwargs,
        )

    mcp._mcp_server.create_initialization_options = _init_opts_tools_changed

    # JWT verifier shared across all inbound requests. Construction touches no
    # network (PyJWKClient defers JWKS fetch until first verify).
    if verifier is None:
        verifier = default_verifier()
    if gate is None:
        gate = AzureBreakGlassGate.from_env()
    # /internal/grant-activated is taken OUT of the kube-rbac-proxy SA gate (the
    # chart adds it to --ignore-paths), so the auth.romaine.life service JWT is
    # the gate there instead. An empty allowlist still requires a valid
    # role=service caller; the chart pins this to the orchestrator's principal.
    if grant_activated_principals is None:
        grant_activated_principals = frozenset(
            p.strip()
            for p in os.environ.get("AZURE_GRANT_ACTIVATED_PRINCIPALS", "").split(",")
            if p.strip()
        )
    if gate.enforce:
        log.info("azure break-glass enforcement is ON; tools hidden+locked until a grant")
    else:
        log.warning("azure break-glass enforcement is OFF; MCP surface is open")

    # tank session_id -> the live ServerSession, captured on tools/list. Lets
    # /internal/grant-activated fire tools/list_changed on the exact session
    # whose grant just went active. Same event loop as the MCP handlers, so a
    # plain dict needs no lock.
    sessions: dict[str, ServerSession] = {}

    def _session_id(request: Request | None) -> str:
        if request is None:
            return ""
        return (request.headers.get("x-tank-caller-session-id", "") or "").strip()

    async def _grant_allowed(request: Request | None) -> bool:
        """Active-grant check for the request's session. Fail closed.

        Re-resolves the caller from the request's own headers rather than the
        CALLER ContextVar: in stateful streamable-http the tool handler runs in
        the session's task, whose context is the *session-open* request — so the
        per-request ContextVar is not guaranteed to be the current caller. The
        headers on ``request_context.request`` always are.
        """
        if not gate.enforce:
            return True
        if request is None:
            return False
        session_id = _session_id(request)
        token = (request.headers.get("x-auth-romaine-token", "") or "").strip()
        if not token:
            authz = request.headers.get("authorization", "")
            if authz.lower().startswith("bearer "):
                token = authz[len("bearer "):].strip()
        caller = None
        if token and verifier is not None:
            try:
                caller = verifier.verify(token)
            except Exception:
                caller = None
        # gate.allowed is synchronous (HTTP to tank-operator, cached); off-thread.
        return await anyio.to_thread.run_sync(gate.allowed, caller, session_id)

    @mcp._mcp_server.list_tools()
    async def list_tools_gated():
        # Overrides FastMCP's default list_tools: capture the session for
        # out-of-band notification, then gate visibility on the grant.
        ctx = mcp.get_context()
        request = ctx.request_context.request
        session_id = _session_id(request)
        if session_id and ctx.session is not None:
            sessions[session_id] = ctx.session
        if await _grant_allowed(request):
            return await mcp.list_tools()
        return []  # locked: zero real tools (proxy injects request_azure_break_glass)

    @mcp._mcp_server.call_tool(validate_input=False)
    async def call_tool_gated(name: str, arguments: dict):
        # Defense in depth: while locked the tools aren't listed, but refuse a
        # cached/guessed call too.
        ctx = mcp.get_context()
        if not await _grant_allowed(ctx.request_context.request):
            raise McpError(ErrorData(code=_LOCKED_CODE, message=_LOCKED_MESSAGE))
        return await mcp.call_tool(name, arguments)

    async def grant_activated(request: Request) -> Response:
        """Event-driven surfacing trigger.

        The orchestrator POSTs ``{"session_id": "..."}`` the moment an azure
        break-glass grant goes active. We fire tools/list_changed on that
        session's stream so the MCP client re-fetches tools/list (which now
        returns the real tools). Not security-sensitive: it only nudges a
        re-list, and list_tools re-checks the grant — so this can never surface
        tools for a session that does not actually hold a grant.

        Auth: this route is in the kube-rbac-proxy --ignore-paths, so the
        auth.romaine.life service JWT is the only gate. CallerJWTMiddleware is
        best-effort (a missing JWT arrives as caller=None), so enforce here.
        """
        caller = CALLER.get()
        if caller is None:
            return JSONResponse(
                {"ok": False, "reason": "auth.romaine.life service JWT required"},
                status_code=401,
            )
        if getattr(caller, "role", None) != "service":
            return JSONResponse(
                {"ok": False, "reason": "requires role=service"}, status_code=403
            )
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
        session = sessions.get(session_id)
        if session is None:
            return JSONResponse(
                {"ok": False, "reason": "no connected MCP session for session_id"},
                status_code=404,
            )
        try:
            await session.send_tool_list_changed()
        except Exception as exc:
            log.warning("grant-activated: send_tool_list_changed failed for %s: %s", session_id, exc)
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
        log.info("grant-activated: fired tools/list_changed for session %s", session_id)
        return JSONResponse({"ok": True})

    async def healthz(_: Request) -> Response:
        return Response("ok", media_type="text/plain")

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/internal/grant-activated", grant_activated, methods=["POST"]),
            # Stateful streamable-http handles GET (SSE), POST, and DELETE
            # (session teardown) itself — no custom DELETE shim needed.
            Mount("/", app=mcp.streamable_http_app()),
        ],
        middleware=[Middleware(CallerJWTMiddleware, verifier=verifier)],
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
