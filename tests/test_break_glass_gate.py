"""Tests for azure break-glass grant enforcement.

Covers the gate's decision logic (exempt callers, missing JWT/session,
active/inactive grants, caching, fail-closed) and the middleware that turns a
denied decision into a 403 — wired behind the real CallerJWTMiddleware so the
X-Auth-Romaine-Token header path is exercised end to end.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from romaine_auth import CALLER, AuthRomaineLifeVerifier, Caller
from mcp_azure_personal.grant import AzureBreakGlassGate
from mcp_azure_personal.http import AzureBreakGlassMiddleware, CallerJWTMiddleware


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _StubJWKClient:
    def __init__(self, key):
        self._key = key

    def get_signing_key_from_jwt(self, _token: str):
        class _K:
            def __init__(self, key):
                self.key = key

        return _K(self._key.public_key())


def _verifier(signing_key) -> AuthRomaineLifeVerifier:
    return AuthRomaineLifeVerifier(
        issuer="https://auth.romaine.life",
        jwks_url="https://auth.romaine.life/api/auth/jwks",
        jwks_client=_StubJWKClient(signing_key),
    )


def _mint(key, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": "https://auth.romaine.life",
        "aud": "https://auth.romaine.life",
        "sub": "u-1",
        "email": "user@example.com",
        "name": "User",
        "role": "service",
        "actor_email": "owner@example.com",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})


def _caller(**kw) -> Caller:
    base = dict(
        sub="u-1",
        email="user@example.com",
        name="User",
        role="service",
        actor_email="owner@example.com",
        raw_token="x",
    )
    base.update(kw)
    return Caller(**base)


def _build_app(signing_key, gate: AzureBreakGlassGate) -> Starlette:
    async def ok(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "caller": getattr(CALLER.get(), "actor_email", None)})

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[Route("/", ok, methods=["POST"]), Route("/healthz", healthz)],
        middleware=[
            Middleware(CallerJWTMiddleware, verifier=_verifier(signing_key)),
            Middleware(AzureBreakGlassMiddleware, gate=gate),
        ],
    )


# --- gate decision logic ---


def test_gate_disabled_allows_everything():
    gate = AzureBreakGlassGate(enforce=False)
    assert gate.allowed(None, "") is True
    assert gate.allowed(_caller(), "941") is True


def test_gate_requires_caller_and_session_when_enforcing():
    gate = AzureBreakGlassGate(enforce=True)
    assert gate.allowed(None, "941") is False  # no verified JWT
    assert gate.allowed(_caller(), "") is False  # no session id


def test_gate_exempt_subject_bypasses_grant_lookup(monkeypatch):
    gate = AzureBreakGlassGate(enforce=True, exempt_subjects=frozenset({"hermes@service.romaine.life"}))
    monkeypatch.setattr(
        gate, "_lookup_grant", lambda sid: (_ for _ in ()).throw(AssertionError("no lookup"))
    )
    assert gate.is_exempt(_caller(actor_email="hermes@service.romaine.life")) is True
    assert gate.allowed(_caller(actor_email="hermes@service.romaine.life"), "") is True


def test_gate_active_grant_allows_and_caches(monkeypatch):
    gate = AzureBreakGlassGate(enforce=True)
    calls: list[str] = []
    monkeypatch.setattr(gate, "_lookup_grant", lambda sid: (calls.append(sid), True)[1])
    assert gate.allowed(_caller(), "941") is True
    assert gate.allowed(_caller(), "941") is True
    assert calls == ["941"]  # second call served from cache


def test_gate_inactive_grant_denies(monkeypatch):
    gate = AzureBreakGlassGate(enforce=True)
    monkeypatch.setattr(gate, "_lookup_grant", lambda sid: False)
    assert gate.allowed(_caller(), "941") is False


def test_gate_fails_closed_on_lookup_error(monkeypatch):
    gate = AzureBreakGlassGate(enforce=True)

    def boom(_sid):
        raise RuntimeError("tank-operator unreachable")

    monkeypatch.setattr(gate, "_lookup_grant", boom)
    assert gate.allowed(_caller(), "941") is False


# --- middleware enforcement ---


def test_middleware_open_when_not_enforcing(signing_key):
    client = TestClient(_build_app(signing_key, AzureBreakGlassGate(enforce=False)))
    assert client.post("/").status_code == 200


def test_middleware_denies_without_jwt_when_enforcing(signing_key):
    client = TestClient(_build_app(signing_key, AzureBreakGlassGate(enforce=True)))
    r = client.post(
        "/",
        headers={"x-tank-caller-session-id": "941"},
        json={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {}},
    )
    # HTTP 200 with a JSON-RPC error — NOT a bare 403 (which makes the SDK
    # OAuth-trigger). The request id is echoed so the SDK matches the error.
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 7
    assert body["error"]["code"] == -32010
    assert "locked" in body["error"]["message"]
    assert "request_azure_break_glass" in body["error"]["message"]


def test_middleware_allows_with_jwt_and_active_grant(signing_key, monkeypatch):
    gate = AzureBreakGlassGate(enforce=True)
    monkeypatch.setattr(gate, "_lookup_grant", lambda sid: True)
    client = TestClient(_build_app(signing_key, gate))
    r = client.post(
        "/",
        headers={"x-auth-romaine-token": _mint(signing_key), "x-tank-caller-session-id": "941"},
    )
    assert r.status_code == 200
    assert r.json()["caller"] == "owner@example.com"


def test_middleware_denies_with_jwt_but_no_active_grant(signing_key, monkeypatch):
    gate = AzureBreakGlassGate(enforce=True)
    monkeypatch.setattr(gate, "_lookup_grant", lambda sid: False)
    client = TestClient(_build_app(signing_key, gate))
    r = client.post(
        "/",
        headers={"x-auth-romaine-token": _mint(signing_key), "x-tank-caller-session-id": "941"},
        json={"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {}},
    )
    assert r.status_code == 200
    assert r.json()["error"]["code"] == -32010


def test_middleware_healthz_bypasses_enforcement(signing_key):
    client = TestClient(_build_app(signing_key, AzureBreakGlassGate(enforce=True)))
    assert client.get("/healthz").status_code == 200


def test_middleware_exempt_caller_allowed_without_grant(signing_key, monkeypatch):
    gate = AzureBreakGlassGate(enforce=True, exempt_subjects=frozenset({"owner@example.com"}))
    monkeypatch.setattr(
        gate, "_lookup_grant", lambda sid: (_ for _ in ()).throw(AssertionError("no lookup"))
    )
    client = TestClient(_build_app(signing_key, gate))
    r = client.post(
        "/",
        headers={
            "x-auth-romaine-token": _mint(signing_key, actor_email="owner@example.com"),
            "x-tank-caller-session-id": "941",
        },
    )
    assert r.status_code == 200


def test_middleware_locked_allows_initialize_handshake(signing_key):
    # Locked = connected-but-tool-less: initialize is synthesized so the MCP
    # client connects cleanly (no error, no OAuth-trigger). A reconnect after a
    # grant then re-runs the real handshake + lists the real tools.
    client = TestClient(_build_app(signing_key, AzureBreakGlassGate(enforce=True)))
    r = client.post(
        "/",
        headers={"x-tank-caller-session-id": "941"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 1
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert "tools" in body["result"]["capabilities"]
    assert "error" not in body


def test_middleware_locked_returns_empty_tools_list(signing_key):
    client = TestClient(_build_app(signing_key, AzureBreakGlassGate(enforce=True)))
    r = client.post(
        "/",
        headers={"x-tank-caller-session-id": "941"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 2
    assert body["result"]["tools"] == []
    assert "error" not in body
