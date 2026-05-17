"""Integration tests for CallerJWTMiddleware.

Verifies the middleware:
  - Accepts requests with no Authorization header (no JWT presented).
  - 401s when a present-but-invalid JWT is offered.
  - Binds the resolved Caller to the ContextVar on success.
  - Bypasses verification for /healthz.
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

from romaine_auth import (
    CALLER,
    AuthRomaineLifeVerifier,
)
from mcp_azure_personal.http import CallerJWTMiddleware


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


def _build_app(signing_key, verifier: AuthRomaineLifeVerifier | None = None):
    if verifier is None:
        verifier = AuthRomaineLifeVerifier(
            issuer="https://auth.romaine.life",
            jwks_url="https://auth.romaine.life/api/auth/jwks",
            jwks_client=_StubJWKClient(signing_key),
        )

    async def whoami(request: Request) -> JSONResponse:
        caller = CALLER.get()
        if caller is None:
            return JSONResponse({"caller": None})
        return JSONResponse({
            "caller": {
                "sub": caller.sub,
                "email": caller.email,
                "role": caller.role,
                "actor_email": caller.actor_email,
                "display_actor": caller.display_actor,
            }
        })

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[Route("/whoami", whoami), Route("/healthz", healthz)],
        middleware=[Middleware(CallerJWTMiddleware, verifier=verifier)],
    )


def _mint(key, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://auth.romaine.life",
        "aud": "https://auth.romaine.life",
        "sub": "u-admin",
        "email": "ADMIN@example.com",
        "name": "Admin",
        "role": "admin",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})


def test_no_authorization_header_passes_through_as_unknown(signing_key):
    client = TestClient(_build_app(signing_key))
    r = client.get("/whoami")
    assert r.status_code == 200
    assert r.json() == {"caller": None}


def test_invalid_jwt_returns_401(signing_key):
    client = TestClient(_build_app(signing_key))
    r = client.get("/whoami", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert r.status_code == 401
    assert "invalid auth.romaine.life JWT" in r.json()["error"]


def test_valid_admin_jwt_binds_caller(signing_key):
    client = TestClient(_build_app(signing_key))
    token = _mint(signing_key)
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["caller"]["role"] == "admin"
    assert body["caller"]["email"] == "admin@example.com"
    assert body["caller"]["display_actor"] == "admin@example.com"


def test_valid_service_jwt_binds_actor_email(signing_key):
    client = TestClient(_build_app(signing_key))
    token = _mint(
        signing_key,
        role="service",
        email="pod-mcp-azure-personal@service.mcp-azure-personal.romaine.life",
        actor_email="USER@example.com",
        sub="svc:mcp-azure-personal:mcp-azure-personal",
    )
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["caller"]["role"] == "service"
    assert body["caller"]["actor_email"] == "user@example.com"
    assert body["caller"]["display_actor"] == "user@example.com"


def test_healthz_bypasses_jwt_verification(signing_key):
    """/healthz must work without auth — liveness probes don't carry a JWT."""
    client = TestClient(_build_app(signing_key))
    r = client.get("/healthz", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 200


def test_expired_jwt_returns_401(signing_key):
    client = TestClient(_build_app(signing_key))
    token = _mint(signing_key, exp=int(time.time()) - 120)
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_pending_role_returns_401(signing_key):
    client = TestClient(_build_app(signing_key))
    token = _mint(signing_key, role="pending")
    r = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
