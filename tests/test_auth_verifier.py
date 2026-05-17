"""Tests for the auth.romaine.life inbound JWT verifier.

End-to-end JWKS fetch is hard to fake with PyJWKClient (it pulls from
urllib at verify-time, not a configurable HTTP client), so these tests
stub the signing key resolution directly via a PyJWKClient subclass
that returns a fixture-minted RSA key.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_azure_personal.auth_verifier import (
    AuthRomaineLifeVerifier,
    Caller,
)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _StubJWKClient:
    """Returns a fixed signing key regardless of the JWT's kid. The
    verifier uses .get_signing_key_from_jwt(token).key — we just need
    a .key attribute on the returned object."""

    def __init__(self, key):
        self._key = key

    def get_signing_key_from_jwt(self, _token: str):
        class _K:
            def __init__(self, key):
                self.key = key

        return _K(self._key.public_key())


def _verifier(key) -> AuthRomaineLifeVerifier:
    return AuthRomaineLifeVerifier(
        issuer="https://auth.romaine.life",
        jwks_url="https://auth.romaine.life/api/auth/jwks",
        jwks_client=_StubJWKClient(key),
    )


def _mint(key, **overrides: Any) -> str:
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


def test_verifier_accepts_admin(signing_key):
    v = _verifier(signing_key)
    token = _mint(signing_key)
    caller = v.verify(token)
    assert isinstance(caller, Caller)
    assert caller.role == "admin"
    assert caller.email == "admin@example.com"  # lowercased
    assert caller.is_admin
    assert not caller.is_service
    assert caller.is_human
    assert caller.raw_token == token


def test_verifier_accepts_user(signing_key):
    v = _verifier(signing_key)
    token = _mint(signing_key, role="user")
    caller = v.verify(token)
    assert caller.role == "user"
    assert caller.is_human
    assert not caller.is_admin


def test_verifier_accepts_service_with_actor_email(signing_key):
    v = _verifier(signing_key)
    token = _mint(
        signing_key,
        role="service",
        email="pod-mcp-azure-personal@service.mcp-azure-personal.romaine.life",
        actor_email="Operator@example.com",
        sub="svc:mcp-azure-personal:mcp-azure-personal",
    )
    caller = v.verify(token)
    assert caller.is_service
    assert caller.actor_email == "operator@example.com"  # lowercased
    assert caller.display_actor == "operator@example.com"


def test_verifier_rejects_service_without_actor_email(signing_key):
    v = _verifier(signing_key)
    token = _mint(
        signing_key,
        role="service",
        email="",
        actor_email="",
    )
    with pytest.raises(jwt.InvalidTokenError, match="actor_email"):
        v.verify(token)


def test_verifier_rejects_pending_role(signing_key):
    v = _verifier(signing_key)
    token = _mint(signing_key, role="pending")
    with pytest.raises(jwt.InvalidTokenError, match="role not approved"):
        v.verify(token)


def test_verifier_rejects_wrong_issuer(signing_key):
    v = _verifier(signing_key)
    token = _mint(signing_key, iss="https://impostor.example")
    with pytest.raises(jwt.InvalidIssuerError):
        v.verify(token)


def test_verifier_rejects_expired(signing_key):
    v = _verifier(signing_key)
    # exp in the past, beyond the 60s leeway window
    token = _mint(signing_key, exp=int(time.time()) - 120)
    with pytest.raises(jwt.ExpiredSignatureError):
        v.verify(token)


def test_verifier_rejects_wrong_signature(signing_key):
    v = _verifier(signing_key)
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": "https://auth.romaine.life",
            "aud": "https://auth.romaine.life",
            "sub": "u-admin",
            "email": "a@b",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        attacker,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    with pytest.raises(jwt.InvalidSignatureError):
        v.verify(token)


def test_verifier_rejects_missing_email_human_role(signing_key):
    v = _verifier(signing_key)
    token = _mint(signing_key, email="")
    with pytest.raises(jwt.InvalidTokenError, match="email"):
        v.verify(token)


def test_caller_display_actor_falls_back_to_email_for_human(signing_key):
    v = _verifier(signing_key)
    caller = v.verify(_mint(signing_key))
    assert caller.display_actor == "admin@example.com"
    assert caller.actor_email == ""
