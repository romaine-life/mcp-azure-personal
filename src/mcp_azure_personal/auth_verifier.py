"""Inbound JWT verifier for auth.romaine.life-issued tokens.

mcp-azure-personal sits behind kube-rbac-proxy, which already gates
on the calling pod's K8s SA token. That tells us "some pod with an
allowed SA is talking to us" but carries no human identity. This
module verifies any Authorization: Bearer JWT the caller also
presents, so mcp-azure-personal learns who the call is for: a tank
session's user, a service principal, a bot-token-wielding admin,
etc.

Auth.romaine.life is the platform's single IdP. Tokens are RS256-
signed with the IdP's KV-backed key; the public key set is published
at /api/auth/jwks. Verification: signature against JWKS, iss claim
matches the IdP, role claim is in the allowed closed set, exp not
passed.

The middleware in http.py runs this verifier on every inbound request,
optional: if no Authorization header is present, the caller stays as
"unknown" — kube-rbac-proxy is still gating who can connect. When a
JWT IS present, it must verify successfully or the request is rejected
with 401. (Half-trusting a malformed JWT would be worse than no JWT.)

This module is a direct copy of mcp-glimmung's auth_verifier.py with
the package path adjusted. The eventual home is a shared lib so the
four kube-rbac-proxy-gated MCPs (mcp-glimmung, mcp-k8s, mcp-argocd,
mcp-azure-personal) share one verifier implementation.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWKClient

log = logging.getLogger(__name__)

DEFAULT_AUTH_ROMAINE_LIFE_ISSUER = "https://auth.romaine.life"
DEFAULT_AUTH_ROMAINE_LIFE_JWKS_URL = "https://auth.romaine.life/api/auth/jwks"

# Closed set of roles mcp-azure-personal accepts on inbound JWTs.
# Mirrors glimmung's own gate (internal/auth/romaine_jwt.go's
# RomaineRoleAdmin / User / Service). `pending` is the default for
# fresh Microsoft sign-ins that haven't been promoted by an admin;
# reject it here so a half-onboarded user can't reach the tool surface.
ALLOWED_ROLES = frozenset({"admin", "user", "service"})

# Cap signature/issuer/role check leeway on clock skew between
# mcp-azure-personal and the IdP. Matches the Go verifier's 60s window.
_LEEWAY_SECONDS = 60


@dataclass(frozen=True)
class Caller:
    """Resolved caller identity from a verified inbound JWT.

    `actor_email` is the meaningful "who triggered this" field for
    service principals — the human on whose behalf the bot is acting,
    minted at exchange time. For human-role tokens (admin/user)
    actor_email is empty and `email` is the human directly.
    """

    sub: str
    email: str
    name: str
    role: str
    actor_email: str
    raw_token: str

    @property
    def is_service(self) -> bool:
        return self.role == "service"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_human(self) -> bool:
        return self.role in ("admin", "user")

    @property
    def display_actor(self) -> str:
        """Best-effort human identity for logging/audit. Falls back to
        email when there's no actor_email (i.e., the human role path)."""
        return self.actor_email or self.email


class AuthRomaineLifeVerifier:
    """Verifies inbound JWTs against auth.romaine.life's JWKS.

    PyJWKClient handles the JWKS cache; it fetches once and refreshes
    on key-not-found. We hold a single instance for the lifetime of
    the process — concurrent verifies share its in-process cache.
    """

    def __init__(
        self,
        *,
        issuer: str = DEFAULT_AUTH_ROMAINE_LIFE_ISSUER,
        jwks_url: str = DEFAULT_AUTH_ROMAINE_LIFE_JWKS_URL,
        leeway: int = _LEEWAY_SECONDS,
        jwks_client: PyJWKClient | None = None,
    ) -> None:
        self._issuer = issuer
        self._leeway = leeway
        self._jwks = jwks_client or PyJWKClient(jwks_url, cache_keys=True)
        self._lock = threading.Lock()

    def verify(self, token: str) -> Caller:
        """Verify the token and return the resolved caller.

        Raises InvalidTokenError (or one of PyJWT's subclasses) on any
        verification failure. The HTTP middleware turns those into 401s.
        """
        with self._lock:
            signing_key = self._jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=self._issuer,
            options={
                "require": ["exp", "iat", "iss", "role"],
                # Audience pinning is optional in this platform — every
                # auth.romaine.life-issued token today uses aud=<issuer>
                # which provides no per-app isolation. Skip aud
                # verification rather than fail closed; per-app aud
                # pinning is a separate design decision.
                "verify_aud": False,
            },
            leeway=self._leeway,
        )
        role = (claims.get("role") or "").strip()
        if role not in ALLOWED_ROLES:
            raise jwt.InvalidTokenError(f"role not approved: {role!r}")

        email = (claims.get("email") or "").strip().lower()
        actor_email = (claims.get("actor_email") or "").strip().lower()
        if role == "service":
            # Service tokens MUST carry actor_email — upstream refuses to
            # mint them otherwise. Seeing one here means tampering or an
            # upstream regression; fail loud rather than silently
            # downgrade the call to "service with no actor."
            if not actor_email:
                raise jwt.InvalidTokenError("service token missing actor_email")
            if not email:
                # Service tokens routinely omit `email` (the synthetic is
                # the actor's identity). Backfill so downstream consumers
                # logging Email get a usable string.
                email = actor_email
        else:
            if not email:
                raise jwt.InvalidTokenError("token missing email claim")

        return Caller(
            sub=str(claims.get("sub") or ""),
            email=email,
            name=str(claims.get("name") or ""),
            role=role,
            actor_email=actor_email,
            raw_token=token,
        )


def default_verifier() -> AuthRomaineLifeVerifier:
    """Construct a verifier from env-driven config. Production uses
    defaults; tests use the env vars to point at a stub JWKS server."""
    issuer = os.environ.get("AUTH_ROMAINE_LIFE_ISSUER", DEFAULT_AUTH_ROMAINE_LIFE_ISSUER)
    jwks_url = os.environ.get("AUTH_ROMAINE_LIFE_JWKS_URL", DEFAULT_AUTH_ROMAINE_LIFE_JWKS_URL)
    return AuthRomaineLifeVerifier(issuer=issuer, jwks_url=jwks_url)


# --- caller context ---

from contextvars import ContextVar

CALLER: ContextVar[Caller | None] = ContextVar(
    "mcp_azure_personal_caller", default=None
)


def current_caller() -> Caller | None:
    """Return the verified caller identity for the current request, or
    None if no inbound JWT was presented (kube-rbac-proxy is still
    gating; we just don't have user attribution)."""
    return CALLER.get()


# Module-level cache of "did we tell the user about the absence of JWT
# verification" so the logs don't flood. Used by the middleware in
# http.py to log once at startup if AUTH_ROMAINE_LIFE_JWKS_URL is
# unreachable rather than per request.
_warned_jwks_unreachable: dict[str, float] = {}
_WARN_THROTTLE_SECONDS = 300


def warn_jwks_unreachable(jwks_url: str, err: Exception) -> None:
    """Rate-limited warning when JWKS fetch fails. Called by the
    middleware when verification raises a connection error so logs
    don't drown in repeated failures."""
    now = time.time()
    last = _warned_jwks_unreachable.get(jwks_url, 0.0)
    if now - last < _WARN_THROTTLE_SECONDS:
        return
    _warned_jwks_unreachable[jwks_url] = now
    log.warning("auth.romaine.life JWKS unreachable: %s err=%s", jwks_url, err)


def _hint_token_shape(token: str) -> dict[str, Any]:
    """Test helper: peek at a JWT's header without verifying. Useful for
    debugging which key the IdP is signing with."""
    try:
        header = jwt.get_unverified_header(token)
        return {"alg": header.get("alg"), "kid": header.get("kid")}
    except Exception:
        return {}
