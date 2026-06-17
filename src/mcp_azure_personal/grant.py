"""Azure break-glass grant enforcement.

The azure-personal MCP is locked by default. A request to the MCP surface is
allowed only when, at request time:

  - the caller is on the configured exemption allowlist (e.g. Hermes, an
    always-on automation that legitimately needs unattended Azure), or
  - tank-operator reports an *active* azure break-glass grant for the caller's
    session.

The session is identified from the ``X-Tank-Caller-Session-Id`` header that the
mcp-auth-proxy sidecar injects on every call to this server. The grant is looked
up against tank-operator's internal endpoint
``GET /api/internal/sessions/{id}/azure-break-glass/grant``, presenting this
server's own ``role=service`` auth.romaine.life JWT — minted by exchanging the
pod's projected auth.romaine.life-audience SA token at ``/api/auth/exchange/k8s``
(the same shape the mcp-auth-proxy uses). Lookups are cached briefly so a burst
of tool calls does not fan out to tank-operator.

Failure is closed: if enforcement is on and the grant cannot be confirmed
active (no JWT, no session id, exchange/lookup error, or an inactive grant),
the request is denied. The agent's normal path back in is the
``request_azure_break_glass`` Tank MCP tool, which records a request and returns
an admin approval URL.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from threading import Lock

import requests

log = logging.getLogger(__name__)

CALLER_SESSION_ID_HEADER = "x-tank-caller-session-id"
AUTH_ROMAINE_FORWARD_HEADER = "x-auth-romaine-token"

DEFAULT_SA_TOKEN_FILE = "/var/run/secrets/auth.romaine.life/token"
DEFAULT_EXCHANGE_URL = "https://auth.romaine.life/api/auth/exchange/k8s"
DEFAULT_TANK_INTERNAL_URL = "http://tank-operator.tank-operator.svc.cluster.local"

_GRANT_CACHE_TTL_SECONDS = 15.0
_SERVICE_JWT_SKEW_SECONDS = 30.0
_HTTP_TIMEOUT_SECONDS = 10.0


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_expires_at(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return 0.0
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


class AzureBreakGlassGate:
    """Decides whether an MCP request may reach the Azure tools.

    Synchronous on purpose (uses ``requests``, the server's existing runtime
    dependency); the async middleware calls :meth:`allowed` in a worker thread.
    A single instance is held for the process lifetime so the service-JWT and
    per-session grant caches are shared across requests.
    """

    def __init__(
        self,
        *,
        enforce: bool,
        tank_internal_url: str = DEFAULT_TANK_INTERNAL_URL,
        exchange_url: str = DEFAULT_EXCHANGE_URL,
        sa_token_file: str = DEFAULT_SA_TOKEN_FILE,
        exempt_subjects: frozenset[str] = frozenset(),
        cache_ttl: float = _GRANT_CACHE_TTL_SECONDS,
    ) -> None:
        self._enforce = enforce
        self._tank_url = (tank_internal_url or "").rstrip("/")
        self._exchange_url = (exchange_url or "").rstrip("/")
        self._sa_token_file = sa_token_file
        self._exempt = frozenset(s.strip().lower() for s in exempt_subjects if s.strip())
        self._cache_ttl = cache_ttl
        self._service_jwt = ""
        self._service_jwt_exp = 0.0
        self._grant_cache: dict[str, tuple[float, bool]] = {}
        self._grant_cache_epoch: dict[str, int] = {}
        self._grant_cache_lock = Lock()

    @classmethod
    def from_env(cls) -> "AzureBreakGlassGate":
        exempt_raw = os.environ.get("AZURE_BREAK_GLASS_EXEMPT_SUBJECTS", "")
        exempt = frozenset(s.strip().lower() for s in exempt_raw.split(",") if s.strip())
        return cls(
            enforce=_env_flag("AZURE_BREAK_GLASS_ENFORCE", default=False),
            tank_internal_url=os.environ.get("TANK_OPERATOR_INTERNAL_URL", DEFAULT_TANK_INTERNAL_URL),
            exchange_url=os.environ.get("AUTH_ROMAINE_EXCHANGE_URL", DEFAULT_EXCHANGE_URL),
            sa_token_file=os.environ.get("AUTH_ROMAINE_SA_TOKEN_FILE", DEFAULT_SA_TOKEN_FILE),
            exempt_subjects=exempt,
        )

    @property
    def enforce(self) -> bool:
        return self._enforce

    def is_exempt(self, caller) -> bool:
        """True when the verified caller is on the exemption allowlist."""
        if caller is None or not self._exempt:
            return False
        candidates = {
            (caller.sub or "").strip().lower(),
            (caller.actor_email or "").strip().lower(),
            (caller.email or "").strip().lower(),
        }
        candidates.discard("")
        return bool(candidates & self._exempt)

    def allowed(self, caller, session_id: str) -> bool:
        """Return True if the request may proceed. Fail closed on any doubt."""
        if not self._enforce:
            return True
        if self.is_exempt(caller):
            return True
        # A verified caller is required: without a valid auth.romaine.life JWT
        # we cannot trust the session id header or scope a grant.
        if caller is None:
            return False
        session_id = (session_id or "").strip()
        if not session_id:
            return False
        return self._active_grant(session_id)

    def invalidate_grant_cache(self, session_id: str) -> bool:
        """Drop the cached grant decision for a Tank session.

        Called by the orchestrator's grant-activated notification after it has
        durably recorded an azure break-glass grant. Bumping the epoch prevents
        a stale in-flight lookup from writing a pre-grant ``False`` back into
        the cache after this invalidation lands.
        """
        session_id = (session_id or "").strip()
        if not session_id:
            return False
        with self._grant_cache_lock:
            existed = self._grant_cache.pop(session_id, None) is not None
            self._grant_cache_epoch[session_id] = self._grant_cache_epoch.get(session_id, 0) + 1
            return existed

    def _active_grant(self, session_id: str) -> bool:
        now = time.monotonic()
        with self._grant_cache_lock:
            cached = self._grant_cache.get(session_id)
            if cached is not None and cached[0] > now:
                return cached[1]
            epoch = self._grant_cache_epoch.get(session_id, 0)

        try:
            active = self._lookup_grant(session_id)
        except Exception as exc:  # network / exchange / parse — deny, briefly
            log.warning("azure break-glass grant check failed for session %s: %s", session_id, exc)
            active = False

        expires_at = time.monotonic() + self._cache_ttl
        with self._grant_cache_lock:
            current_epoch = self._grant_cache_epoch.get(session_id, 0)
            if current_epoch == epoch or active:
                self._grant_cache[session_id] = (expires_at, active)
        return active

    def _lookup_grant(self, session_id: str) -> bool:
        token = self._service_token()
        url = f"{self._tank_url}/api/internal/sessions/{session_id}/azure-break-glass/grant"
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        if resp.status_code >= 400:
            log.warning(
                "azure break-glass grant lookup returned HTTP %s for session %s",
                resp.status_code,
                session_id,
            )
            return False
        body = resp.json()
        return isinstance(body, dict) and body.get("active") is True

    def _service_token(self) -> str:
        now = time.time()
        if self._service_jwt and self._service_jwt_exp > now + _SERVICE_JWT_SKEW_SECONDS:
            return self._service_jwt
        with open(self._sa_token_file, "r", encoding="utf-8") as handle:
            sa_token = handle.read().strip()
        resp = requests.post(
            self._exchange_url,
            headers={"Authorization": f"Bearer {sa_token}"},
            json={},
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        body = resp.json()
        token = str(body.get("token") or "")
        exp = _parse_expires_at(body.get("expires_at"))
        if not token or exp <= now:
            raise RuntimeError("auth.romaine.life exchange returned an invalid service token")
        self._service_jwt = token
        self._service_jwt_exp = exp
        return token
