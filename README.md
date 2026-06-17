# mcp-azure-personal

Personal Azure MCP server plus deployment chart.

## Layout

- `src/` - Python MCP server package.
- `Dockerfile` - image build for `romainecr.azurecr.io/mcp-azure-personal`.
- `chart/` - Helm chart synced by ArgoCD.

Images are SHA-tagged from `main`; `.github/workflows/build.yml` pushes the image and commits the matching chart tag.

## Break-glass access (locked by default)

This MCP is **locked by default**: normal Tank sessions cannot reach it. The
boundary lives in the server (`src/mcp_azure_personal/grant.py` +
`AzureBreakGlassMiddleware` in `http.py`), not in the sidecar — so a direct
in-cluster call is refused too, not just the localhost MCP path.

When `AZURE_BREAK_GLASS_ENFORCE=true`, every MCP request must be backed by an
**active Tank azure break-glass grant** for the caller's session (or an exempt
caller). The server identifies the session from the `X-Tank-Caller-Session-Id`
header the mcp-auth-proxy injects, verifies the `X-Auth-Romaine-Token` JWT, and
looks the grant up at tank-operator's
`GET /api/internal/sessions/{id}/azure-break-glass/grant`, presenting its own
`role=service` JWT minted from the projected `auth.romaine.life`-audience SA
token. No grant ⇒ the MCP handshake stays connected with zero tools, and tool
calls return a JSON-RPC locked error. The agent's path in is the Tank
`request_azure_break_glass` MCP tool (records a request, returns an admin
approval URL); see `romaine-life/tank-operator`
`docs/features/session-lifecycle/capabilities.md` → "Locked-by-default Azure
MCP".

When Tank records a grant it also POSTs `/internal/grant-activated` with a
service JWT. This endpoint does not grant access or push MCP notifications; it
only clears the short per-session grant cache so the runner's normal
reconnect/rebuild immediately observes the durable grant.

Config (chart `values.yaml` → `breakGlass`): `enforce` (default `false` — ships
inert), `exemptSubjects` (comma-separated JWT `sub`/`actor_email` allowlist for
unattended automation such as Hermes), `tankInternalUrl`, `exchangeUrl`,
`grantActivatedPrincipals`.

**Cutover order** (do not flip `enforce` to true before both): (1) `auth`
allowlists this server's SA (`mcp-azure-personal/mcp-azure-personal`) in
`K8S_SERVICE_SA_ALLOWLIST` so the token exchange works; (2) `exemptSubjects`
includes Hermes's service identity. Failure is closed, so a missing allowlist
entry or unreachable tank-operator denies access.

## Postgres Tools

- `pg_query` runs read-only queries with `default_transaction_read_only=on`.
- `pg_execute` runs one write-capable DML statement (`INSERT`, `UPDATE`,
  `DELETE`, or `MERGE`) against allowlisted Azure Postgres hosts. It defaults
  to `dry_run=true`, rolls back dry runs, enforces statement timeout and
  affected-row caps, and commits only when `dry_run=false`.
