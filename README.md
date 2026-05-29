# mcp-azure-personal

Personal Azure MCP server plus deployment chart.

## Layout

- `src/` - Python MCP server package.
- `Dockerfile` - image build for `romainecr.azurecr.io/mcp-azure-personal`.
- `chart/` - Helm chart synced by ArgoCD.

Images are SHA-tagged from `main`; `.github/workflows/build.yml` pushes the image and commits the matching chart tag.

## Postgres Tools

- `pg_query` runs read-only queries with `default_transaction_read_only=on`.
- `pg_execute` runs one write-capable DML statement (`INSERT`, `UPDATE`,
  `DELETE`, or `MERGE`) against allowlisted Azure Postgres hosts. It defaults
  to `dry_run=true`, rolls back dry runs, enforces statement timeout and
  affected-row caps, and commits only when `dry_run=false`.
