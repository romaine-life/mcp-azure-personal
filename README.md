# mcp-azure-personal

Personal Azure MCP server plus deployment chart.

## Layout

- `src/` - Python MCP server package.
- `Dockerfile` - image build for `romainecr.azurecr.io/mcp-azure-personal`.
- `chart/` - Helm chart synced by ArgoCD.

Images are SHA-tagged from `main`; `.github/workflows/build.yml` pushes the image and commits the matching chart tag.
