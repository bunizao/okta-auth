# okta-auth-mcp

> **Alpha** — this project is under active development and iterating quickly.
> APIs, tool signatures, and session formats may change between releases.

MCP server that performs Okta SSO login through Playwright and persists per-domain session state for reuse by AI agents.

## What It Provides

| Tool | Description |
|------|-------------|
| `okta_login` | Authenticate to a target URL and store session state |
| `okta_check_session` | Verify whether a stored session is still valid |
| `okta_list_sessions` | List saved sessions and metadata |
| `okta_delete_session` | Remove a stored session |
| `okta_get_cookies` | Retrieve cookies from stored session (sensitive) |

Sessions are stored under `~/.okta-auth-mcp/sessions/`.

## Security Model

- This server is intended for **local trusted execution**.
- Session files and cookies are sensitive credentials; protect the host account.
- Prefer private/internal usage unless security controls are reviewed.

## Installation

### With uv (recommended)

No manual install needed — use `uvx` to run directly:

```bash
uvx okta-auth-mcp
```

### With pip

```bash
pip install okta-auth-mcp
```

### Browser setup

The server uses Playwright for browser automation. It **automatically detects and prefers your system Chrome/Edge** — no extra download required if you already have one installed.

If no system browser is found, install the Playwright-bundled Chromium as fallback:

```bash
playwright install chromium
```

## MCP Client Configuration

### Claude Code

```bash
claude mcp add okta-auth -- uvx okta-auth-mcp
```

### Claude Desktop / Cursor / Windsurf

```json
{
  "mcpServers": {
    "okta-auth": {
      "command": "uvx",
      "args": ["okta-auth-mcp"]
    }
  }
}
```

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'
playwright install chromium
```

Run checks locally:

```bash
ruff format --check .
ruff check .
pytest
```

## Release

- Tag format: `vX.Y.Z`
- GitHub Actions builds distributions and publishes to PyPI with trusted publishing.
- Configure PyPI trusted publisher to enable release workflow.
