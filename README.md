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
- **Never pass credentials as tool arguments** — use environment variables so that AI agents never see your username, password, or TOTP secret in their context.

## Credentials Setup

### Environment Variables

Set credentials in your shell profile so they are inherited by the MCP server process. The AI agent only needs to pass the target URL.

```bash
# Add to ~/.zshrc or ~/.zprofile (zsh) / ~/.bashrc (bash)
export OKTA_USERNAME="you@company.com"
export OKTA_PASSWORD="your-okta-password"
export OKTA_TOTP_SECRET="JBSWY3DPEHPK3PXP"  # only if MFA is enabled
```

After editing, reload your shell or open a new terminal, then restart the AI Agent.

The AI agent can then log in with just the URL:

```
okta_login(url="https://portal.company.com")
```

Explicit arguments still override environment variables if needed.

### How to Get Your TOTP Secret Key

The TOTP secret is the Base32 key (16–32 uppercase letters and digits) that backs your authenticator app. You need to obtain it **during the initial MFA enrollment** — it cannot be retrieved from an already-configured authenticator app.

#### During Okta MFA setup

1. In Okta, go to **Settings → Security Methods** (or follow your admin's enrollment link).
2. Choose **Google Authenticator** as the factor type.
3. The QR code screen also shows a **"Can't scan?"** link — click it.
4. Copy the displayed text key (e.g. `JBSWY3DPEHPK3PXP`). This is your `OKTA_TOTP_SECRET`.
5. Finish enrollment by entering the 6-digit code from your authenticator app to confirm.

> This project does **not** currently support portals that use **only** the Okta Verify app for MFA.

#### Already enrolled and lost the secret?

You must **re-enroll** the authenticator factor to obtain a new secret:

1. Go to **Okta → Settings → Security Methods**.
2. Remove the existing authenticator entry.
3. Re-add it and follow the steps above to capture the secret before scanning the QR code.

## Installation

### With uv

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
