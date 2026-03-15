# okta-auth

> **Alpha** — this project is under active development and iterating quickly.
> APIs, tool signatures, and session formats may change between releases.

Okta login toolkit with two entry points:

- `okta`: interactive CLI for humans to log in and save a session locally
- `okta-auth`: MCP server for AI agents that reuse those sessions

## CLI Usage

Run `okta` with no arguments to start an interactive login flow:

```bash
okta
```

Run `okta config` to open the interactive credential wizard:

```bash
okta config
```

The wizard supports two providers:

- `keyring`: store `OKTA_USERNAME`, `OKTA_PASSWORD`, and optional `OKTA_TOTP_SECRET`
  in the OS credential manager
- `op`: generate `~/.okta-auth/op.env` with `op://...` references for `op run`

Only non-secret settings such as the default portal URL and provider metadata are
stored in `~/.okta-auth/config.json`.

You can also pass values directly:

```bash
okta https://portal.company.com --username you@company.com
```

The login flow is headless by default. Pass `--headed` if you want to see the browser window.

Available commands:

- `okta [url]`: log in and save a session
- `okta config`: open the TUI credential wizard
- `okta config --provider keyring`: configure the local OS keyring explicitly
- `okta config --provider op`: configure 1Password CLI references explicitly
- `okta config --show`: inspect stored credential status without revealing secrets
- `okta config --reset`: delete stored credentials and local settings
- `okta check <url>`: verify a saved session
- `okta list`: list saved sessions
- `okta delete <url>`: delete a saved session
- `okta cookies <url>`: inspect stored cookies

## MCP Tools

| Tool | Description |
|------|-------------|
| `okta_login` | Authenticate to a target URL and store session state |
| `okta_check_session` | Verify whether a stored session is still valid |
| `okta_list_sessions` | List saved sessions and metadata |
| `okta_delete_session` | Remove a stored session |
| `okta_get_cookies` | Retrieve cookies from stored session (sensitive) |

Sessions are stored under `~/.okta-auth/sessions/`. Existing sessions under
`~/.okta-auth-mcp/sessions/` are migrated automatically.

## Security Model

- This project is intended for **local trusted execution**.
- Session files and cookies are sensitive credentials; protect the host account.
- Prefer private/internal usage unless security controls are reviewed.
- Prefer `okta config` so secrets are stored in the OS keyring instead of shell files.
- **Never pass credentials as tool arguments** unless you explicitly accept that risk.

## Credentials Setup

Credential resolution order is:

1. Explicit CLI or MCP arguments
2. Environment variables
3. Credentials saved by `okta config` in the OS keyring when the provider is `keyring`

### Recommended: `okta config --provider keyring`

The default local setup is the built-in TUI wizard with the `keyring` provider:

```bash
okta config --provider keyring
```

What it stores:

- `username`, `password`, `totp_secret`: OS keyring only
- `default_url`: `~/.okta-auth/config.json`

Backends used by `keyring` typically map to:

- macOS: Keychain Access
- Windows: Credential Locker / Windows Credential Manager
- Linux: Secret Service or KWallet

If no secure backend is available, the wizard refuses to save credentials rather than
falling back to plaintext files.

### 1Password CLI via `okta config --provider op`

If you already manage secrets in 1Password, the wizard can generate the `op run`
reference file for you:

```bash
okta config --provider op
```

In `op` mode the wizard stores:

- `vault`, `item`, field names, `default_url`: `~/.okta-auth/config.json`
- `OKTA_USERNAME`, `OKTA_PASSWORD`, optional `OKTA_TOTP_SECRET` references:
  `~/.okta-auth/op.env`

The generated env file contains `op://...` references, not plaintext credentials.
Vault, item, and field names must use characters supported by 1Password secret
references. If a name contains unsupported separators such as `/`, use the
object's unique ID instead.

Use it to launch the CLI or MCP server:

```bash
op run --env-file=$HOME/.okta-auth/op.env -- okta
op run --env-file=$HOME/.okta-auth/op.env -- uvx --from okta-auth-cli okta-auth
```

### Environment Variables

Environment variables remain supported for CI, ephemeral shells, or when you prefer an
external secret manager. They override any credentials saved by `okta config`.

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

### Manual 1Password CLI Setup

[`op run`](https://developer.1password.com/docs/cli/secrets-scripts/) injects secrets at process launch time. No plaintext credentials appear in shell profiles, config files, or environment variables — they live only in 1Password.

**1. Store credentials in 1Password** (one-time setup):

```bash
op item create --category login --title "Okta MCP" \
  username="you@company.com" \
  password="your-okta-password" \
  totp_secret="JBSWY3DPEHPK3PXP"
```

**2. Create a secrets reference file** at `~/.okta-auth/.env` (contains paths, not values):

```bash
OKTA_USERNAME=op://Personal/Okta MCP/username
OKTA_PASSWORD=op://Personal/Okta MCP/password
OKTA_TOTP_SECRET=op://Personal/Okta MCP/totp_secret
```

**3. Update your MCP client config** to wrap the server with `op run`:

_Claude Code:_
```bash
claude mcp add okta-auth -- op run --env-file=$HOME/.okta-auth/.env -- uvx --from okta-auth-cli okta-auth
```

_Claude Desktop / Cursor / Windsurf:_
```json
{
  "mcpServers": {
    "okta-auth": {
      "command": "op",
      "args": ["run", "--env-file=/Users/yourname/.okta-auth/.env", "--", "uvx", "--from", "okta-auth-cli", "okta-auth"]
    }
  }
}
```

`op run` prompts for biometric/Touch ID once per session. Install 1Password CLI via `brew install 1password-cli`.

### macOS Keychain

A built-in alternative that requires no extra tools. Credentials are stored in the system Keychain and fetched on each shell startup.

**Store** (one-time, run in terminal):

```bash
security add-generic-password -a okta-mcp -s OKTA_USERNAME    -w "you@company.com"
security add-generic-password -a okta-mcp -s OKTA_PASSWORD    -w "your-okta-password"
security add-generic-password -a okta-mcp -s OKTA_TOTP_SECRET -w "JBSWY3DPEHPK3PXP"
```

**Load** in `~/.zshrc` or `~/.zprofile`:

```bash
export OKTA_USERNAME=$(security find-generic-password    -a okta-mcp -s OKTA_USERNAME    -w 2>/dev/null)
export OKTA_PASSWORD=$(security find-generic-password    -a okta-mcp -s OKTA_PASSWORD    -w 2>/dev/null)
export OKTA_TOTP_SECRET=$(security find-generic-password -a okta-mcp -s OKTA_TOTP_SECRET -w 2>/dev/null)
```

macOS may prompt for Keychain access on the first load after a reboot.

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

### With uv tool

```bash
uv tool install okta-auth-cli
okta config
okta
```

### With pipx

```bash
pipx install okta-auth-cli
okta config
okta
```

### With pip

```bash
pip install okta-auth-cli
okta config
okta
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
claude mcp add okta-auth -- uvx --from okta-auth-cli okta-auth
```

### Claude Desktop / Cursor / Windsurf

```json
{
  "mcpServers": {
    "okta-auth": {
      "command": "uvx",
      "args": ["--from", "okta-auth-cli", "okta-auth"]
    }
  }
}
```

Use `okta` for the interactive CLI. Use `okta-auth` only when wiring the package into an MCP client.

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
