# okta-auth

> **Alpha**: this project is under active development. APIs, tool signatures, and
> session formats may change between releases.

`okta-auth` signs in to SAML apps and GlobalProtect VPN portals behind Okta
Identity Engine over plain HTTP. No browser. It has two entry points:

- `okta`: interactive CLI for humans
- `okta-auth`: MCP server for AI agents that reuse saved sessions

MFA is answered with a TOTP code (Google Authenticator, or Okta Verify's code).
Push-only MFA and Okta Classic Engine orgs are not supported.

Upgrading from 0.2.x? See [Migrating to 0.3.0](#migrating-to-030).

Sessions are stored under `~/.okta-auth/sessions/`. Existing sessions under
`~/.okta-auth-mcp/sessions/` are migrated automatically.

## Install

### uv tool

```bash
uv tool install okta-auth-cli
```

### pipx

```bash
pipx install okta-auth-cli
```

### pip

```bash
pip install okta-auth-cli
```

## Upgrade

- `uv tool`: `uv tool upgrade okta-auth-cli`
- `pipx`: `pipx upgrade okta-auth-cli`
- `pip`: `pip install -U okta-auth-cli`

## Quick Start

### 1. Configure credentials

Run the built-in wizard:

```bash
okta config
```

If the wizard asks for a TOTP secret and you are not sure where to find it, see
[TOTP Secret](#totp-secret).

The wizard supports two providers:

- `keyring`: store credentials in the OS credential manager
- `op`: generate `~/.okta-auth/op.env` with `op://...` references for `op run`

Only non-secret settings such as the default URL and provider metadata are stored
in `~/.okta-auth/config.json`.

### 2. Log in

```bash
okta
```

Or pass a target URL directly:

```bash
okta https://portal.company.com
```

`okta` exits with code 77 when Okta rejects the username or password. It never
retries on its own: repeated attempts can lock the account.

### 3. Reuse the session from MCP

Once configured, AI agents can authenticate with the saved session or with the
credential provider you configured.

## TOTP Secret

The TOTP secret is the Base32 key behind your authenticator app. You typically
must capture it during initial MFA enrollment.

### During Okta MFA setup

1. Go to **Settings -> Security Methods** in Okta.
2. Choose **Google Authenticator** or another TOTP-compatible factor.
3. On the QR screen, click **Can't scan?**
4. Copy the displayed Base32 secret.
5. Complete enrollment by entering the generated code.

This project does not currently support portals that rely only on the Okta Verify
push app for MFA.

### If you already enrolled and lost the secret

You usually need to remove and re-enroll the authenticator factor to get a new
secret.

## Credential Setup

Credential resolution order is:

1. Explicit CLI or MCP arguments
2. Environment variables
3. Stored keyring credentials when the selected provider is `keyring`

### Recommended: OS keyring

This is the default and recommended local setup:

```bash
okta config --provider keyring
```

What gets stored:

- `username`, `password`, `totp_secret`: OS keyring only
- `default_url`: `~/.okta-auth/config.json`

Typical keyring backends:

- macOS: Keychain Access
- Windows: Credential Manager / Credential Locker
- Linux: Secret Service or KWallet

If no secure backend is available, the wizard refuses to fall back to plaintext.

### 1Password CLI

If you already manage secrets in 1Password:

```bash
okta config --provider op
```

What gets stored:

- `vault`, `item`, field names, `default_url`: `~/.okta-auth/config.json`
- `OKTA_USERNAME`, `OKTA_PASSWORD`, optional `OKTA_TOTP_SECRET` references:
  `~/.okta-auth/op.env`

The generated env file contains `op://...` references, not plaintext values.

Launch the CLI or MCP server through `op run`:

```bash
op run --env-file=$HOME/.okta-auth/op.env -- okta
op run --env-file=$HOME/.okta-auth/op.env -- uvx --from okta-auth-cli okta-auth
```

1Password vault, item, and field names must be compatible with secret reference
paths. If a name contains unsupported separators such as `/`, use the object's
unique ID instead.

### Environment variables

Environment variables are still supported for CI, ephemeral shells, or external
secret managers. They override `okta config` values.

```bash
export OKTA_USERNAME="you@company.com"
export OKTA_PASSWORD="your-okta-password"
export OKTA_TOTP_SECRET="JBSWY3DPEHPK3PXP"
```

### Manual 1Password setup

If you do not want to use the wizard, you can set up `op run` manually.

1. Create a login item:

```bash
op item create --category login --title "Okta MCP" \
  username="you@company.com" \
  password="your-okta-password" \
  totp_secret="JBSWY3DPEHPK3PXP"
```

2. Create `~/.okta-auth/op.env`:

```bash
OKTA_USERNAME=op://Personal/Okta MCP/username
OKTA_PASSWORD=op://Personal/Okta MCP/password
OKTA_TOTP_SECRET=op://Personal/Okta MCP/totp_secret
```

3. Launch through `op run`:

```bash
op run --env-file=$HOME/.okta-auth/op.env -- uvx --from okta-auth-cli okta-auth
```

## CLI

### Common commands

- `okta [url]`: log in and save a session
- `okta config`: open the credential wizard
- `okta config --provider keyring`: force keyring configuration
- `okta config --provider op`: force 1Password configuration
- `okta config --show`: show current config status
- `okta config --reset`: remove saved config and credentials
- `okta check <url>`: verify a stored session
- `okta list`: list stored sessions
- `okta delete <url>`: delete a stored session
- `okta cookies <url>`: inspect stored cookies
- `okta globalprotect <server>`: sign in to a GlobalProtect portal or gateway
  and print OpenConnect's one-time cookie as JSON

### Example

```bash
okta https://portal.company.com --username you@company.com
```

### GlobalProtect

```bash
okta globalprotect vpn.company.com
```

prints `{"server", "interface", "user", "cookieName", "cookie"}`. It asks the
gateway first and falls back to the portal; `--interface gateway|portal` asks
only one. Hand the result to OpenConnect:

```bash
gp=$(okta globalprotect vpn.company.com)
jq -r .cookie <<<"$gp" | sudo openconnect --protocol=gp \
  --user="$(jq -r .user <<<"$gp")" \
  --usergroup="$(jq -r '.interface + ":" + .cookieName' <<<"$gp")" \
  --passwd-on-stdin vpn.company.com
```

The cookie works once. It is printed because OpenConnect needs it; don't log it.
Nothing is saved except Okta's device token.

### Exit codes

- `0`: success
- `1`: any other failure
- `77`: Okta rejected the username or password

## MCP Server

### MCP tools

| Tool | Description |
|------|-------------|
| `okta_login` | Authenticate to a target URL and store session state |
| `okta_check_session` | Verify whether a stored session is still valid |
| `okta_list_sessions` | List saved sessions and metadata |
| `okta_delete_session` | Remove a stored session |
| `okta_get_cookies` | Retrieve cookies from a stored session |

### Claude Code

```bash
claude mcp add okta-auth -- uvx --from okta-auth-cli okta-auth
```

If you use 1Password:

```bash
claude mcp add okta-auth -- op run --env-file=$HOME/.okta-auth/op.env -- uvx --from okta-auth-cli okta-auth
```

### Claude Desktop / Cursor / Windsurf

Default:

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

With 1Password:

```json
{
  "mcpServers": {
    "okta-auth": {
      "command": "op",
      "args": ["run", "--env-file=/Users/yourname/.okta-auth/op.env", "--", "uvx", "--from", "okta-auth-cli", "okta-auth"]
    }
  }
}
```

Use `okta` for the interactive CLI. Use `okta-auth` only when wiring the package
into an MCP client.

## Migrating to 0.3.0

0.3.0 replaces the Playwright browser with plain HTTP requests to Okta's IDX API.

- No browser to install. `playwright` and `pyotp` are no longer dependencies.
- `--headed`, `--timeout-ms` and `--settle-ms` are still accepted but ignored,
  with a warning. Drop them from scripts.
- The `okta_login` and `okta_check_session` MCP tools no longer take `headed`
  or `timeout_ms`. A failed `okta_login` result carries `error_code`
  (`credentials_rejected`, `passcode_rejected`, `mfa_unsupported`,
  `unexpected_step`, `handoff_failed`, `network` or `http_<status>`).
- `okta_auth.adapter.ensure_login(url)` no longer takes `headed` or `timeout_ms`;
  `OktaAdapterError` has a `code` attribute.
- `okta` exits 77 when Okta rejects the credentials.
- `okta check` follows the URL with the stored cookies: the session is active
  when live cookies reach a successful response on the same host without a
  login form.
- Session files keep the same format, now hold only the target site's cookies
  and are written with mode 0600. Okta's device token is kept in
  `~/.okta-auth/device-tokens.json`, so Okta keeps recognising this machine.
- Okta Classic Engine orgs and push-only MFA fail with a clear error instead of
  waiting on a browser.
- New: `okta globalprotect <server>`.

## Python API

```python
import asyncio
from okta_auth import OktaSignInError, sign_in, sign_in_globalprotect, totp

result = asyncio.run(
    sign_in(
        url="https://portal.company.com/login",
        username="you@company.com",
        password="...",
        totp_secret="JBSWY3DPEHPK3PXP",
        device_token=None,  # pass result.device_token back next time
    )
)
result.cookies  # the target site's cookies
result.device_token  # Okta's DT cookie
result.landing_url  # where the SAML post landed; may carry one-time tokens
result.okta_session  # Okta's session cookies, without DT
```

`sign_in` raises `OktaSignInError` with a `code`, and `ValueError` for bad input.
It never retries.

### Apps that start at Okta

Some apps (OnTrack, for one) have no page that redirects to Okta: sign-in starts
at the Okta app link, `https://<org>.okta.com/app/<name>/<id>/sso/saml`, and the
app hands back a one-time token in the URL it redirects to. Pass the app link as
`url`. `sign_in` then succeeds when the SAML post leaves Okta and ends on a 2xx
page that is not a login form, returns that site's cookies, and puts the final
URL in `landing_url`. Read the token from there; never log it.

### Several apps, one MFA answer

Pass `okta_session` from one result into the next `sign_in` and Okta skips the
password and one-time code while its session lasts. Without it, two sign-ins
inside the same 30-second window would send the same TOTP code twice, and Okta
refuses a reused code with `passcode_rejected`.

```python
moodle = await sign_in(url=moodle_login, **credentials, device_token=token)
ontrack = await sign_in(
    url=ontrack_app_link, **credentials, device_token=token, okta_session=moodle.okta_session
)
```

## Security

- This project is intended for local trusted execution.
- Session files and cookies are sensitive credentials.
- Prefer `okta config` over passing credentials directly on the command line.
- Prefer `keyring` or `op run` over plaintext shell files.
- Never post cookie values, passwords, or TOTP secrets in issues or logs.
- Credentials are only sent to the Okta host that served the sign-in page, and
  cookies only to the host that set them. Only `https://` URLs are accepted.
- Errors name a host and path, never passwords, codes, tokens, query strings or
  cookie values.

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'
```

Run checks locally:

```bash
ruff format --check .
ruff check .
mypy
pytest
```

Tests run against a scripted fake Okta org (`tests/fake_sso.py`), never a real
one.
