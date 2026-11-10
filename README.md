# okta-auth

Sign in to SAML apps and GlobalProtect VPN portals behind Okta Identity Engine
with plain HTTP. No browser. You give it a URL, a username, a password and a
TOTP secret; it returns the cookies the app set once you're signed in.

> **Alpha.** APIs and session formats may change before 1.0.

Two packages, same protocol, same tests, both called `okta-auth-cli`:

| Package | Install | For |
|---------|---------|-----|
| [TypeScript](typescript/README.md) | `npm install okta-auth-cli` | Node 22+, Bun, Cloudflare Workers; the `okta-auth` CLI |
| [Python](python/README.md) | `uv tool install okta-auth-cli` | Python 3.11+; the `okta` CLI and the `okta-auth` MCP server |

Both CLIs keep their state under `~/.okta-auth` and share Okta's device token,
so switching between them doesn't look like a new device to Okta. MFA is answered with a TOTP code (Google Authenticator, or Okta Verify's
code). Push-only MFA and Okta Classic Engine orgs are not supported.

See [CONTRIBUTING.md](CONTRIBUTING.md) to work on either package and
[SECURITY.md](SECURITY.md) to report a vulnerability.
