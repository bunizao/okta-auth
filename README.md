# okta-auth

> Sign in to apps behind Okta Identity Engine over plain HTTP. No browser, no runtime dependencies.

[![npm](https://img.shields.io/npm/v/okta-auth-cli?logo=npm)](https://www.npmjs.com/package/okta-auth-cli)
[![PyPI](https://img.shields.io/pypi/v/okta-auth-cli?logo=pypi&logoColor=white)](https://pypi.org/project/okta-auth-cli/)
[![CI](https://github.com/bunizao/okta-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/bunizao/okta-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

okta-auth is a sign-in library for services that need a session in an
Okta-protected app on their own: scripts, scheduled jobs, backend services,
Cloudflare Workers, VPN clients. Give it the app's URL, a username, a password
and a TOTP secret. It follows the redirects into Okta, answers the Identity
Engine (IDX) sign-in steps, posts the SAML response back to the app, and returns
the cookies the app set.

```ts
import { signIn } from "okta-auth-cli";

const { cookies } = await signIn({
  url: "https://app.example.com/login",
  username: "user@example.com",
  password: process.env.OKTA_PASSWORD!,
  totpSecret: process.env.OKTA_TOTP_SECRET,
});
```

## Features

- **Plain HTTP.** The core uses only `fetch` and WebCrypto, so it runs unchanged
  in Node 22+, Bun and Cloudflare Workers. A Python port mirrors it.
- **SAML apps** that redirect or post their `SAMLRequest` to Okta, Okta app
  links (IdP-initiated SAML), and OIDC apps Okta redirects back to.
- **TOTP MFA** with a built-in RFC 6238 generator, or a callback that fetches the
  current code from a password manager.
- **Session reuse.** Pass Okta's session from one sign-in to the next and a
  second app signs in without MFA. Okta's device token persists across runs.
- **GlobalProtect.** Signs in to a Palo Alto GlobalProtect gateway or portal and
  returns the one-time cookie for OpenConnect.
- **Fails safe.** Never retries, throws typed error codes, and keeps secrets out
  of every message.

## Packages

| | TypeScript | Python |
| --- | --- | --- |
| Install | `npm install okta-auth-cli` | `pip install okta-auth-cli` |
| Runtimes | Node 22+, Bun, Cloudflare Workers | Python 3.11+ |
| Library | `signIn()` | `await sign_in()` |
| CLI | `okta-auth` | `okta` (plus an MCP server, `okta-auth`) |
| Docs | [typescript/](typescript/README.md) | [python/](python/README.md) |

Both packages implement the same protocol and pass the same scripted test cases.
The Python API mirrors the one below in snake_case, with seconds instead of
milliseconds.

## API

### `signIn(options): Promise<SignInResult>`

Signs in once and returns the target site's cookies.

| Option | Type | Description |
| --- | --- | --- |
| `url` | `string` | An `https` page that sends signed-out visitors to Okta, or an Okta app link (`https://<org>.okta.com/app/<name>/<id>/sso/saml`). |
| `username` | `string` | |
| `password` | `string` | Sent only to the Okta host that served the sign-in page. |
| `totpSecret` | `string?` | Base32 secret of a TOTP authenticator. |
| `totpCode` | `() => Promise<string>` | Returns the current code. Called only when Okta asks; wins over `totpSecret`. |
| `deviceToken` | `string?` | Okta's `DT` cookie from an earlier result, so Okta sees a known device. |
| `oktaSession` | `Cookie[]?` | Okta's session from an earlier result. Skips the password and MFA while it lasts. |
| `fetch` | `Fetch?` | A custom `fetch`, for proxies or tests. |
| `now` | `() => number` | Clock in ms since epoch. Drives TOTP and cookie expiry. |
| `onProgress` | `(message: string) => void` | Called with a redacted message before each step. |

| Result | Type | Description |
| --- | --- | --- |
| `cookies` | `Cookie[]` | Cookies the target host set, and only those. |
| `deviceToken` | `string \| undefined` | Okta's `DT` cookie. Store it and pass it back. |
| `landingUrl` | `string` | Where the SAML post landed. May carry one-time tokens: read them, never log them. |
| `oktaSession` | `Cookie[]` | Okta's session cookies, without `DT`. |

```ts
// Two apps, one MFA answer.
const first = await signIn({ url: appA, ...credentials, deviceToken });
const second = await signIn({ url: appB, ...credentials, deviceToken, oktaSession: first.oktaSession });
```

### `signInGlobalProtect(options): Promise<GlobalProtectResult>`

Takes the credential options of `signIn` plus `server` (a host name) and
`interface` (`"gateway"` or `"portal"`; by default the gateway, then the
portal). Returns `{ interface, user, cookieName, cookie, deviceToken }`. The
cookie works once:

```bash
openconnect --protocol=gp --user="$user" --usergroup="gateway:prelogin-cookie" \
  --passwd-on-stdin vpn.example.com <<<"$cookie"
```

### `totp(secret, now?): Promise<string>`

The current 6-digit RFC 6238 code for a base32 secret.

### `OktaSignInError`

Invalid input (a non-`https` URL, a secret that isn't base32) throws a
`TypeError` before any request. Everything after that throws `OktaSignInError`
with a `code`, and `deviceToken` when Okta set one before the failure.

| `code` | Meaning | Retry |
| --- | --- | --- |
| `credentials_rejected` | Okta refused the username or password. | **Never automatically.** Each attempt counts towards lockout. |
| `passcode_rejected` | Okta refused the one-time code: wrong secret, clock skew, or a reused code. | Once, in the next 30-second window. |
| `mfa_unsupported` | Okta wants push, SMS, email or another authenticator this can't answer. | No |
| `unexpected_step` | Okta asked for something unknown, such as an expired password or a required new authenticator. The message names the step. | No |
| `handoff_failed` | Okta signed in, but the app still isn't signed in after the SAML post. | No |
| `network` | A request timed out (15 s) or failed. | With backoff |
| `http_<status>` | A page or IDX call answered with that status. | 5xx and 429, with backoff |

Messages name hosts, paths and IDX step names. They never contain passwords,
codes, the TOTP secret, state tokens, query strings or cookie values.

## CLI

Both packages ship a CLI that saves sessions under `~/.okta-auth`. The
TypeScript one:

```bash
okta-auth login https://app.example.com/login   # sign in and save the app's cookies
okta-auth cookies https://app.example.com       # print a Cookie header
okta-auth globalprotect vpn.example.com         # print an OpenConnect cookie as JSON
okta-auth status
okta-auth logout
```

Credentials come from `OKTA_USERNAME`, `OKTA_PASSWORD` and `OKTA_TOTP_SECRET`,
`op://` references to 1Password, or the OS keychain. `okta-auth setup` opens a
local page that sets them up. Exit code `77` means Okta rejected the
credentials; a supervisor must not retry it. The Python CLI is `okta`, with
`okta list`, `okta check` and `okta delete` for the session commands. See the
[TypeScript](typescript/README.md#cli) and [Python](python/README.md#cli) docs.

## How it works

1. GET the target URL, following redirects by hand, until Okta's sign-in page or
   the app's auto-submitting `SAMLRequest` form.
2. Read the `stateToken` and walk Okta's IDX API: identify, password, then the
   TOTP authenticator. Optional prompts (a password-expiry warning, an optional
   new authenticator) are skipped. Push, SMS and email are never chosen.
3. Follow Okta's success link to the SAML response form and post it to the
   app's assertion consumer service.
4. Follow the redirects and check that the app answers 2xx on its own host
   without a login form.

Every request must be HTTPS. Credentials go only to the Okta host that served the
sign-in page, and the cookie jar keeps each cookie on the host that set it.
Redirects are capped at 10 and IDX steps at 8.

## Limitations

- Okta Identity Engine only. Classic Engine orgs fail with `unexpected_step`.
- TOTP is the only second factor. Push-only MFA, SMS, email codes and FastPass
  are not supported.
- Steps that need a person, such as an expired password or a required new
  authenticator, fail with a message saying so.
- Cookies are host-only: a cookie set for a parent domain is returned for the
  host that set it.

## Getting a TOTP secret

The secret is only shown while enrolling an authenticator. In Okta, open
**Settings → Security Methods**, set up **Google Authenticator**, choose
**Can't scan?** on the QR code screen, and copy the secret before finishing
enrollment.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests run against a scripted fake Okta
org and never touch a real one. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
