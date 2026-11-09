# okta-auth

Sign in to a SAML app behind Okta Identity Engine with plain HTTP. No browser,
no Playwright, no runtime dependencies. The same code runs in Node 22+, Bun and
Cloudflare Workers.

You give it a URL on the target site, a username, a password and a TOTP secret.
It returns the cookies the target site set once you're signed in, plus Okta's
device token for next time.

> **Alpha.** The API may still change before 1.0.

## Install

```bash
npm install okta-auth-cli
```

The package holds both the library and the `okta-auth` command.

## Library

```ts
import { OktaSignInError, signIn } from "okta-auth-cli";

const { cookies, deviceToken } = await signIn({
  url: "https://learning.monash.edu/login/index.php",
  username: env.OKTA_USERNAME,
  password: env.OKTA_PASSWORD,
  totpSecret: env.OKTA_TOTP_SECRET,
  deviceToken: await storage.get("okta-device-token"), // optional, see below
});

const session = cookies.find((cookie) => cookie.name === "MoodleSession");
if (deviceToken) await storage.put("okta-device-token", deviceToken);
```

### API

```ts
function signIn(options: SignInOptions): Promise<SignInResult>;

interface SignInOptions {
  url: string;              // https page that sends signed-out visitors to Okta
  username: string;
  password: string;
  totpSecret?: string;      // base32, as shown when enrolling Google Authenticator
  deviceToken?: string;     // from a previous SignInResult
  fetch?: (input: string, init: RequestInit) => Promise<Response>;
  now?: () => number;       // ms since epoch; drives TOTP and cookie expiry
}

interface SignInResult {
  cookies: Cookie[];               // the target host's cookies, and only those
  deviceToken: string | undefined; // Okta's DT cookie
}

interface Cookie {
  name: string;
  value: string;
  domain: string;      // always the exact host that set it
  path: string;
  expires?: number;    // seconds since epoch; absent for session cookies
  secure: boolean;
  httpOnly: boolean;
}

function totp(secret: string, now?: number): Promise<string>; // RFC 6238, 6 digits

class OktaSignInError extends Error {
  code: OktaSignInErrorCode;
}
```

Invalid input (a non-https URL, a secret that isn't base32) throws a
`TypeError` before any request goes out.

### Errors

Everything that goes wrong after that throws `OktaSignInError`. Branch on `code`:

| `code` | Meaning | Retry? |
|---|---|---|
| `credentials_rejected` | Okta refused the username or password. | **Never automatically.** Each attempt counts towards Okta's lockout. |
| `passcode_rejected` | Okta refused the one-time code: wrong secret, clock skew, or a code already used. | At most once, after the next 30-second window. |
| `mfa_unsupported` | Okta wants push, SMS, email or another authenticator this package can't answer. | No. |
| `unexpected_step` | Okta asked for something unknown, or the site isn't Okta Identity Engine. The message names the IDX forms. | No. |
| `handoff_failed` | Okta signed in, but the target site still isn't signed in after the SAML post. | No. |
| `network` | A request timed out (15 s) or failed. | With backoff. If it happened while posting the password, Okta may still have counted it. |
| `http_N` | A page or IDX call answered HTTP N (`http_429`, `http_503`...). | 5xx and 429 with backoff. |

`signIn` itself never retries. Messages name hosts, paths, IDX form names and
Okta's i18n keys (`incorrectPassword`), never passwords, codes, the TOTP secret,
state tokens or cookie values.

### Device token

Okta sets a long-lived `DT` cookie to recognise a device. A sign-in without it
looks like a new device, and orgs with sign-on notifications email the user
every time. Store `deviceToken` and pass it back. It goes only to the Okta host.

### GlobalProtect

`signInGlobalProtect` signs in to a Palo Alto GlobalProtect portal or gateway
that uses Okta SAML and returns the one-time cookie OpenConnect connects with.
It replaces `gp-saml-gui` or a headless browser.

```ts
import { signInGlobalProtect } from "okta-auth-cli";

const gp = await signInGlobalProtect({
  server: "vpn.gp.monash.edu",
  username, password, totpSecret, deviceToken,
});
// gp: { interface: "gateway", user, cookieName: "prelogin-cookie", cookie, deviceToken }
```

```ts
interface GlobalProtectOptions {
  server: string;                    // host only, e.g. vpn.gp.monash.edu
  interface?: "gateway" | "portal";  // default: gateway, then portal
  // username, password, totpSecret, deviceToken, fetch, now: as for signIn
}
```

It POSTs to the prelogin endpoint (`/ssl-vpn/prelogin.esp` for the gateway,
`/global-protect/prelogin.esp` for the portal), takes the SAML request in
either binding to Okta, signs in, and reads `saml-username` and
`prelogin-cookie` or `portal-userauthcookie` from the ACS response headers, or
from the HTML comment older versions use. Nothing goes to Okta until a prelogin
offers SAML. If the ACS answers without a cookie, it throws `handoff_failed`.

The cookie works once. Pass it to OpenConnect on stdin:

```bash
openconnect --protocol=gp --user="$user" --usergroup="gateway:prelogin-cookie" \
  --passwd-on-stdin vpn.gp.monash.edu <<<"$cookie"
```

### Cloudflare Workers

Nothing to configure: the package uses `fetch`, `Headers.getSetCookie()`,
`AbortSignal.timeout` and WebCrypto, all built in. Keep the credentials in
secrets:

```bash
wrangler secret put OKTA_USERNAME
wrangler secret put OKTA_PASSWORD
wrangler secret put OKTA_TOTP_SECRET
```

## CLI

```bash
okta-auth login https://learning.monash.edu/login/index.php
okta-auth status
okta-auth cookies https://learning.monash.edu/   # prints a Cookie header
okta-auth logout                                 # or: okta-auth logout <url>
```

`okta-auth globalprotect <server> [--interface gateway|portal]` prints
`{ server, interface, user, cookieName, cookie }` as JSON and saves only the
device token. The cookie is printed because OpenConnect needs it; don't log it.

Add `--json` to any command for machine-readable output. `cookies --json`
prints the full cookie list.

`login` saves the target's cookies to `~/.okta-auth/sessions/<host>.json`
(mode 0600) and the device token to `~/.okta-auth/device-tokens.json`.
`logout` deletes sessions and keeps the device token, so the next `login`
doesn't count as a new device. Set `OKTA_AUTH_HOME` to use another directory.

### Credentials

The CLI reads environment variables first:

```bash
export OKTA_USERNAME="you@example.edu"
export OKTA_PASSWORD="..."
export OKTA_TOTP_SECRET="JBSWY3DPEHPK3PXP"
```

That works with 1Password too: `op run --env-file=okta.env -- okta-auth login <url>`.

On macOS, anything not in the environment comes from the Keychain, service
`okta-auth`. With `-w` last, `security` prompts for the value instead of taking
it on the command line:

```bash
security add-generic-password -U -s okta-auth -a username -w
security add-generic-password -U -s okta-auth -a password -w
security add-generic-password -U -s okta-auth -a totp_secret -w
```

These are the entries the Python version's `okta config` wrote, so an existing
setup keeps working.

For scripts, `--credentials-stdin` takes the credentials only from stdin, as
`{"username": ..., "password": ..., "totp_secret": ...}`, so they stay out of
argv and the environment:

```bash
security find-generic-password -s my-service -w | okta-auth globalprotect vpn.gp.monash.edu --credentials-stdin
```

### Exit codes

`0` on success, `77` when Okta rejects the username or password, `1` for
everything else. A supervisor that retries on failure must stop on `77`: each
attempt counts towards Okta's lockout.

## TOTP secret

The TOTP secret is the base32 key behind an authenticator app. You can only see
it while enrolling:

1. In Okta, open **Settings → Security Methods**.
2. Set up **Google Authenticator**.
3. On the QR code screen, choose **Can't scan?** and copy the secret.
4. Finish enrolling with a code from your app, so Okta knows the secret works.

If you've lost the secret, remove the authenticator and enroll again.

## How it works

1. GET the target URL, following redirects by hand. The service provider
   redirects to Okta with a `SAMLRequest`.
2. Read `stateToken` from Okta's sign-in page.
3. Walk Okta's IDX API (`/idp/idx/introspect`, then each remediation):
   `identify` → `challenge-authenticator` (password) →
   `select-authenticator-authenticate` → `challenge-authenticator` (TOTP).
   When Okta offers a choice it picks the password, then Google Authenticator,
   then Okta Verify's code. It never picks push, SMS or email.
4. Follow Okta's success link to the auto-submitting SAML form.
5. POST `SAMLResponse` and `RelayState` to the service provider's ACS, follow
   the redirects, and check that the target URL returns a 2xx response on its
   own host without a login form. Same-origin 307/308 redirects preserve the
   POST; forwarding that POST to another origin is refused.

If Okta already has a session and answers step 1 with the SAML form, steps 2–4
are skipped. Credentials only ever go to the Okta host that served the sign-in
page, the cookie jar keeps every cookie on the host that set it, and every
request must be HTTPS. Redirects are capped at 10 and IDX steps at 8.

## Limits

- **Okta Identity Engine only.** Okta Classic (`/api/v1/authn`) fails with
  `unexpected_step`.
- **SAML service providers** that start sign-in with an HTTP-Redirect
  `SAMLRequest`. That covers Moodle's `auth_saml2` and most SimpleSAMLphp SPs.
- **GlobalProtect** portals whose TLS needs legacy renegotiation or a private
  CA fail with `network` under Node's default TLS settings.
- **TOTP second factors only:** Google Authenticator, or Okta Verify when it
  offers "Enter a code".
- **Host-only cookies.** A cookie the SP sets for a parent domain is still
  returned only for the host that set it.

## Migrating from 0.2 (Python)

- The package is now on npm. The command is `okta-auth`, not `okta`.
- The Playwright engine is gone, and so are `--headed`, `--timeout-ms` and the
  browser settings.
- The MCP server is gone. Agents can run `okta-auth cookies <url>`; programs
  should call `signIn()`. Piping session cookies into a model's context was a
  leak waiting to happen.
- `okta config` is gone. Use environment variables or the `security` commands
  above. The Keychain entries it wrote still work.
- Saved sessions in `~/.okta-auth/sessions` still read. `okta-auth cookies`
  returns only the target host's cookies from them.

## Security

- Session files and device tokens are credentials. Don't commit or paste them.
- Never retry `credentials_rejected` in a loop.
- Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Development

```bash
npm install
npm run check   # typecheck; the core is also checked without Node's types
npm test        # vitest against a scripted fake Okta org and SAML SP
npm run build
```
