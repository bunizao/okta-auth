# AGENTS.md

Guidance for coding agents working in this repository.

## Project

okta-auth (npm: `okta-auth-cli`) signs in to SAML apps behind Okta Identity
Engine over plain HTTP. The core is a library that must run unchanged in
Node 22+, Bun and Cloudflare Workers. A thin Node CLI (`okta-auth`) sits on top.

## Commands

```bash
npm install
npm run check   # tsc over everything, then the core again without @types/node
npm test        # vitest
npm run build   # tsc -> dist/
```

## Layout

```
src/
├── index.ts      # public exports: signIn, totp, OktaSignInError, types
├── sign-in.ts    # the flow: redirects into Okta, IDX loop, SAML post, signed-in check
├── globalprotect.ts # GP prelogin -> Okta -> ACS, returns OpenConnect's one-time cookie
├── idx.ts        # picks the next IDX remediation and builds its body
├── client.ts     # HTTP: host-scoped cookies, manual redirects, timeouts, HTTPS only, DT seeding
├── cookies.ts    # host-only cookie jar and Set-Cookie parser
├── html.ts       # stateToken and SAML form extraction, entity decoding
├── totp.ts       # RFC 6238 over WebCrypto, base32
├── errors.ts     # OktaSignInError codes
└── cli/          # Node only: main.ts (commands), store.ts (~/.okta-auth), credentials.ts (env, Keychain)
tests/
├── fake-sso.ts   # scripted fake Okta org, Moodle-like SAML SP and GlobalProtect portal behind a fake fetch
└── *.test.ts
```

## Rules

- `src/*.ts` (the core) uses only `fetch`, `Headers`, `URL`, `AbortSignal` and
  WebCrypto. No `node:` imports, `Buffer` or `process`; `tsconfig.core.json`
  enforces it. Node-only code goes in `src/cli/`.
- No runtime dependencies.
- Error messages and logs never contain passwords, one-time codes, the TOTP
  secret, state tokens, query strings or cookie values. Use `where(url)` for
  locations. Tests assert this.
- `signIn` never retries. A `credentials_rejected` retry can lock the account.
- Credentials only go to the Okta host that served the sign-in page; cookies
  only to the host that set them.
- New IDX behaviour gets a scripted case in `tests/fake-sso.ts` and a test.
- Never sign in to a real Okta org from tests or scripts.

## Python port

`okta_auth.core` in the Python package (PyPI `okta-auth-cli`, branch
`feat/pure-http-sign-in`) mirrors `src/*.ts` module for module. This package is
the reference: protocol fixes land in both in the same release, with a test of
the same case name in each (Python lowercases the name and joins words with
`_`). The Python AGENTS.md lists the deliberate differences (seconds instead of
milliseconds, `ValueError`, sync `totp`, snake_case).
