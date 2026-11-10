# AGENTS.md

Guidance for coding agents working on the Python package. Read `../AGENTS.md`
first for the rules both packages share.

## Project

okta-auth (PyPI: `okta-auth-cli`) signs in to SAML apps and GlobalProtect
portals behind Okta Identity Engine over plain HTTP. `okta_auth.core` is the
protocol; the `okta` CLI, the `okta-auth` MCP server and `adapter.py` sit on top.

## Reference implementation

The TypeScript package (`okta-auth-cli` on npm, `../typescript/src/*.ts`) is the
reference. `okta_auth.core` mirrors it
module for module. Protocol fixes land in both in the same release, with a
test of the same case name in each.

| `../typescript/`        | `python/`                           |
|-------------------------|-------------------------------------|
| `src/sign-in.ts`        | `src/okta_auth/core/sign_in.py`     |
| `src/globalprotect.ts`  | `src/okta_auth/core/globalprotect.py` |
| `src/idx.ts`            | `src/okta_auth/core/idx.py`         |
| `src/client.ts`         | `src/okta_auth/core/client.py`      |
| `src/cookies.ts`        | `src/okta_auth/core/cookies.py`     |
| `src/html.ts`           | `src/okta_auth/core/html.py`        |
| `src/totp.ts`           | `src/okta_auth/core/totp.py`        |
| `src/errors.ts`         | `src/okta_auth/core/errors.py`      |
| `tests/fake-sso.ts`     | `tests/fake_sso.py`                 |
| `tests/<name>.test.ts`  | `tests/test_<name>.py`              |

Test names are the TypeScript case names, lowercased, with every run of other
characters replaced by `_`: "skips IDX when Okta already has a session" becomes
`test_skips_idx_when_okta_already_has_a_session`.

Deliberate differences:

- `now` returns seconds (TS: milliseconds).
- Bad input raises `ValueError` (TS: `TypeError`).
- `totp()` is synchronous (TS: async, because WebCrypto is).
- Names are snake_case: `device_token`, `totp_secret`, `cookie_name`, `http_only`.
- Tests inject an `httpx` transport (`transport=`) instead of `fetch`.

## Commands

```bash
cd python
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'

ruff format --check .
ruff check .
mypy
pytest
```

## Layout

```
src/okta_auth/
├── core/           # the protocol; mirrors the TS core (table above)
├── auth/
│   ├── login.py          # perform_login / verify_session: core + session store
│   └── session_store.py  # ~/.okta-auth/sessions/<host>.json (0600), device-tokens.json
├── cli.py          # okta: login, check, list, delete, cookies, config, globalprotect
├── server.py       # okta-auth: FastMCP stdio server
├── adapter.py      # ensure_login / get_cookies for other Python packages
└── log.py          # stderr only
tests/
├── fake_sso.py     # scripted fake Okta org, SAML SP and GlobalProtect portal (httpx.MockTransport)
└── test_*.py
```

## Rules

- `core` uses httpx with `follow_redirects=False` and its own host-only cookie
  jar; httpx's jar stays disabled. HTTPS only, with timeouts. Stdlib for TOTP.
- Error messages and logs never contain passwords, one-time codes, the TOTP
  secret, state tokens, query strings or cookie values. Use `where(url)` for
  locations, and `raise ... from None` when wrapping httpx errors (their
  messages carry full URLs). Tests assert this.
- `sign_in` never retries. A `credentials_rejected` retry can lock the account;
  the CLI exits 77 instead.
- Credentials only go to the Okta host that served the sign-in page; cookies
  only to the host that set them.
- New IDX behaviour gets a scripted case in `tests/fake_sso.py` and a test,
  ported from (or to) `../typescript` under the same name.
- Never sign in to a real Okta org from tests or scripts.
- Logs go to stderr. stdout is the MCP JSON-RPC channel.

## Code style

Ruff (line length 100, rules E, F, I, B), mypy over `src`, English comments,
Conventional Commits.
