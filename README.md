# okta-auth

**Sign in to Okta apps without a browser.**

Give it a URL, your university username, password and TOTP secret. It walks Okta's sign-in over plain HTTP, MFA included, and hands back the cookies the app set. The same fetch-only core runs in Node, Bun, Python and Cloudflare Workers, so a remote MCP server can sign itself in.

Use it as a CLI, a TypeScript or Python library, or the sign-in step of your own Worker.

[![npm version](https://img.shields.io/npm/v/okta-auth-cli?logo=npm)](https://www.npmjs.com/package/okta-auth-cli)
[![PyPI version](https://img.shields.io/pypi/v/okta-auth-cli?logo=pypi&logoColor=white)](https://pypi.org/project/okta-auth-cli/)
[![CI](https://github.com/bunizao/okta-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/bunizao/okta-auth/actions/workflows/ci.yml)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-supported-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> 🦄 Part of [unicorn](https://unicorn.tuuhub.com). The sign-in step the live tools share, so none of them needs a browser.
>
> 📖 **Read the docs: [TypeScript](typescript/README.md) · [Python](python/README.md)**

## Set up

Ask your agent (Claude Code, Codex, or anything with a terminal):

```text
Install okta-auth-cli from npm, run `okta-auth setup`, then sign me in to https://learning.monash.edu/login/index.php.
```

`okta-auth setup` opens a page in your browser. It finds your Okta login in 1Password or saves it to the macOS Keychain, then tries a sign-in. Your password never passes through the agent.

Or by hand:

```bash
npm install -g okta-auth-cli
okta-auth setup
okta-auth login https://learning.monash.edu/login/index.php
```

With Python, `uv tool install okta-auth-cli` gives you the `okta` CLI and an `okta-auth` MCP server instead.

## Use it from

| Where | How |
| --- | --- |
| Your terminal and scripts | `okta-auth login <url>`, then `okta-auth cookies <url>` prints a `Cookie` header. [CLI](typescript/README.md) |
| TypeScript: Node 22+, Bun, Workers | `npm install okta-auth-cli`, then `signIn({ url, username, password, totpSecret })`. [Library](typescript/README.md) |
| Python 3.11+ | `uv add okta-auth-cli`, then `await sign_in(url=..., ...)`. [Library](python/README.md) |
| OpenConnect | `okta-auth globalprotect <server>` prints the one-time VPN cookie as JSON. [GlobalProtect](typescript/README.md) |

## What it signs in to

| Ask your agent | Command |
| --- | --- |
| “Sign me in to Moodle.” | `okta-auth login https://learning.monash.edu/login/index.php` |
| “Give curl my Moodle session.” | `curl -H "Cookie: $(okta-auth cookies https://learning.monash.edu)" …` |
| “Get me a VPN cookie for OpenConnect.” | `okta-auth globalprotect vpn.gp.monash.edu` |
| “Which sessions do I have?” | `okta-auth status` |
| “Sign me out of everything.” | `okta-auth logout` |

It follows whatever Okta Identity Engine and the app ask for:

- **Apps:** SAML apps that redirect or post their request to Okta, Okta app links (the tiles on your Okta dashboard), OIDC apps that Okta redirects back to, and GlobalProtect gateways and portals.
- **MFA:** a TOTP code from Google Authenticator or Okta Verify. It picks the code over push, and can ask 1Password for the code so the secret stays there.
- **Policies:** it skips optional prompts such as a password-expiry warning or an optional new authenticator. When Okta needs a browser instead (an expired password, a required new authenticator, an external identity provider), it says so.
- **Devices:** it keeps Okta's device token, so Okta doesn't see a new device each time. The library can also reuse Okta's session to sign in to a second app without MFA.

Push-only MFA, SMS, email codes, FastPass and Okta Classic Engine orgs are not supported.

## Safe by design

- It never retries a sign-in by itself. A wrong password stops after one attempt, so it can't lock your account.
- Your password only goes to the Okta host that served the sign-in page. Cookies only go to the host that set them.
- Errors and logs name hosts and paths only: no passwords, codes, tokens, query strings or cookie values. Tests check this.
- No runtime dependencies. The core uses only `fetch` and WebCrypto.

## Learn more

- [TypeScript library and CLI](typescript/README.md): options, results, error codes, GlobalProtect, Workers
- [Python library, CLI and MCP server](python/README.md)
- [Contributing](CONTRIBUTING.md): two packages, one protocol, the same test cases in each
- [Security](SECURITY.md): reporting a vulnerability

## 🦄 Part of unicorn

Live tools answer what is there now; unicorn answers what changed. okta-auth signs them in.

| Project | Layer | What it does |
| --- | --- | --- |
| [🦄 unicorn](https://github.com/TuuHub/unicorn) | Memory | Remembers your campus sources and tells your agent what changed. Remote MCP. |
| [moodle-cli](https://github.com/bunizao/moodle-cli) | Live | Moodle. CLI, local and remote MCP. |
| [edstem-cli](https://github.com/bunizao/edstem-cli) | Live | Ed Discussion. CLI, local and remote MCP. |
| [ontrack](https://github.com/bunizao/ontrack-cli) | Live | OnTrack and Doubtfire. CLI only. |
| **[okta-auth](https://github.com/bunizao/okta-auth)** (you are here) | **Sign-in** | **Okta sign-in without a browser. CLI and library for Node, Bun, Python and Workers.** |

📖 [All docs](https://unicorn.tuuhub.com/docs) · [CLIs overview](https://unicorn.tuuhub.com/cli)

## License

MIT. See [LICENSE](LICENSE).
