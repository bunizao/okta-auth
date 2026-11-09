# AGENTS.md

Guidance for coding agents working in this repository.

## Project

okta-auth signs in to SAML apps and GlobalProtect portals behind Okta Identity
Engine over plain HTTP. It ships as two packages, both named `okta-auth-cli`:

```
typescript/   # npm. The reference: the core runs in Node 22+, Bun and Cloudflare Workers
python/       # PyPI. okta_auth.core mirrors typescript/src module for module
```

Each folder has its own AGENTS.md with commands, layout and package rules. Read
the one for the package you touch.

## Rules for both packages

- Error messages and logs never contain passwords, one-time codes, the TOTP
  secret, state tokens, query strings or cookie values. Use `where(url)` for
  locations. Tests assert this.
- Sign-in never retries. A `credentials_rejected` retry can lock the account;
  both CLIs exit 77 instead.
- Credentials only go to the Okta host that served the sign-in page; cookies
  only to the host that set them.
- New IDX behaviour gets a scripted case in each fake SSO
  (`typescript/tests/fake-sso.ts`, `python/tests/fake_sso.py`) and a test of
  the same case name in each.
- A protocol fix lands in both packages in the same PR.
- Never sign in to a real Okta org from tests or scripts.
- `setup.html` is one page served by both CLIs; the two copies must stay
  identical (a Python test checks).

## Releases

Each package is versioned and released on its own. Bump the version in
`python/pyproject.toml` or `typescript/package.json`, then push a tag:
`py-vX.Y.Z` publishes to PyPI, `ts-vX.Y.Z` to npm. A pre-release version
(`0.3.0rc1`, `0.3.0-rc.0`) stays off the default install on both registries.

## Code style

English comments, Conventional Commits. Scope commits by package when only one
changes, e.g. `fix(py): ...`, `feat(ts): ...`.
