# Contributing

The repository holds two packages: `python/` (PyPI) and `typescript/` (npm,
the reference implementation). See AGENTS.md for the rules both follow.

## Python

```bash
cd python
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'

ruff format --check .
ruff check .
mypy src
pytest
```

## TypeScript

```bash
cd typescript
npm install

npm run check
npm test
npm run build
```

## Pull Requests

- Keep PRs focused and small.
- Add/update tests for behavior changes. New Okta behavior gets a scripted case
  in both fake SSOs (`typescript/tests/fake-sso.ts`, `python/tests/fake_sso.py`).
- A protocol fix changes both packages in the same PR, with a test of the same
  case name in each.
- Do not commit secrets, cookies, or local session files.
- Never test against a real Okta org with real credentials in CI or shared logs.
