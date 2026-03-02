# Contributing

## Setup

```bash
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'
playwright install chromium
```

## Local Quality Gates

```bash
ruff format --check .
ruff check .
pytest
```

## Pull Requests

- Keep PRs focused and small.
- Add/update tests for behavior changes.
- Do not commit secrets, cookies, or local session files.
