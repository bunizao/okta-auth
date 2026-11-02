# Contributing

## Setup

```bash
npm install
```

## Local Quality Gates

```bash
npm run check
npm test
npm run build
```

## Pull Requests

- Keep PRs focused and small.
- Add/update tests for behavior changes. New Okta behavior gets a scripted case
  in `tests/fake-sso.ts`.
- Do not commit secrets, cookies, or local session files.
- Never test against a real Okta org with real credentials in CI or shared logs.
