# Active Context

## Current focus
v0.1.0 skeleton is built on `feature/skeleton` and passes its gates. Awaiting merge to main.

## Recent decisions
- Band wording fixed in ADR 0002.
- venv made with `uv venv --python 3.12` (the py-launcher 3.12 entry is stale). `make setup` falls back to uv.
- pytest-socket uses `--allow-hosts=127.0.0.1,::1` (not `--disable-socket`) because asyncio needs loopback sockets on Windows.
- ESLint pinned to 9 because eslint-plugin-react does not support 10 yet.
- `npm audit` reports 2 moderate issues in react-router (SSR hydration only, unused in this SPA). Not upgraded, since pins are frozen; revisit at v1.0.0 `make audit-deps`.

## Blockers / open questions
- GNU make is not installed on this Windows machine, so the Makefile has not been run end to end (recipes were run by hand).

## Next step
Merge `feature/skeleton`, then start v0.2.0 URL core (normalize, features, rules, word lists).
