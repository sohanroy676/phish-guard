# Active Context

## Current focus
v0.2.0 URL core is built on `feature/url-core` and passes unit tests, full suite and lint. Awaiting merge to main.

## Recent decisions
- Band wording fixed in ADR 0002.
- venv made with `uv venv --python 3.12` (the py-launcher 3.12 entry is stale). `make setup` falls back to uv.
- pytest-socket uses `--allow-hosts=127.0.0.1,::1` (not `--disable-socket`) because asyncio needs loopback sockets on Windows.
- ESLint pinned to 9 because eslint-plugin-react does not support 10 yet.
- `npm audit` reports 2 moderate issues in react-router (SSR hydration only, unused in this SPA). Not upgraded, since pins are frozen; revisit at v1.0.0 `make audit-deps`.

- Feature set (30 features) and rules were designed here because the roadmap's reference code is not in the repo; see ADR 0003. Word lists ship via package-data.
- tldextract uses `suffix_list_urls=()` and `cache_dir=None` (bundled list only).

## Blockers / open questions
- GNU make is not installed on this Windows machine, so the Makefile has not been run end to end (recipes were run by hand).

## Next step
Merge `feature/url-core`, then start v0.3.0 (URL model training; read detailedRoadmap.md).
