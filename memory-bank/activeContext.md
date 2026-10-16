# Active Context

## Current focus
v0.3.0 URL data, training and locked evaluation, on `feature/url-model`. v0.2.0 (URL core) is merged to main, tagged v0.2.0 and pushed.

## Recent decisions
- Band wording fixed in ADR 0002.
- venv made with `uv venv --python 3.12` (the py-launcher 3.12 entry is stale). `make setup` falls back to uv.
- pytest-socket uses `--allow-hosts=127.0.0.1,::1` (not `--disable-socket`) because asyncio needs loopback sockets on Windows.
- ESLint pinned to 9 because eslint-plugin-react does not support 10 yet.
- `npm audit` reports 2 moderate issues in react-router (SSR hydration only, unused in this SPA). Not upgraded, since pins are frozen; revisit at v1.0.0 `make audit-deps`.
- Feature set (30 features) and rules were designed here because the roadmap's reference code is not in the repo; see ADR 0003. Word lists ship via package-data.
- tldextract uses `suffix_list_urls=()` and `cache_dir=None` (bundled list only).
- v0.3.0: processed splits are CSV (no pyarrow, lock unchanged). PhiUSIIL is downloaded manually by the user into `data/raw/`.

## Blockers / open questions
- GNU make is not installed on this Windows machine, so the Makefile has not been run end to end (recipes are run by hand).
- PhiUSIIL not yet in `data/raw/` as of 2026-10-16; real audit/train/evaluate runs wait for it.

## Next step
Implement v0.3.0 per the approved plan (read detailedRoadmap.md v0.3.0).
