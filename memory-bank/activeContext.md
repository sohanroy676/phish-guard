# Active Context

## Current focus
v0.3.0 (URL data, training, locked evaluation) is built on `feature/url-model`, real PhiUSIIL results are committed, and it awaits review and merge. v0.2.0 is merged, tagged and pushed.

## Recent decisions
- Band wording fixed in ADR 0002.
- venv made with `uv venv --python 3.12` (the py-launcher 3.12 entry is stale). `make setup` falls back to uv.
- pytest-socket uses `--allow-hosts=127.0.0.1,::1` (not `--disable-socket`) because asyncio needs loopback sockets on Windows.
- ESLint pinned to 9 because eslint-plugin-react does not support 10 yet.
- `npm audit` reports 2 moderate issues in react-router (SSR hydration only, unused in this SPA). Not upgraded, since pins are frozen; revisit at v1.0.0 `make audit-deps`.
- Feature set (30 features) and rules were designed here because the roadmap's reference code is not in the repo; see ADR 0003. Word lists ship via package-data.
- tldextract uses `suffix_list_urls=()` and `cache_dir=None` (bundled list only).
- v0.3.0 (ADR 0004): splits are CSV, no pyarrow. PhiUSIIL leaks through scheme and path (every legitimate URL is https with an empty path), so the RF drops `is_https` and 12 path/query features (17 host features left) and the LR reads the host only (`host_text`). Path and scheme signals stay in rules.
- `t_low` = highest threshold keeping OOF phishing recall >= 95%, capped at `t_high`.
- The user gave standing permission to copy downloaded files into the project (e.g. data/raw/).

## Results (locked test, 47,012 rows, 20,051 phishing)
- lr_char: PR-AUC 0.947, FPR 0.96% and recall 77% at t_high, recall 95% at t_low but FPR 46%.
- rf_hand: PR-AUC 0.895, FPR 0.96% and recall 64% at t_high, FPR 76% at t_low.
- Heuristic baseline: PR-AUC 0.456 (about the 42.7% prevalence). Rules rarely fire on mostly-homepage data.

## Blockers / open questions
- GNU make is not installed on this Windows machine, so the Makefile has not been run end to end (recipes are run by hand).
- `t_low` gives a large Suspicious band (46% of legitimate hosts for lr_char). Revisit the band policy in v0.4.0 `core/risk.py` (e.g. a lower recall target for t_low).
- Host-only models cannot see path-based phishing; PhiUSIIL cannot measure that fairly. A fresh external test set is on the Later list.

## Next step
Review and merge `feature/url-model`, then start v0.4.0 (login and URL analysis in the app; read detailedRoadmap.md).
