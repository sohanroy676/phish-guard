# Progress

## Done

- Step 0 scaffold fixes (.gitignore, CI, ADR 0002) — 2026-10-16
- v0.1.0 skeleton: FastAPI health, React shell, tooling, pinned locks — merged to main — 2026-10-16
- v0.2.0 URL core: normalize, 30 features, rules, word lists, ADR 0003, 66 tests passing — merged, tagged v0.2.0, pushed — 2026-10-16
- v0.3.0 URL pipeline: audit, grouped prepare, LR + RF training, thresholds, registry, locked evaluation, ADR 0004; real PhiUSIIL run, 108 tests passing — merged, tagged v0.3.0, pushed — 2026-10-16
- CI fix (PR #4): install the package, GITHUB_TOKEN for gitleaks, fetch-depth 0. CI is green on main (ab25fc1); earlier merges to main had failed — 2026-10-16
- v0.4.0 login and URL analysis: `t_low` by FPR cap (ADR 0005, retrained thresholds), `core/risk.py`, `core/explain.py`, `core/url/scoring.py`, register/login/logout with consent, server-side sessions + CSRF, `POST /api/analyze/url`, React register/login/analyze pages and result card; 178 Python tests (1 xfail) and 11 frontend tests passing; live smoke test OK — merged (5089ac5), tagged v0.4.0, pushed, CI green — 2026-10-16
- Host-bias fix: URL model v2 reads the registered domain (ADR 0006), new split and locked test, `url_locked_v2.json`, golden Wikipedia test now passes, famous-.com golden tests xfail; 183 Python tests passing (3 xfail) — merged to main (505cdd5), pushed, CI green — 2026-10-16
- Bug fixed in v0.2.0 code: `ftp://` URLs said "could not be read" instead of "Only http/https links can be assessed" (regression test added)
- v0.5.0 email core and model: `core/email/{parse,mask,features,rules}.py` (stdlib), MinHash grouping, audit/prepare/train/evaluate generalised to url|email (`training/kinds.py`), `configs/email.yaml`, ADR 0007, Makefile email targets; locked and temporal evaluation run once; two leakage rounds found and fixed before evaluation; 294 Python tests passing (3 xfail) — on `feature/email-core`, not merged — 2026-10-16

- v0.6.0 email analysis in the app: `core/email/scoring.py`, `risk.higher/combine_email`, email reason template, `POST /api/analyze/email` (fields or raw) and `/upload`, header panel, per-link results, React `/analyze/email` with three tabs; 317 Python tests (3 xfail) and 15 frontend tests passing; live smoke test OK with real models (v2 URL, v1 email) - on `feature/email-app`, not merged - 2026-10-16

- v0.7.0 history, SSE dashboard, retention purge: event bus, `/api/events`, `/api/history` (list, filters, Delete all), `/api/dashboard/summary`, startup and daily purge, React History, Dashboard (Recharts) and Privacy pages; 344 Python tests (3 xfail) and 21 frontend tests passing; live smoke test OK (own-user SSE event only, second user empty, Delete all, RETENTION_DAYS=0 purge on restart) - on `feature/history-dashboard`, not merged - 2026-10-16

- v1.0.0 hardening (v0.8.0 never existed in the roadmap): architecture doc sync, golden score tests, offline integration test, README, SPA deep-link fix, Prettier CRLF config; `pip-audit` clean, `npm audit` 2 known unreachable findings; 369 Python tests (3 xfail) and 21 frontend tests passing; live smoke test OK (all pages, SSE 0.27 s, user isolation, Delete all) - merged, tagged v1.0.0, pushed, CI green after a golden-test skip fix - 2026-10-16

## In progress

- Post-v1: modern-ham measurement tool built on `feature/email-modern-ham-measure` (7 new tests, 368 fast tests passing, lint clean); waiting for the user's .eml samples before measuring — 2026-10-16

- Nothing in progress. v1.0.0 merged (8b9265a), pushed, CI green, tagged; the user's manual checks and Wi-Fi-off pass are done and passed (2026-10-16)

## Not done in v0.4.0 (by design)

- Nothing outstanding from v0.4.0; its deferred items shipped in v0.5.0-v0.7.0
