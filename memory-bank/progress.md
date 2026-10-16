# Progress

## Done

- Step 0 scaffold fixes (.gitignore, CI, ADR 0002) — 2026-10-16
- v0.1.0 skeleton: FastAPI health, React shell, tooling, pinned locks — merged to main — 2026-10-16
- v0.2.0 URL core: normalize, 30 features, rules, word lists, ADR 0003, 66 tests passing — merged, tagged v0.2.0, pushed — 2026-10-16
- v0.3.0 URL pipeline: audit, grouped prepare, LR + RF training, thresholds, registry, locked evaluation, ADR 0004; real PhiUSIIL run, 108 tests passing — merged, tagged v0.3.0, pushed — 2026-10-16
- CI fix (PR #4): install the package, GITHUB_TOKEN for gitleaks, fetch-depth 0. CI is green on main (ab25fc1); earlier merges to main had failed — 2026-10-16
- v0.4.0 login and URL analysis: `t_low` by FPR cap (ADR 0005, retrained thresholds), `core/risk.py`, `core/explain.py`, `core/url/scoring.py`, register/login/logout with consent, server-side sessions + CSRF, `POST /api/analyze/url`, React register/login/analyze pages and result card; 178 Python tests (1 xfail) and 11 frontend tests passing; live smoke test OK — on `feature/url-app` — 2026-10-16
- Bug fixed in v0.2.0 code: `ftp://` URLs said "could not be read" instead of "Only http/https links can be assessed" (regression test added)

## In progress

- v0.4.0 on `feature/url-app`, awaiting review and merge

## Not done in v0.4.0 (by design)

- SSE events, history, dashboard, retention purge (v0.7.0); email (v0.5.0, v0.6.0)
