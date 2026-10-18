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

- Result-card wording for the modern-ham finding done on `feature/email-card-wording` (368 Python, 25 frontend tests, lint clean); not merged — 2026-10-16

- Post-v1: modern-ham measurement tool built on `feature/email-modern-ham-measure` (7 new tests, 368 fast tests passing, lint clean); measured on 123 own messages: 100% flagged Suspicious/High, ADR 0007 addendum written, awaiting the user's choice of fix — 2026-10-16

- Nothing in progress. v1.0.0 merged (8b9265a), pushed, CI green, tagged; the user's manual checks and Wi-Fi-off pass are done and passed (2026-10-16)

## Not done in v0.4.0 (by design)

- Nothing outstanding from v0.4.0; its deferred items shipped in v0.5.0-v0.7.0

- auth_fail narrowed after investigating the 9 Gmail hits (none were real failures); 373 fast tests passing, lint clean; on `fix/auth-fail-investigation`, not merged — 2026-10-16

- Email bulk-mail gate (ADR 0008): bulk detection, link-wrapper discount, band gate, card wording; 395 Python (3 xfail) and 28 frontend tests passing, lint clean; on `feature/email-bulk-gate`, not merged - 2026-10-16

- Gate recall tool `measure_phish.py` built and merged; measurement and ADR 0008 addendum waiting on the user's manual phishing_pot download; email v2 plan not written - 2026-10-16

- phishing_pot gate recall measured (gate: phishing flagged 98.2% -> 88.7%), ADR 0008 addendum, parse_raw malformed-header fix, email v2 plan + ADR 0009 proposed; 400 fast tests passing; on `feature/email-gate-recall-measure`, not merged - 2026-10-17

- Email v2 (ADR 0009): modern-ham prepare pipeline, sender/recipient masking, lr_text v2 trained and measured once on the 123 held-out and phishing_pot; 438 fast tests passing; on `feature/email-v2-modern-ham`, not merged; v2 not the default - 2026-10-17

- Email link-band policy (ADR 0010): sender-owned popular-domain link exemption, Majestic-derived list, builder script, card wording; phishing cost measured (1 of 12,247 lost), benefit unmeasured; 445 Python and 29 frontend tests passing; on `feature/email-link-policy`, not merged - 2026-10-18
