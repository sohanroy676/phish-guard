# Active Context

## Current focus
v1.0.0 is merged to main (8b9265a), pushed, CI green, and tagged v1.0.0. v0.7.0 is tagged too. There was never a v0.8.0. v1 is feature-complete; the only v1 item left is the user's manual Wi-Fi-off pass. The v1.0.0 `make evaluate` was skipped on purpose (never re-run or --force).

## Recent decisions
- Band wording fixed in ADR 0002. Band policy in ADR 0005: `t_low` is the lowest threshold with OOF FPR <= 10% (`target_fpr_low`), capped at `t_high`.
- lr_char alone decides the band (`manifest.primary`). rf_hand is loadable and evaluated but unused in the app.
- Rules only raise a band, except a shortener: the shortener rule discards the model band and gives Can't assess (Suspicious if a high-severity rule also fired).
- Sessions are server-side rows (cookie value HMAC'd with SECRET_KEY, HttpOnly, SameSite=Lax), with a CSRF header on all POSTs except register and login. Argon2id passwords.
- The app refuses to start with empty or placeholder SECRET_KEY / HMAC_PEPPER. With MODEL_VERSION_URL set, a hash or sklearn mismatch also stops startup. With it empty, analyze returns 503.
- Claude cannot read `.env` (denied). **The user's local `.env` must now say `MODEL_VERSION_URL=v2`** (`.env.example` already does). With `v1` the app still works but has the old bias.
- Model reasons are the top n-grams (coefficient x TF-IDF) of the text the model read (`UrlScorer.text`), shown only for High and Suspicious. Rule warnings are a separate list.
- ADR 0004: PhiUSIIL leaks through scheme and path, so models ignore them; path and scheme signals live in rules.
- ADR 0006 (v2): lr_char reads the registered domain (`domain_text`). `prepare_url` keeps one row per (label, domain) and drops domains with both labels, so v2 has a new split; v1's processed CSVs were overwritten and v1 is reference only. Locked result in `reports/results/url_locked_v2.json` (`url_locked.json` is v1's).
- Email decisions agreed with the user: combine the worst-link URL band with the text band at band time (v0.6.0) instead of training the URL score into the email model; write `core/email/*` from scratch (the "reference code" is not in the repo); the newest Nazario year is the temporal test, and ham has no years so temporal FPR is a held-out ham estimate.
- venv made with `uv venv --python 3.12`. pytest-socket allows loopback only. ESLint pinned to 9. 2 react-router npm audit findings are known and unused (revisit at v1.0.0).
- ADR 0007 (email): `lr_text` (word 1-2-gram TF-IDF on masked, stoplisted subject+body) is primary; `rf_struct` uses 11 structural features (n_links, n_link_domains, has_html excluded as corpus-era artefacts). Header rules run only with real headers. Model text drops number and URL tokens. Training drops non-English mail. Locked and temporal result files: `reports/results/email_{locked,temporal}_v1.json` (used once). Temporal ham FPR is a held-out ham estimate (ham has no dates).
- The user gave standing permission to copy downloaded files into the project (e.g. data/raw/).

## Results
- Email v1 (locked, lr_text): PR-AUC 0.9965, FPR 1.1% / recall 97.7% at t_high; temporal PR-AUC 0.9943; rf_struct 0.897 locked, 0.789 temporal; rule baseline 0.25. These are NOT real-world accuracy: ham is 1999-2003 Enron/SpamAssassin prose, phishing is 2015-2025 templates (ADR 0007).
- v2 locked test (35,078 rows, 8,678 phishing), lr_char: PR-AUC 0.711. At t_high (0.809) FPR 1.2%, recall 34.6%. At t_low (0.576) FPR 10.1%, recall 58.3%. rf_hand PR-AUC 0.707. Heuristic baseline 0.267.
- v1 (PR-AUC 0.947) was inflated by the `www.` and duplicate-host artefacts and is not comparable.

- v0.6.0 decisions: band order low < cant_assess < suspicious < high (`risk.higher`); email band = higher of text band and worst link band, then email rules raise it (a high rule lifts to at least Suspicious). Upload: early 413 at 2 MB, and the parser's 1 MB limit also gives 413. Header rules only with real headers (raw/upload); header warnings are listed apart from body rule warnings. Stored: `kind="email"`, HMAC (`email_hmac`), defanged sender domain in `display_host`, band, reasons, all rule messages (generic). Model reasons show only when the text model itself is High/Suspicious. Pasted-fields mode treats HTML as text, so the lookalike anchor check only works in raw/upload mode.

- v0.7.0 decisions: SSE events are in-memory (`app/events.py`, per-user queues, drop-oldest, payload `{type: analysis}` only; the page refetches `GET /api/dashboard/summary`), so the app must run as ONE worker. `GET /api/events` needs login only (EventSource is GET). History: `GET/DELETE /api/history` with an allow-list serializer (no `input_hmac`); Delete all removes only the caller's analyses and leaves sessions. Retention: `purge_old` deletes analyses strictly older than `RETENTION_DAYS` (exactly 30 days is kept; 0 purges everything older than now) and expired sessions, at startup and daily; `retention_days` must be >= 0. TestClient cannot read endless streams, so the SSE isolation test runs a real uvicorn on loopback (`tests/integration/test_events_live.py`). No new index on `analyses` (create_all cannot alter existing DBs).

## v1.0.0 decisions
- CI has the committed manifests but not the git-ignored `.joblib` files, so tests needing a real model must check the `.joblib` and skip (the first v1.0.0 merge failed CI on this, fixed in 8b9265a).
- Golden scores in `tests/golden/scores.json` (regenerate with `python tests/golden/test_scores.py` only with a model version bump). `tests/integration/test_offline.py` blocks DNS and connects. `SPAFiles` in `app/main.py` serves `index.html` for client routes (a refresh on `/history` used to 404; found by the live smoke test). Starlette passes `\` paths on Windows, so normalise before checking `api/`.
- README documents install, train, run, test and known limits. The 2 react-router npm findings are unreachable (hardcoded navigation targets, no SSR) and recorded in README. `web/.prettierrc` has `endOfLine: auto` so `npm run lint` passes on CRLF checkouts (`core.autocrlf=true`).

## Blockers / open questions
- **Known limitation (ADR 0006):** short famous .com domains still score Suspicious/High in v2 (google.com 0.82, amazon.com 0.71, github.com 0.59). Golden test is `xfail(strict)`. Follow-up if it matters before v1.0.0: add an external legitimate-host source as v3 (needs a manual download and licence check). Don't tune on the golden hosts.
- Email corpora are in `data/raw/email/` (git-ignored, archives and SHA-256s in `configs/email.yaml`). The user's local `.env` should set `MODEL_VERSION_EMAIL=v1` once v0.6.0 loads the email model (joblib files are git-ignored; retrain with `make`-equivalents: `python -m phishguard.training.prepare_email email` then `train email`; the locked results already exist, so `evaluate` would need `--force`, which should not be used).
- No modern legitimate email in the data: FPR on newsletters, receipts and notifications is unmeasured and likely much higher than 1%. Follow-up before v1.0.0.
- GNU make is not installed, so the Makefile has not been run end to end.
- Prettier `--check .` warns on 6 root config files because of CRLF on this Windows checkout (pre-existing, `src` is clean).

## Next step
Post-v1 candidates, none started: the user's manual offline pass; v3 URL model with an external legitimate-host source (ADR 0006, needs a manual download and licence check); measure the email model on modern legitimate mail (ADR 0007); the 2 react-router audit findings (needs a breaking upgrade). Branches `feature/email-app`, `feature/history-dashboard`, `feature/v1-hardening` and `fix/golden-skip-without-joblib` are merged and can be deleted (ask the user first). `.claude/settings.json` is committed now.
