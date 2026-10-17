# Active Context

## Current focus
v1.0.0 is merged to main (8b9265a), pushed, CI green, and tagged v1.0.0. v0.7.0 is tagged too. There was never a v0.8.0. v1 is feature-complete and the user's manual pass is done: all roadmap checks and the Wi-Fi-off pass looked right (2026-10-16). The v1.0.0 `make evaluate` was skipped on purpose (never re-run or --force).

## In progress (post-v1 item 1)
- Branch `feature/email-modern-ham-measure` (not merged): `training/measure_ham.py` + `tests/unit/test_measure_ham.py` committed (1f7eaef). It measures the email model on a folder of .eml (subfolder = category) and writes counts only to `reports/results/email_modern_ham_<label>.json`; it never overwrites and never trains.
- MEASURED 2026-10-16 on 123 of the user's own Gmail messages (Takeout mbox split to .eml under `data/raw/email_modern/own/`, git-ignored): final band was Suspicious or High for 100%, High for 82%; text model alone 93.5% flagged (High 80.5%); worst-link URL band High 29 / Suspicious 67 / Low 27; `auth_fail` fired on 9 (unexplained, possibly Takeout headers). Written up as the ADR 0007 addendum; `reports/results/email_modern_ham_own.json`. **Option 2 (wording) chosen and done on `feature/email-card-wording` (stacked on `feature/email-modern-ham-measure`, unmerged): stronger `MODEL_NOTE`, shown above details for High/Suspicious. Band logic/thresholds untouched. Next decision: email v2 or band-policy change.** Original options:: rule tweaks (cannot lower bands), modern-ham email v2 (needs a source and licence; this sample must stay held out), a softer result-card wording/model-note, or document only. Do not tune on this sample without asking.
- 2 docs commits on local main are still unpushed (user said not yet).

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
Post-v1 candidates, none started: v3 URL model with an external legitimate-host source (ADR 0006, needs a manual download and licence check); measure the email model on modern legitimate mail (ADR 0007); the 2 react-router audit findings (needs a breaking upgrade). Merged local branches were deleted at the user's request. `.claude/settings.json` is committed now.

## Session update (auth_fail, option c)
- Branch `fix/auth-fail-investigation` (fc5e363, unmerged, not pushed): `auth_fail` narrowed. The 9 hits on the held-out Gmail sample were genuine Gmail headers (8x `dmarc=fail p=NONE` via SES, 1x one failed DKIM beside a passing one), not Takeout artefacts. A method now fails only with no passing result of the same method; `dmarc=fail` under `p=none` is ignored. Re-measured as `reports/results/email_modern_ham_own_authfix.json`: auth_fail 9 -> 0, bands unchanged (still 100% High/Suspicious). ADR 0007 has the follow-up paragraph.
- Next (user chose "(c) then (b)"): plan email v2 with a modern-ham source (needs data: more own mail with a different date range, deduped against the held-out 123, and/or a licensed public set the user approves). The 123-message sample stays held-out. Link-band discounting for tracking domains (option a) only if link bands still dominate after v2. Needs a new ADR 0008 for any band-policy change.

## Session update (bulk-mail gate, ADR 0008)
- Branch `feature/email-bulk-gate` (committed, unmerged, not pushed). User chose approach D+B+C (no new training data). `core/email/bulk.py` (bulk markers + aligned dmarc pass from the topmost Authentication-Results; `is_link_wrapper`), `risk.email_decision` (gate: bulk and no strong rule -> text High/Suspicious and Suspicious links become Can't assess, High link still counts, Low needs authenticated bulk; fields-only text-High capped at Suspicious), `core/lists/redirectors.txt` (rspamd Apache-2.0 + hand-curated ESP click domains), email card shows bulk note and "not counted" tracker links, own BULK_ADVICE wording for email Can't assess.
- Measured once on the held-out 123 (`email_modern_ham_own_bulkgate.json`, no tuning): flagged 100% -> 82%, High 82% -> 67%, Can't assess 22. Only 31 of 123 detected as bulk; 29 High links remain. Recall cost on phishing NOT measured (temporal set is locked; never run `evaluate`).
- Dropped/deferred: EasyPrivacy (pixel path patterns only), Majestic Million (approved, unused), anchor-text domain scoring. Research notes committed as `docs/email-false-positives.md` (several licence claims there are unverified; see ADR 0008).
- Next: user review/merge; then email v2 with modern ham (self-collected mailbox, needs source approval) and a recall-cost measurement on non-temporal phishing (e.g. phishing_pot, licence unconfirmed).

## Session update (gate recall measurement, paused)
- Branch `feature/email-gate-recall` (merged to main): `training/measure_phish.py` + `tests/unit/test_measure_phish.py` (counts-only; gated vs ungated bands, text-only, share changed/lost flag; never overwrites) and a `skip_wrappers` option on `measure_ham.worst_link_band`. 399 fast tests pass, lint clean.
- phishing_pot licence CHECKED: its LICENSE file is CC BY-NC 4.0. User APPROVED it as a counts-only source (non-commercial, nothing redistributed). The download was too slow (~4 MB/min) and was stopped; the user will download the ZIP manually into `data/raw/email_phishing_pot/` (git-ignored, currently empty). NOT measured yet; the ADR 0008 addendum is NOT written.
- Next: record the ZIP's SHA-256, extract only `.eml` into that folder (untrusted: `python -I`, scripts elsewhere), run `python -m phishguard.training.measure_phish --dir data/raw/email_phishing_pot --label pot` ONCE (no tuning), write the ADR 0008 addendum with gated vs ungated numbers and the CC BY-NC note. Then write the email v2 plan (`docs/email-v2-plan.md`, ADR 0009 proposed stub): new mailbox, 200-400 English senders, mbox, split by sender registered domain, mask sender/brand tokens, 123-sample held out. User must approve the v2 source before any collection or training. Never run `evaluate`/`--force`.

## Session update (phishing_pot measured, v2 proposed) - 2026-10-17
- Branch `feature/email-gate-recall-measure` (3 commits + this memory-bank commit, unmerged, not pushed). The user cloned phishing_pot (commit 2933c03, CC BY-NC 4.0) into `data/raw/email_phishing_pot/` (12,271 .eml, git-ignored); there was no ZIP.
- Bug fixed (54aa377): `HeaderParseError` is not a `ValueError`, so a truncated base64 header (sample-6972) crashed `parse_raw`, also in the app. First measure run crashed and wrote nothing; second run was the single measurement.
- Result `reports/results/email_phish_pot.json` (n=12,247): ungated flagged 98.2% (High 55.9, Susp 42.3, Can't 0.4, Low 1.4); gated flagged 88.7% (High 51.8, Susp 36.9, Can't 10.0, Low 1.2); 1,156 (9.4%) lost their flag. Gate trades ~9 points phishing recall for 18 points fewer false flags on own mail. ADR 0008 addendum written. Do not re-run or tune.
- `docs/email-v2-plan.md` and ADR 0009 (Proposed) written. NOTHING collected or trained. **Waiting on the user to approve the v2 source (mailbox, date range, exclusions).** The 123-sample stays held out. Never run `evaluate` or `--force`.
- Next: user reviews/merges the branch; then source approval for v2.
