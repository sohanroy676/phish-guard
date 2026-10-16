# Detailed Roadmap

Each version lists what it adds, what to test, the result to expect, and red flags that mean something needs fixing. Don't start a version until the previous one passes.

---

## v0.1.0 Project skeleton
**Done in this version:** repo layout, `pyproject.toml`, pinned `requirements.lock`, Makefile, `.env.example`, `.gitignore`, ruff, pytest, FastAPI app with `GET /api/health`, React + Vite shell with navigation, ESLint + Prettier + Vitest.

**Test:**
1. `make setup`
2. `make lint` and `make test`, then `cd web && npm test`
3. `make app`, then open http://localhost:8000/api/health
4. `cd web && npm run dev`, then open http://localhost:5173

**Expected:**
- Setup finishes with no errors, and `.env` exists.
- Lint reports 0 errors and all tests pass (even if there are only one or two).
- Health returns JSON like `{"status": "ok", "db": "ok", "models": {}}`.
- The browser shows the PhishGuard shell with links to Analyze URL, Analyze Email, History and Dashboard.

**Red flags:** `.env` shows up in `git status`. The Vite page can't reach `/api/health` (proxy not set up).

---

## v0.2.0 URL core
**Done in this version:** `core/url/normalize.py`, `features.py` (from the reference code), `rules.py`, and the word lists in `core/lists/`.

**Test:**
1. `pytest tests/unit -q`
2. `python -c "from phishguard.core.url.normalize import normalize_url; print(normalize_url('hxxps://Secure-PayPa1[.]com/Login'))"`
3. Try `normalize_url('ftp://example.com')`

**Expected:**
- All unit tests pass.
- Step 2 prints a normalised result with scheme `https`, host `secure-paypa1.com` (refanged, lowercase) and the path kept.
- Step 3 raises `UnsupportedURL`.
- `url_features()` always returns the same set of feature names in the same order, whatever the input.
- The shortener rule fires for `https://bit.ly/abc123`, and the brand rule fires for `http://paypal.com.verify-account.xyz/`.

**Red flags:** any feature that needs the internet. Feature count or order changes between inputs.

---

## v0.3.0 URL data, training and locked evaluation
**Done in this version:** `make audit`, `make prepare`, `make train-url` and `make evaluate` for URLs. LR on char n-grams and RF on hand features. Thresholds for FPR ≤ 1% chosen on out-of-fold dev predictions. Model and manifest written.

**Test:**
1. Put PhiUSIIL in `data/raw/`, then run `make audit` and open `reports/audit_url.md`
2. `make prepare`, then `pytest tests/unit -q -k split`
3. `make train-url`, then open `models/url/<version>/manifest.json`
4. `make evaluate`, then open `reports/results/url_locked.json`

**Expected:**
- The audit shows class counts, duplicate counts and scheme (http/https) rates per class. Phishing and legitimate counts match the dataset's published totals (about 100k phishing and 135k legitimate). If they're flipped, the label mapping is wrong (`1` = legitimate).
- The split test confirms no registered domain appears in both train and test.
- The manifest contains `t_high`, `t_low`, the dev FPR at the threshold (≤ 0.01), `sklearn_version` and the model file's SHA-256.
- The results JSON has PR-AUC, recall at the chosen threshold and FPR for each model, plus the heuristic baseline. Both models beat the baseline.

**Red flags:** phishing and legitimate counts swapped. Scheme rates very different between classes while `is_https` is still a model feature (the audit says to move it to rules). Locked-test FPR far above 1%.

---

## v0.4.0 Login and URL analysis in the app
**Done in this version:** register (consent checkbox), login, logout, session cookie + CSRF, `POST /api/analyze/url`, model registry with hash and version check, result card with band, headline, advice, two lists and the advisory footer.

**Test (in the browser):**
1. Register with consent unchecked, then register again with it checked
2. Analyze `https://bit.ly/3abcXYZ`
3. Analyze `http://paypal.com.secure-login-verify.xyz/account/update`
4. Analyze `https://en.wikipedia.org/wiki/Phishing`
5. Analyze `ftp://example.com/file`
6. `sqlite3 phishguard.db "select display_host, input_hmac, band from analyses;"`
7. Change one byte of `model.joblib`, then restart `make app`

**Expected:**
1. Without consent, registration is rejected with a clear message. With consent, you're logged in.
2. **Can't assess this input**, with the reason that the destination of a shortened link is hidden.
3. **Likely phishing** or **Suspicious: be careful**, with a model reason about the brand appearing outside the real domain and a matching rule warning.
4. **No strong phishing signs found**, with the "isn't a guarantee of safety" sub-text. The word "Safe" never appears.
5. A friendly 422 message: "Only http/https links can be assessed".
6. Only defanged hosts (`hxxp`, `[.]`) and hashes. No full URL anywhere.
7. The app refuses to start with a hash-mismatch error.

**Red flags:** score shown as a percentage. Model reasons and rule warnings mixed in one list. The full URL stored in the DB.

---

## v0.5.0 Email core and email model
**Done in this version:** `core/email/parse.py` (from the reference code), `mask.py`, `features.py`, `rules.py`; `make audit`, `make prepare`, `make train-email` and `make evaluate` for emails, with the newest Nazario year held out.

**Test:**
1. `pytest tests/unit -q`
2. Parse a sample `.eml` with an HTML link whose text says `www.paypal.com` but points elsewhere
3. Run masking on "Pay $500 to john@x.com via http://a.b/c"
4. Open `reports/audit_email.md`, then `reports/results/email_locked.json` and `email_temporal.json`

**Expected:**
- Tests pass, and the parser returns the (href, anchor text) pair. The anchor/href mismatch rule fires.
- The masked text replaces the amount, address and URL with placeholder tokens.
- The audit lists per-source counts and flags features that separate Enron from SpamAssassin, which move to rules.
- Temporal results are a bit lower than locked results. That's normal and shows real generalisation.

**Red flags:** near-perfect scores on both tests with top features like corpus names, dates or signatures (artefact leakage; add them to `artefact_stoplist.txt`). Header rules firing on pasted fields.

---

## v0.6.0 Email analysis in the app
**Done in this version:** `/analyze/email` with three tabs (Fields, Paste original, Upload .eml), per-link URL results, a header-check panel, and email results stored as HMAC + sender domain.

**Test:**
1. Fields tab: subject "Your account is suspended", body with "verify your account" and a lookalike link
2. Paste original: an email with `Authentication-Results: ... spf=fail dmarc=fail` at the top
3. Upload a normal newsletter `.eml`
4. Upload a 2 MB file, then a `.txt` file that isn't an email

**Expected:**
1. **Likely phishing** or **Suspicious**, with a link-by-link list where the lookalike link is flagged. The header panel says "Header checks unavailable: paste the original email to enable them".
2. The SPF/DMARC failure appears under rule warnings, and the band is at least Suspicious.
3. Usually **No strong phishing signs found**.
4. The 2 MB file gets a 413 "too large" message. The `.txt` file gets a 422 "not a valid email file" message.

**Red flags:** HTML from the email rendered in the page (it must show as plain text). Email body text found in the DB.

---

## v0.7.0 History, live dashboard, retention
**Done in this version:** `/history` (filter by band and type, Delete all), `/dashboard` (cards, band distribution, daily trend, recent high-risk) updated over SSE, `/privacy` page, retention purge on startup and daily.

**Test:**
1. Open the dashboard in one window and analyze a URL in another
2. Check history after a few analyses
3. Register a second user and check their history
4. Click Delete all
5. Set `RETENTION_DAYS=0` in `.env` and restart

**Expected:**
1. The dashboard counts and recent list update within a second or two, without a refresh.
2. History shows the time, type, defanged host as **plain text, not a link**, the band and the model version.
3. The second user sees an empty history and an empty dashboard.
4. History and dashboard counts drop to zero.
5. Old rows are purged on startup.

**Red flags:** the dashboard only updates after a refresh. One user can see another user's rows. Clickable hosts in history.

---

## v1.0.0 Hardening and final evaluation
**Done in this version:** golden-file tests, an offline integration test, a final `make evaluate` run, `make audit-deps` clean, README with install/train/run/test steps, demo build served by FastAPI.

**Test:**
1. `pytest -q` (including slow tests), `make lint`, `cd web && npm test`
2. `make audit-deps`
3. `pytest tests/integration -q -k offline`
4. `cd web && npm run build`, then `make app`, turn off Wi-Fi, and use every page at http://localhost:8000
5. Follow the README from a fresh clone

**Expected:**
- Everything passes with 0 lint errors.
- No known vulnerabilities, or each one is noted with a reason.
- The offline test passes with sockets blocked.
- With the network off, every feature works: URL, all three email inputs, history, dashboard.
- The golden tests confirm saved inputs still give the same bands and scores (update the golden files whenever the model version changes).
- A fresh clone reaches a working app using only the README.

**Red flags:** anything that fails only when offline. Golden scores changed without a model version bump.