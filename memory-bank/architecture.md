# Architecture

## Folder structure
```
phishguard/
├── CLAUDE.md  AGENTS.md  README.md  pyproject.toml  requirements.lock  Makefile
├── .env.example              # SECRET_KEY, HMAC_PEPPER, DATABASE_URL, RETENTION_DAYS, MODEL_VERSION_URL, MODEL_VERSION_EMAIL
├── .gitignore                # .env, data/, models/**/*.joblib, *.db, *.eml, *.mbox
├── .claude/                  # Claude Code rules (rules/), slash commands (commands/), settings
├── configs/
│   ├── url.yaml              # dataset paths + SHA-256, seed, model grids, target FPR
│   └── email.yaml
├── src/phishguard/
│   ├── core/                 # shared by training AND serving
│   │   ├── url/              normalize.py  features.py  rules.py  scoring.py
│   │   ├── email/            parse.py  mask.py  features.py  rules.py  scoring.py
│   │   ├── risk.py           # score + rules -> band + wording
│   │   ├── explain.py        # SHAP / coefficient x value -> top reasons
│   │   ├── registry.py       # load models/<kind>/<version>/, verify SHA-256 + sklearn version
│   │   └── lists/            # brands.txt shorteners.txt free_hosting.txt keywords.txt artefact_stoplist.txt
│   ├── training/
│   │   ├── audit.py  audit_email.py   # data audit -> reports/audit_*.md
│   │   ├── kinds.py  minhash.py       # url/email differences; MinHash near-duplicate groups
│   │   ├── prepare_url.py  prepare_email.py   # clean, dedupe, group, split -> data/processed/*.csv
│   │   ├── models.py         # pipeline factories (lr_char, lr_hand, rf_hand)
│   │   ├── train.py          # grouped CV, threshold, fit final, write models/<kind>/<version>/
│   │   └── evaluate.py       # locked + temporal tests -> reports/results/*.json
│   └── app/
│       ├── main.py           # create_app(): middleware, routers, static SPA
│       ├── config.py  db.py  models_db.py  auth.py  security.py  events.py  retention.py
│       └── routers/          auth.py  analyze.py  analyze_email.py  events.py  history.py  dashboard.py  meta.py
├── web/                      # React app: src/pages, src/components, src/api.ts
├── models/                   # url/<version>/model.joblib + manifest.json (joblib git-ignored)
├── data/                     # raw/ interim/ processed/ (git-ignored)
├── reports/                  # audit_*.md, results/*.json, figures/
└── tests/                    # unit/ integration/ golden/
```

## Data flow

**URL analysis (`POST /api/analyze/url`)**
1. React sends `{url}` with the session cookie and CSRF token.
2. `routers/analyze.py` validates the input (http/https only, size limit).
3. `core/url/normalize.py` refangs and normalises it. Unsupported input gives a friendly 422.
4. `core/url/features.py` builds the feature row, and `core/url/rules.py` runs the rule checks.
5. The model from `core/registry.py` scores it. `core/risk.py` turns score + rules into a band (High / Suspicious / Low / Can't assess). Rules can raise a band, never lower it.
6. `core/explain.py` produces the top model reasons, kept separate from the rule warnings.
7. `db.py` stores the HMAC of the normalised URL, the defanged host, band, reasons, model version and latency. The full URL is never stored.
8. `events.py` pushes an update to that user's SSE stream, and the result JSON goes back to the browser.

**Email analysis (`POST /api/analyze/email`, `/api/analyze/email/upload`)**
1. Input is subject/body fields, pasted raw source, or an uploaded `.eml` (≤ 1 MB, must parse as RFC 822).
2. `core/email/parse.py` extracts headers, text and (href, anchor text) link pairs. HTML is parsed, never rendered.
3. Every link goes through the URL pipeline above. The email band is the higher of the text band and the worst-link URL band (combined at band time in v0.6.0, never trained into the email model, ADR 0007).
4. `core/email/mask.py` masks URLs, addresses and numbers, then `features.py` builds TF-IDF + structural features.
5. `core/email/rules.py` runs header checks (topmost Authentication-Results only), Reply-To mismatch and anchor/href mismatch. Pasted fields can't trigger header rules.
6. Band, explanations, storage (HMAC + sender domain only) and the SSE push work the same way as for URLs.

**Training (offline, via Makefile)**
`make audit` / `audit-email` → `make prepare` / `prepare-email` (dedupe, group by registered domain / MinHash cluster, locked test split) → `make train-url` / `train-email` (StratifiedGroupKFold, thresholds chosen on out-of-fold dev predictions so FPR ≤ 1%, writes model + manifest) → `make evaluate` / `evaluate-email` (locked test used once, plus the newest Nazario year as a temporal test).

**Live dashboard**
`/dashboard` opens `GET /api/events` (SSE, per user). Each new analysis pushes an event, and the page refetches `GET /api/dashboard/summary`.

## Key modules
| Module | Responsibility |
|---|---|
| `core/url`, `core/email` | Parsing, normalisation, features and rules. The single source of truth for both training and serving. `scoring.py` wraps a loaded model for the app (text the model reads, score, band inputs) |
| `core/risk.py` | Thresholds from the manifest + rules → band and fixed wording. Never says "Safe" |
| `core/explain.py` | Model reasons (SHAP for RF, coefficient × value for LR), each showing the real value |
| `core/registry.py` | Loads model files only from `models/` and verifies the hash and sklearn version |
| `training/` | Audit, prepare, train, evaluate. Never imported by the app |
| `app/` | FastAPI app: auth (Argon2id, session cookie, CSRF), routers, DB, SSE, retention purge |
| `web/` | React UI: analyze pages, result card, history, dashboard, privacy page |

## Third-party services and secrets
- The running app calls no third-party services or APIs and makes no outbound requests.
- Datasets are downloaded manually once, never by the app.
- All secrets and config (`SECRET_KEY`, `HMAC_PEPPER`, `DATABASE_URL`, `RETENTION_DAYS`, model versions) live in `.env`, loaded by `app/config.py`. `.env` is git-ignored, and `.env.example` lists the keys with placeholder values. Nothing is ever hardcoded.