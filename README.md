# PhishGuard

Offline, explainable phishing risk scoring for URLs and emails. It never visits links and never says "Safe".

You paste a URL or an email (fields, raw source, or a `.eml` upload) and get a risk band (High / Suspicious / Low / Can't assess), the model's top reasons, and a separate list of rule warnings. Each user has a private history and a live dashboard. The app makes no outbound network requests (no DNS, WHOIS or page fetches).

## Requirements
- Python 3.12 and Node 22 LTS
- GNU make (optional on Windows: the plain commands are listed below)

## Install
```
make setup
```
This creates `.venv`, installs `requirements.lock`, runs `npm ci` in `web/` and copies `.env.example` to `.env` if missing. Without make:
```
python -m venv .venv                       # or: uv venv --python 3.12 .venv
.venv/Scripts/python -m pip install -r requirements.lock      # Linux/macOS: .venv/bin/python
.venv/Scripts/python -m pip install -e . --no-deps
cd web && npm ci
```
Then edit `.env`. It is git-ignored, and the app refuses to start with an empty or placeholder secret:
```
python -c "import secrets; print(secrets.token_hex(32))"   # run twice: SECRET_KEY and HMAC_PEPPER
```
Set `MODEL_VERSION_URL=v2` and, once the email model is trained, `MODEL_VERSION_EMAIL=v1`. With a version empty, that analyzer returns 503.

## Train the models
Datasets are downloaded by hand once into `data/raw/` (git-ignored, never fetched by the app). Checksums and sources are in `configs/url.yaml` and `configs/email.yaml`.
```
make audit prepare train-url                # URL model (PhiUSIIL)
make audit-email prepare-email train-email  # email model (Nazario vs Enron + SpamAssassin)
make evaluate evaluate-email                # locked and temporal tests, written to reports/results/*.json
```
`evaluate` uses each locked test once. Do not re-run it or force it to overwrite results; see ADRs 0004, 0006 and 0007 for the saved numbers. Model files (`models/**/*.joblib`) are git-ignored, and the app refuses to load one whose hash or scikit-learn version differs from its manifest.

## Run
Development:
```
make app                  # backend on :8000
cd web && npm run dev     # frontend on :5173, proxies /api
```
Demo build (one origin, no CORS):
```
cd web && npm run build
make app                  # serves web/dist at http://localhost:8000
```
**Run a single worker.** Live dashboard events are held in process memory, so more than one worker would lose them. Before deploying anywhere reachable, go through `PRE-DEPLOY-CHECKLIST.md`.

## Test and lint
```
make test              # fast Python tests (network blocked, loopback only)
make test-all          # includes slow model-training tests
cd web && npm test
make lint
make audit-deps        # pip-audit and npm audit
pytest tests/integration -q -k offline   # every feature with DNS and connects blocked
```
Golden tests (`tests/golden/`) pin bands and raw scores for saved inputs and skip when a model is not trained locally. After a deliberate model version change, regenerate the scores with `python tests/golden/test_scores.py` and commit the new file with the version bump.

## Known limitations
- The URL model is a weak signal (locked PR-AUC 0.711; recall 34.6% at the High threshold). Short famous `.com` domains such as `google.com` can still score Suspicious or High (ADR 0006). Rules carry much of the weight.
- Email results are not real-world accuracy: the legitimate mail is 1999-2003 prose and the phishing is 2015-2025 templates, so false positives on modern newsletters and receipts are unmeasured (ADR 0007).
- Pasted-fields email mode treats HTML as plain text, so the lookalike-link check only works on raw source or `.eml` uploads.
- `npm audit` reports 2 moderate findings in `react-router` (an open redirect in `<Link>`/`useNavigate` with attacker-controlled targets, and a deserialization issue in SSR hydration). Neither is reachable here: every navigation target in `web/src` is a hardcoded path and the app uses no SSR. Fixing needs a breaking major upgrade, which is deferred because dependencies are pinned for v1.
- Prettier `--check .` warns on 6 root config files because of CRLF line endings on a Windows checkout.

## More
`AGENTS.md` (commands and conventions), `ROADMAP.md` (plan), `memory-bank/architecture.md` (modules and data flow), `docs/adr/` (decisions).
