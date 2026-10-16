# Tech Stack

## Languages and frameworks
- **Backend / ML:** Python 3.12
  - FastAPI + Uvicorn (API server)
  - SQLAlchemy 2 on SQLite in WAL mode
  - scikit-learn, pandas, NumPy, SciPy (data and models)
  - tldextract, configured offline with its bundled suffix list (no network fetch)
  - shap (explanations for the Random Forest)
  - argon2-cffi (password hashing), joblib (model files)
- **Frontend:** TypeScript, React 18, Vite, React Router, Recharts, plain CSS
- **Node.js:** 22 LTS (frontend toolchain only)
- **Versions:** pin exact versions on day 1 in `requirements.lock` and `web/package-lock.json`, and don't upgrade during the project. Each model manifest records its scikit-learn version, and the app refuses to load a model whose version doesn't match.

## Package managers
- Python: pip + venv (`.venv/`). Dependencies declared in `pyproject.toml`, pinned in `requirements.lock` (`pip freeze > requirements.lock`)
- Frontend: npm with `package-lock.json` (`npm ci`)

## Testing
- **Python:** pytest, FastAPI TestClient (httpx), pytest-socket (network blocked during tests)
  - Location: `tests/unit/`, `tests/integration/`, `tests/golden/`
  - Naming: files `test_<module>.py`, functions `test_<behaviour>()`
  - Model-training tests are marked `@pytest.mark.slow`
  - Run fast tests: `make test` (runs `pytest -q -m "not slow"`)
  - Run everything: `pytest -q`
- **Frontend:** Vitest + React Testing Library
  - Location: next to the component, named `<Component>.test.tsx`
  - Run: `cd web && npm test`

## Lint and format
- Python: ruff for lint and format: `ruff check .` and `ruff format .`
- Frontend: ESLint (with `react/no-danger` enabled) + Prettier: `npm run lint` and `npm run format`
- Both at once: `make lint` and `make format`
- Dependency audit: `make audit-deps` (runs `pip-audit` and `npm audit`)

## Build, run and dev commands
- First-time setup: `make setup` (creates `.venv`, installs `requirements.lock`, runs `npm ci` in `web/`, copies `.env.example` to `.env` if missing)
- Data audit: `make audit`
- Clean, dedupe, group and split data: `make prepare`
- Train models: `make train-url`, `make train-email`
- Evaluate on locked test sets: `make evaluate`
- Dev backend: `make app` (runs `uvicorn phishguard.app.main:app --reload --port 8000`)
- Dev frontend: `cd web && npm run dev` (Vite on port 5173, proxies `/api` to port 8000)
- Demo build: `cd web && npm run build`, then `make app`. FastAPI serves `web/dist` from the same origin, so there's no CORS. Use a single worker because SSE events live in-process.

## Database and external services
- **Database:** SQLite (WAL) at `DATABASE_URL`, default `sqlite:///./phishguard.db`
- **Runtime external services:** none. The app makes zero outbound network requests.
- **Datasets** (downloaded manually once into `data/raw/`, git-ignored, never fetched by the app):
  - URLs: PhiUSIIL Phishing URL Dataset (UCI, CC BY 4.0). Its label `1` means legitimate, not phishing.
  - Emails: Nazario phishing corpus (phishing) vs Enron + SpamAssassin ham (legitimate). No spam corpora.