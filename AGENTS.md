# AGENTS.md

PhishGuard: an offline web app that scores URLs and emails for phishing risk with explainable ML, showing risk bands, reasons, private history and a live dashboard.

Stack: Python 3.12 · FastAPI · scikit-learn · SQLAlchemy + SQLite · React 18 + Vite + TypeScript

- Setup: `make setup`
- Run: `make app` and `cd web && npm run dev`
- Test: `make test` and `cd web && npm test`
- Lint: `make lint`

Critical conventions:
- Feature logic lives only in `src/phishguard/core/` and is shared by training and serving. Never duplicate it.
- The app never makes network requests or visits links (no WHOIS, DNS or fetching).
- Never store raw email text or full URLs. Store only the HMAC, defanged host, band and reasons.
- Secrets live only in `.env` (see `.env.example`). Never hardcode them.

Detailed rules: see `.clinerules/`.