# PhishGuard

Offline, explainable phishing risk scoring for URLs and emails. It never visits links and never says "Safe".

## Quick start
```
make setup
make app                  # backend on :8000
cd web && npm run dev     # frontend on :5173
```
Requires Python 3.12 and Node 22. See `AGENTS.md` for commands and conventions, and `ROADMAP.md` for the plan.
