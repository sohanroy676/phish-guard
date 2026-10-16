# Roadmap

Version-by-version tasks, tests and expected results are in `memory-bank/detailedRoadmap.md`.

## Now (week 1): URL detector end to end
- v0.1.0 Project skeleton and tooling (done)
- v0.2.0 URL core: normalise, features, rules (done)
- v0.3.0 URL data audit, training and locked evaluation (done, awaiting merge)
- v0.4.0 Login and URL analysis in the app

## Next (weeks 2–3): emails, dashboard, finish
- v0.5.0 Email core and email model
- v0.6.0 Email analysis in the app
- v0.7.0 History, live dashboard, retention
- v1.0.0 Hardening, offline check, final evaluation

## Later / ideas (only after v1.0.0)
- Fresh external URL test set (PhishTank/OpenPhish + Common Crawl inner pages), which needs weeks of collection
- Karim et al. LSD replication on UCI Phishing Websites
- Calibrated LinearSVC and a soft-voting ensemble, kept only if it wins a paired test
- Admin page (aggregate counts only) and model-card page
- Rate limiting on login and analyze endpoints
- Playwright end-to-end tests and hypothesis property tests
- Stacking, offline blocklist snapshot as a separate check, LLM-rewritten robustness test set
- PostgreSQL

## Explicitly not planned
- Browser extension, Gmail or Outlook integration
- WHOIS, DNS, reputation lookups, page fetching or redirect-following
- Image, QR code or attachment content analysis
- Multilingual input
- Deep-learning models