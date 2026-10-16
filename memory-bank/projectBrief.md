# Project Brief: PhishGuard

## What and who
PhishGuard is a web app that checks a suspicious URL or email for phishing risk using explainable machine learning, entirely offline, without ever visiting the link. It's for individuals who want a second opinion before clicking or replying. Each user's history is private.

## v1 goal: what "done" looks like
Built solo in 2–3 weeks. v1 is done when all of these work:
1. **URL detector:** offline scoring from the URL string alone. Logistic Regression on character n-grams plus a Random Forest on hand-crafted features, trained on PhiUSIIL with domain-grouped splits. Thresholds chosen on out-of-fold dev predictions for FPR ≤ 1%.
2. **Email detector:** paste fields, paste raw source, or upload `.eml`. Text model plus the highest URL score among embedded links. Header checks run as rules. Trained on Nazario vs Enron + SpamAssassin ham, with the newest Nazario year held out.
3. **Results:** a risk band (High / Suspicious / Low / Can't assess) with fixed wording, never "Safe". Two separate lists: model reasons and rule warnings.
4. **Accounts:** register (with consent checkbox), login, private history, "Delete all", and a 30-day retention purge.
5. **Live dashboard:** updates over SSE without a page refresh when a new analysis is recorded.
6. **Privacy:** raw email text and full URLs are never stored, only the HMAC, defanged host or sender domain, band and reasons.
7. **Evaluation:** locked test and temporal test results written to `reports/results/*.json`.
8. **Quality:** fast tests, lint and dependency audit pass. The app works with the network disabled.

## Explicitly out of scope
- Browser extension, Gmail or Outlook integration
- WHOIS, DNS, reputation or blocklist lookups, fetching pages or following redirects
- Image, QR code or attachment content analysis
- Non-English input
- Deep-learning models
- Deferred until after v1 (see ROADMAP.md, don't build early): fresh external URL test set, Karim et al. replication, SVM and ensemble models, admin page, model-card page, rate limiting, Playwright E2E, PostgreSQL