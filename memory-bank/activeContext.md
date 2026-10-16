# Active Context

## Current focus
v0.4.0 (login and URL analysis in the app) is built on `feature/url-app` and awaits review and merge. v0.3.0 is merged, tagged and pushed, and CI is green on main (PR #4 fixed the install, gitleaks token and fetch-depth).

## Recent decisions
- Band wording fixed in ADR 0002. Band policy in ADR 0005: `t_low` is now the lowest threshold with OOF FPR <= 10% (`target_fpr_low`), capped at `t_high`. Only thresholds changed (same model files and hashes); the locked results file was regenerated once with `--force`.
- lr_char alone decides the band (`manifest.primary`). rf_hand is loadable and evaluated but unused in the app.
- Rules only raise a band, except a shortener: the shortener rule discards the model band and gives Can't assess (Suspicious if a high-severity rule also fired). Decided with the user.
- Sessions are server-side rows (cookie value HMAC'd with SECRET_KEY, HttpOnly, SameSite=Lax), with a CSRF header on all POSTs except register and login. Argon2id passwords. No `itsdangerous` dependency was added.
- The app refuses to start with empty or placeholder SECRET_KEY / HMAC_PEPPER (checked in the lifespan, so importing `main.py` still works without `.env`). With MODEL_VERSION_URL set, a hash or sklearn mismatch also stops startup. With it empty, the app starts and analyze returns 503.
- Claude cannot read `.env` (denied). The user's local `.env` needs `MODEL_VERSION_URL=v1` (now in `.env.example`) and real secrets.
- Model reasons are the top host n-grams (coefficient x TF-IDF) and are shown only for High and Suspicious. Rule warnings are a separate list.
- venv made with `uv venv --python 3.12`. pytest-socket allows loopback only. ESLint pinned to 9. 2 react-router npm audit findings are known and unused (revisit at v1.0.0). tldextract uses its bundled list only.
- ADR 0004: PhiUSIIL leaks through scheme and path, so models are host-only; path and scheme signals live in rules.
- The user gave standing permission to copy downloaded files into the project (e.g. data/raw/).

## Results (locked test, 47,012 rows, 20,051 phishing)
- lr_char: PR-AUC 0.947. At t_high FPR 0.96%, recall 77%. At t_low (new) FPR 9.9%, recall 85.6%.
- rf_hand: PR-AUC 0.895. At t_high FPR 0.96%, recall 64%. At t_low (new) FPR 10.0%, recall 75.9%.
- Heuristic baseline: PR-AUC 0.456.

## Blockers / open questions
- **Known model limitation (ADR 0005):** with the real model, `en.wikipedia.org` scores 0.89 and `github.com` 0.99 (High), while `www.wikipedia.org` scores 0.05. PhiUSIIL legitimate hosts are almost all `www.<site>`, so subdomains look like phishing. The golden Wikipedia test is `xfail(strict)`. Fix later: train on the registrable domain, or add external legitimate hosts. Decide before v1.0.0.
- GNU make is not installed, so the Makefile has not been run end to end.
- The ECONNREFUSED error has not come back. If it does, ask for the exact message first (Vite proxy `/api` -> localhost:8000, or localhost resolving to ::1).
- Prettier `--check .` warns on 6 root config files because of CRLF on this Windows checkout (pre-existing, `src` is clean).

## Next step
Review and merge `feature/url-app`, then decide how to handle the host-model bias, then v0.5.0 (email core and model; read detailedRoadmap.md).
