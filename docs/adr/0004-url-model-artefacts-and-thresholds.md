# ADR-0004: URL model artefacts, splits and thresholds

## Status
Accepted

## Date
2026-10-16

## Context
v0.3.0 trains the first URL models. The roadmap fixes the method (LR on char n-grams, RF on hand features, domain-grouped splits, thresholds for FPR ≤ 1% on out-of-fold dev predictions) but not the artefact layout, the second threshold, or the split file format. v0.4.0 will load these artefacts in the app.

## Decision
- Two models per version in `models/url/<version>/`: `lr_char.joblib` (TF-IDF char 2-4-grams + logistic regression, reads `url_text`) and `rf_hand.joblib` (random forest, reads the 30 features from `core/url/features.py`). `manifest.json` lists, per model, the file, SHA-256, input kind, params, `t_high`, `t_low` and dev out-of-fold metrics. It also records `sklearn_version`, `exclude_features`, seed and the dev data SHA-256.
- `url_text` (host + path + query, no scheme) is the n-gram input, so the text model cannot learn from http vs https. If the audit shows a large scheme gap between classes, `is_https` goes into `exclude_features` for the RF and the scheme is left to rules.
- `t_high` is the lowest threshold with out-of-fold dev FPR ≤ 1%. `t_low` is the highest threshold that keeps out-of-fold phishing recall ≥ 95%, capped at `t_high`. The roadmap did not define `t_low`; scores at or above `t_high` map to High, between the two to Suspicious, below `t_low` to Low.
- URLs are deduplicated on scheme + host/path/query. Host/path/query strings that appear with both labels are dropped, since the text model would see identical input with opposite labels.
- Group key is the registered domain (the host for IPs and names without a suffix). The locked test is one fold of `StratifiedGroupKFold`. Splits are stored as CSV (`url, y, group`), so no parquet engine is needed.
- `core/registry.py` loads models only from `models/`, validates kind/version/file names, and checks the file hash and the scikit-learn version before unpickling.
- `evaluate` refuses to overwrite `reports/results/url_locked.json` without `--force`, since the locked test is meant to be used once.

## Alternatives considered
- A single combined model: loses the two views the roadmap asks to compare.
- Adding pyarrow for parquet: a new dependency for no gain at about 235k rows.
- Leaving the scheme in the n-gram text: lets the model shortcut on http/https.

## Consequences
Changing the feature set, `url_text`, thresholds' definitions or the manifest layout needs a new model version. Retraining after looking at locked results breaks the locked-test protocol, so `--force` should be rare and recorded.
