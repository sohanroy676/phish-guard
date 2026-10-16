# ADR-0004: URL model artefacts, splits and thresholds

## Status
Accepted

## Date
2026-10-16

## Context
v0.3.0 trains the first URL models. The roadmap fixes the method (LR on char n-grams, RF on hand features, domain-grouped splits, thresholds for FPR ≤ 1% on out-of-fold dev predictions) but not the artefact layout, the second threshold, or the split file format. v0.4.0 will load these artefacts in the app.

## Decision
- Two models per version in `models/url/<version>/`: `lr_char.joblib` (TF-IDF char 2-4-grams + logistic regression, reads `host_text`, the host only) and `rf_hand.joblib` (random forest, reads the 30 features from `core/url/features.py`). `manifest.json` lists, per model, the file, SHA-256, input kind, params, `t_high`, `t_low` and dev out-of-fold metrics. It also records `sklearn_version`, `exclude_features`, seed and the dev data SHA-256.
- PhiUSIIL leaks through scheme and path (`reports/audit_url.md`): every legitimate URL is https with an empty path, against 48.7% https and 27% non-empty paths for phishing. To stop the models learning "has a path", the n-gram model reads the host only (`host_text`), and `configs/url.yaml` excludes `is_https` and the 12 features derived from the path or query from the RF, leaving 17 host-derived features. Path and scheme signals stay in `core/url/rules.py`. The cost is that the model cannot see path-based phishing; locked-test scores are lower than a path-aware model would show, but they are not inflated by the dataset's collection bias.
- `t_high` is the lowest threshold with out-of-fold dev FPR ≤ 1%. `t_low` is the highest threshold that keeps out-of-fold phishing recall ≥ 95%, capped at `t_high`. The roadmap did not define `t_low`; scores at or above `t_high` map to High, between the two to Suspicious, below `t_low` to Low.
- URLs are deduplicated on scheme + host/path/query. Host/path/query strings that appear with both labels are dropped, since the text model would see identical input with opposite labels.
- Group key is the registered domain (the host for IPs and names without a suffix). The locked test is one fold of `StratifiedGroupKFold`. Splits are stored as CSV (`url, y, group`), so no parquet engine is needed.
- `core/registry.py` loads models only from `models/`, validates kind/version/file names, and checks the file hash and the scikit-learn version before unpickling.
- `evaluate` refuses to overwrite `reports/results/url_locked.json` without `--force`, since the locked test is meant to be used once.

## Alternatives considered
- A single combined model: loses the two views the roadmap asks to compare.
- Adding pyarrow for parquet: a new dependency for no gain at about 235k rows.
- Leaving scheme and path in the model inputs: highest locked-test scores, but they would reflect how PhiUSIIL was collected.
- Training only on empty-path URLs: keeps path features but the model never sees path-based phishing.

## Consequences
Changing the feature set, `url_text`, thresholds' definitions or the manifest layout needs a new model version. Retraining after looking at locked results breaks the locked-test protocol, so `--force` should be rare and recorded.
