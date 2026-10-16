# ADR-0006: URL n-gram model reads the registered domain

## Status
Accepted

## Date
2026-10-16

## Context
ADR 0005 recorded that the v1 `lr_char` model (which read the full host) over-flagged real sites: `en.wikipedia.org` scored 0.89 and `github.com` 0.99, while `www.wikipedia.org` scored 0.05. PhiUSIIL legitimate hosts are almost all `www.<site>`, so the model learned `www.` as a legitimacy signal. The locked test could not show this, because it has the same artefact.

## Decision
- `core/url/features.py` gains `domain_text()`: the registered domain (`wikipedia.org`, `bbc.co.uk`), or the whole host for IPs and names without a public suffix. `lr_char` reads it at training and serving time. Subdomain signals stay in the rules and in the RF host features.
- Model version `v2`. The manifest input kind is `domain_text`. `UrlScorer` supports both `host_text` (v1) and `domain_text`, and the model reasons are computed on the text the scorer actually used.
- `prepare_url.py` keeps one row per (label, registered domain) and drops domains that appear with both labels. This makes the rows match what the model reads and stops domains with many hosts from outweighing others. It changes the dev and test rows, so v2 has a **new split and a new locked test**. v1's processed CSVs were overwritten, so v1 cannot be retrained from the current splits; v1 stays on disk for reference only.
- The locked result is written to `reports/results/url_locked_v2.json` (first use, no `--force`). `url_locked.json` stays as the v1 record.
- `.env.example` now sets `MODEL_VERSION_URL=v2`.

## Results
Locked test v2 (35,078 rows, 8,678 phishing), `lr_char`: PR-AUC 0.711, ROC-AUC 0.832. At `t_high` (0.809) FPR 1.2%, recall 34.6%. At `t_low` (0.576) FPR 10.1%, recall 58.3%. The heuristic baseline's PR-AUC is 0.267. v1 reported PR-AUC 0.947, but that number was inflated by the `www.` and one-host-per-site artefacts, so the two are not comparable.

Spot checks on non-test hosts (not used for tuning): `en.wikipedia.org`, `www.wikipedia.org` and `wikipedia.org` all score 0.13 (Low). `bbc.co.uk` 0.09, `nytimes.com` 0.10. Phishing-looking domains such as `paypal-secure-login.xyz` score 0.997. v1 scored `google.com` 0.999, `amazon.com` 0.991 and `github.com` 0.994.

## Alternatives considered
- Add external legitimate hosts (a top-sites list): needs a manual download and licence check, and adds a source artefact (bare domains would come only from the extra list). Kept as the follow-up.
- Strip only `www.`: leaves `en.`, `api.` and other subdomains off-distribution.

## Consequences
Known limitation: short famous `.com` domains still look suspicious to a model trained on PhiUSIIL alone (`google.com` 0.82 High, `amazon.com` 0.71 and `github.com` 0.59 Suspicious). The golden test for them is `xfail(strict)`. Recall is much lower than v1 claimed; the model is a weak signal, and the rules carry more weight than the v1 numbers suggested. If this matters for v1.0.0, add an external legitimate-host source as v3. Do not tune on the golden hosts.
