# ADR-0007: Email models, corpora and evaluation design

## Status
Accepted

## Date
2026-10-16

## Context
v0.5.0 adds the offline email detector: parsing, masking, rules, two models and their evaluation. The roadmap fixes the corpora (Nazario phishing vs Enron and SpamAssassin ham) and a temporal test on the newest Nazario year. It leaves open how to build inputs that work for pasted fields as well as raw mail, how to group near-duplicates without a new dependency, how to read a temporal test when ham has no dates, and how to treat features that identify a corpus.

## Decision
**Corpora** (downloaded by hand into `data/raw/email/`, never by the app; every file is pinned by SHA-256 in `configs/email.yaml`):
- Phishing: Nazario corpus, `phishing-2015` to `phishing-2025` mboxes, CC-BY-4.0 (attribution: Jose Nazario, monkey.org/~jose/phishing).
- Ham: SpamAssassin public corpus 20030228 (`easy_ham`, `easy_ham_2`, `hard_ham`, no spam) and a seeded sample of 6,000 files from the Enron CMU maildir (2015-05-07 release), skipping deleted, junk and spam folders. 6,000 is about twice the Nazario mail kept in the first audit.
- Rows after cleaning: 12,203. Dropped: unreadable or oversized mail, texts under 3 words, exact duplicates, and mail with almost no common English words (non-English input is out of scope and its words would otherwise become phishing features).

**Inputs, header-independent.** Both models read only the subject and body text (`lr_text`: word 1-2-gram TF-IDF on `core/email/features.model_text`) or structural counts (`rf_struct`: 11 features after exclusions). Headers are used only by rules, so a pasted-fields email is scored exactly like an uploaded one. The URL score is **not** a model feature. In v0.6.0 the email band is the higher of the text band and the worst-link URL band.

**Masking and artefacts.** `mask_text` replaces URLs, addresses, amounts and numbers with tokens. `model_text` then drops the number and URL tokens, separator rulers and the words in `core/lists/artefact_stoplist.txt`. Numbers and URLs encode message format and era: old plain-text ham is full of dates and inline URLs, while HTML phishing keeps its URLs in `href`s that never reach the text. The stoplist holds corpus names, list footers, reply/forward markers, month and day names, the `.org` that Nazario's domain anonymisation leaves behind, and Enron first names and topics. It grew in two rounds from the audit and from the top coefficients of the trained model, using dev data only.

**Excluded features.** `n_links`, `n_link_domains` (Enron mail has almost no links, so these separate Enron from SpamAssassin with AUC 0.12) and `has_html` (AUC 0.97 for phishing vs ham, purely because the ham is early-2000s plain text) are excluded from `rf_struct`. Link and mismatch signals stay in the rules.

**Near-duplicate groups.** `training/minhash.py`: 5-word shingles, 64 permutations, 16 bands x 4 rows, joined when the estimated Jaccard similarity is at least 0.7, with union-find. No group appears in more than one of dev, locked test and temporal set. Texts that appear with both labels would be dropped (none were found).

**Splits.** The temporal set is the newest Nazario year (2025) minus any mail whose group also holds older mail (11 rows dropped). Everything else is split by one fold of `StratifiedGroupKFold` into dev (9,441 rows, 1,913 phishing) and the locked test (2,361 rows, 478 phishing). **Ham has no dates**, so the temporal set reuses the locked-test ham. Its FPR is a held-out ham estimate, not a temporal measurement, and only the phishing side is temporal. The results file says so in a `note` field. The temporal set has 2,273 rows (390 phishing).

**Thresholds** as for URLs (ADR 0004, 0005): from out-of-fold dev scores, `t_high` at FPR <= 1% and `t_low` at FPR <= 10%. `evaluate` refuses to run if any result file exists, so neither test set is spent twice.

## Results
Out-of-fold on dev: `lr_text` PR-AUC 0.9954, `rf_struct` 0.8944. The locked test was used once, after the leakage checks.

| | PR-AUC | FPR at t_high | recall at t_high | FPR at t_low | recall at t_low |
|---|---|---|---|---|---|
| locked, lr_text | 0.9965 | 1.12% | 97.7% | 8.1% | 99.6% |
| locked, rf_struct | 0.8967 | 0.96% | 65.3% | 9.4% | 87.0% |
| locked, rule baseline | 0.2536 | 0.16% | 7.1% | | |
| temporal, lr_text | 0.9943 | 1.12% (ham, not temporal) | 97.2% | 8.1% | 99.7% |
| temporal, rf_struct | 0.7886 | 0.96% (ham, not temporal) | 44.9% | 9.4% | 78.5% |
| temporal, rule baseline | 0.1929 | 0.16% | 3.3% | | |

`lr_text` is the primary model. The top coefficients after cleaning are phishing wording (`your account`, `dear`, `kindly`, `verify`, `payment`, brand names) against conversational function words in ham (`the`, `me`, `thanks`, `meeting`). The temporal scores are slightly lower than the locked ones, as expected, and `rf_struct` drops much more.

## Alternatives considered
- Train the worst-link URL score into the email model: rejected, it ties the email model to the URL model version and the URL model is weak (ADR 0006). Combining bands at band time keeps both inspectable.
- Keep number and URL tokens in the text: the first model scored OOF PR-AUC 0.996 largely on dates, list footers and ham names. Those were removed before any test set was used, and the score barely moved, so the model does separate the wording as well.
- A language-detection library: a new dependency; a common-English-word ratio is enough to drop obviously non-English mail.
- `datasketch` for MinHash: a new dependency for about 60 lines.

## Consequences
- **The near-perfect `lr_text` scores should not be read as real-world accuracy.** The ham is Enron and SpamAssassin mail from 1999-2003, conversational and plain text, and the phishing is 2015-2025 template mail. Era and style still differ even after the cleaning above, so FPR on modern legitimate mail (marketing, notifications, receipts, which also say "your account") is likely much higher than 1%. The `note` in `email_temporal_v1.json` is the only temporal caveat; there is no modern ham. A modern legitimate-mail source is the follow-up, as with ADR 0006's host list.
- The rules (`core/email/rules.py`) and the URL band carry signal the text model cannot, so v0.6.0 must show them separately and not average them in.
- English only. Non-English mail is dropped from training and is not assessed meaningfully.
- Retraining is deterministic for a seed, but `prepare_email` takes several minutes (parsing, not fitting).
