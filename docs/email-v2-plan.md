# Email model v2 plan (modern legitimate mail)

Status: PROPOSED. Nothing in this plan has been collected, downloaded or trained. The source needs the owner's approval first (see "Approval gate").

## Why
The v1 text model learned "ham" from 1999-2003 Enron and SpamAssassin prose. On 123 of the owner's own modern Gmail messages it flagged 100% (ADR 0007 addendum). The bulk-mail gate (ADR 0008) hides part of this at band time but does not fix the model. v2 replaces the ham side with modern mail. See `docs/email-false-positives.md` for why no public licensed corpus exists.

## Source (needs approval)
- A new mailbox export in mbox format (a Google Takeout or similar), different from the held-out 123 sample.
- Target: 200-400 distinct English-language senders, so one sender or newsletter cannot dominate. Cap messages per sender (suggest 10) so counts are balanced.
- Only English mail; the existing language filter is reused.
- Kept in `data/raw/email_modern/v2/` (git-ignored). Raw mail is never committed or shared. Only counts, hashes and manifests are committed.
- Which mailbox, which date range and whose mail is the owner's decision. Mail from other people (personal correspondence) should be excluded or the owner should confirm they are comfortable using it; a mailbox of automated mail only (receipts, newsletters, notifications) is the safest choice.

## Hold-outs
- The 123-message sample stays held out forever: never trained on, never tuned on. Dedupe v2 candidates against it (Message-ID, and the existing MinHash near-duplicate check).
- The Nazario newest year stays the temporal phishing test. `evaluate` is not re-run for v1; v2 gets its own new result files and a new label.

## Split
- Split by sender registered domain (`tldextract`, offline): all mail from one domain lands in exactly one of train / dev / test. Reuses the group-split approach of `training/prepare.py`; no new split logic duplicated.
- Phishing side keeps the existing Nazario groups and temporal hold-out.
- Thresholds again chosen on out-of-fold dev predictions (FPR targets as in ADR 0005), never on test.

## Masking (leakage control)
Modern senders carry brand names and sender-specific boilerplate that would let the model memorise "this brand = ham". Before training:
- Replace the sender address, sender display name and sender registered domain wherever they appear in subject/body with a token (extend `core/email/mask.py`, so training and serving share it).
- Mask brand tokens: the sender's own brand words (from display name and domain label). Optionally a short list of the most frequent brand tokens in the corpus.
- Keep existing masks (URL, email, money, number tokens) and drop footers that repeat per sender if they dominate top n-grams.
- Check: top coefficients must not be sender or brand names; run the existing top n-gram review before looking at any test number.

## Steps (after approval)
1. Approve source and scope (owner). Write down the export date and file SHA-256 in `configs/email.yaml`.
2. Convert mbox to `.eml` outside the repo tree's tracked files; strip nothing else.
3. Prepare: dedupe vs the 123, language filter, per-sender cap, group split.
4. Extend masking, add unit tests (adversarial: brand in display name only, IDN, subdomains).
5. Train `lr_text` v2 (same model family; no new architecture). Compare with v1 only on dev, not on the hold-outs, until the end.
6. Measure once on the 123 held-out sample and once on phishing_pot recall (counts only), no tuning afterwards.
7. Decide whether the ADR 0008 gate stays, is relaxed, or is removed. Any band-policy change needs its own ADR.

## Risks
- One person's mailbox is a single-user distribution; v2 will be better on modern bulk mail but is not a general accuracy claim.
- Privacy: the corpus contains personal mail. Never log or commit text; only aggregate counts.
- Fewer than ~200 senders gives a noisy FPR estimate; say so in the results.

## Approval gate
Do not collect, convert or train anything until the owner approves, in writing: (1) the mailbox, (2) the date range, (3) any exclusions. ADR 0009 is Proposed until then.
