# ADR-0009: Email model v2 trained on modern legitimate mail

## Status
Accepted for measurement: v2 is trained and measured but is not the default (see Results)

## Date
2026-10-17

## Context
The v1 email text model (ADR 0007) learned legitimate mail from 1999-2003 corpora and flags nearly all modern mail (100% on 123 held-out own Gmail messages). ADR 0008 added a band-time gate for bulk mail, which reduces but does not remove the problem, and its recall cost is being measured on phishing_pot. No public, licensed, modern legitimate-mail corpus was found (`docs/email-false-positives.md`).

## Decision (proposed)
Train a v2 `lr_text` with a modern-ham side from a new self-collected mailbox in mbox format: 200-400 English senders, a per-sender cap, split by sender registered domain, with sender and brand tokens masked. The 123-message sample stays held out and is not used for tuning. Details and steps are in `docs/email-v2-plan.md`.

## Alternatives considered
- Keep v1 plus the ADR 0008 gate only: cheapest, but the model stays wrong on modern mail and the gate is a heuristic phishers can evade.
- Public datasets: none with a suitable licence and modern, real, legitimate mail.
- Synthetic modern ham: would teach the generator's style, not real mail.
- Discount tracker or famous domains (Majestic Million) at band time: changes URL bands and needs its own check.

## Consequences
- Needs the owner's explicit approval of the mailbox and scope before any collection or training.
- Result is specific to one mailbox; it must not be reported as general accuracy.
- The gate in ADR 0008 may be relaxed or removed afterwards; that needs a new ADR.
- Raw mail stays git-ignored; only counts and manifests are committed.

## Update 2026-10-17
Source approved by the owner (own mailbox, any mail, any range, no exclusions). Status stays Proposed until the data is prepared and the model is trained and measured; then it becomes Accepted or is superseded.

## Update 2026-10-17 (second source decision)
The source is widened to the owner's mailbox plus several friends' mailboxes, each with the person's consent. Scope: automated mail only (Promotions, Updates, Social, Purchases); no Spam, Trash, Sent or Chats; each person's mail kept separate; no date restriction beyond what the exports contain (min and max are reported). Raw mbox files stay in git-ignored `data/raw/email_modern/own/v2/<Name>/`; people appear in reports and commits only as `person_N`, with the mapping in a git-ignored file. v2 ham is modern mail only. A requirements check (counts only, PASS/FAIL) runs before any preparation or training. The 123 held-out messages stay held out. Status stays Proposed until the model is trained and measured.

## Results (2026-10-17)
**Data and training.** Six consenting mailboxes (`person_1`..`person_6`), automated mail only. After filters and a cap of 10 per sender domain: 1,696 ham from 337 sender domains (person_2 supplies 48%; person_3 only 25) against 2,808 Nazario phishing. Dev 3,266 rows, locked test 816 (never evaluated), temporal 730. The 647 near-duplicates of the 123 held-out messages were dropped; there was no Message-ID overlap. Social has about 24 messages, so nothing per category is reliable for it. Model: `lr_text`, word 1-2-grams, C=10, trained with `mask: sender` (sender name, domain and brand words, recipient names after a greeting, and a small stoplist hidden; `sender_context_stoplist.txt`). Thresholds on out-of-fold dev: `t_high` 0.770 (FPR 0.97%, recall 93.3%), `t_low` 0.443 (FPR 9.99%, recall 98.3%). Dev PR-AUC 0.996 is NOT real-world accuracy: the two classes differ by era and format as well as intent.

**The 123 held-out own messages, counts only** (`email_modern_ham_own_v2.json`, v1 plus gate in brackets):
- Text model alone: High or Suspicious 22 of 123 = 17.9% (v1 93.5%); High 12 = 9.8% (v1 80.5%).
- Final band with the ADR 0008 gate: High 31, Suspicious 42, Can't assess 22, Low 28. High or Suspicious 73 = 59.3% (v1 + gate 82.1%); High 31 = 25.2% (v1 + gate 66.7%).
- The remaining flags are mostly link bands, which v2 did not change: worst link High 29, Suspicious 40, Low 54.

**phishing_pot recall, 12,247 messages** (`email_phish_pot_v2.json`, counts only, CC BY-NC source, nothing redistributed):
- Text alone flagged 72.8% (v1 95.2%); text Low 27.2% (v1 4.8%).
- Ungated final band 89.9% (v1 98.2%). With the gate 82.5% (v1 88.7%); 911 (7.4%) lost their flag to the gate (v1 9.4%).

**Reading.** v2 cuts false flags from the text model on this mailbox from 93.5% to 17.9%, and pays 22 points of text-only recall on phishing_pot. Part of that recall loss is expected (a text model that no longer treats all bulk mail as phishing also stops flagging bulk-style phishing), and part is the thresholds being set at 1% FPR on modern ham. This is one person-group's mail, small, and not a population rate. The gate and the v2 model overlap: the gate now costs 7.4 points of recall for a benefit that was not re-measured on v2 (the gated vs ungated ham numbers for v2 were not collected, and measuring them now would be a second look at the held-out set).

**Known leaks left in.** `reddy` (a surname, weight about -1.0) was not removed because a committed stoplist should not hold personal names. `unsubscribe` is the strongest ham n-gram (a phisher can add it). `otp` and `your order` rest on few senders.

**Gate recommendation (not decided, no band-policy change made).** Keep the ADR 0008 gate as it is for now. The text model no longer drives the false flags, links do, and the gate is the only thing handling tracker links. The next step is a link-band policy for tracking and wrapper domains, which needs its own ADR (0010). v2 should not become the default (`MODEL_VERSION_EMAIL`) until the owner has reviewed the recall loss; the app loads v2 correctly via `mask: sender`, but there are no app-level v2 golden scores yet.

## Update 2026-10-18 (golden scores, side-by-side for the default decision)
v2 golden scores are now pinned in `tests/golden/scores_email_v2.json` (3 inputs, same tolerance, skipped when the v2 `.joblib` is absent; regenerate with `python tests/golden/test_scores.py`). The default is NOT changed: `MODEL_VERSION_EMAIL` stays `v1`. Existing numbers only, nothing re-measured:

| Measure | v1 | v2 |
|---|---|---|
| Text alone flagged, 123 held-out own mail | 93.5% | 17.9% |
| Final band with gate, 123 held-out | 82.1% | 59.3% |
| phishing_pot text alone flagged (12,247) | 95.2% | 72.8% |
| phishing_pot ungated final | 98.2% | 89.9% |
| phishing_pot gated final | 88.7% | 82.5% |

Switching trades about 6 points of gated phishing recall (and 8 ungated) for 23 points fewer false flags on one group's modern automated mail. Criteria for a later switch: the ADR 0010 benefit result (links cause most remaining flags), and the owner accepting the recall loss.

## Update 2026-10-18 (default switched to v2)
The owner asked for v2 to become the default if it is better. Judged better on balance, with the cost stated. On the 1,004 unused automated messages the final flagged share falls from 53.9% (v1) to 39.8% (v2); on the 123 held-out messages from 82.1% to 59.3%. The price is about 6 points of gated phishing recall on phishing_pot (88.7% to 82.5%; 98.2% to 89.9% ungated). v1 flagged 93.5% of modern ham on text alone and relied on the ADR 0008 gate to hide it, which also hides phishing; v2 needs the gate far less (gated to Can't assess 11% against 35%). Caveats: the ham numbers come from six consenting mailboxes and are not a population rate, and the phishing set is old-style corpus mail. The default in `.env.example` and the README is now `MODEL_VERSION_EMAIL=v2`; v1 stays loadable. Status: Accepted as the default.
