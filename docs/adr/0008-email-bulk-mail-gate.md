# ADR-0008: Email band policy for bulk mail

## Status
Accepted

## Date
2026-10-16

## Context
The email text model (ADR 0007) was trained on 1999-2003 ham. On 123 of the author's own modern Gmail messages (held out, never trained or tuned on) the final band was Suspicious or High for 100% (High 82%). The research notes in `docs/email-false-positives.md` found no public, licensed, real, modern legitimate-mail corpus, so retraining is not possible now. Retraining on a self-collected mailbox is still open (approach A in those notes).

## Decision
Where the text model is out of its depth, stop it speaking. Everything is header- or list-based, offline, and decided without the 123-message sample.

1. **Bulk-mail detection** (`core/email/bulk.py`): a message with real headers is bulk if it has `List-Unsubscribe`, `List-Id`, or `Precedence: bulk|list|junk`. It is "authenticated" if the topmost Authentication-Results shows `dmarc=pass` with a `header.from` equal to or under the From domain. Pasted fields never count as bulk. These are not rules and add no warnings.
2. **Gate** (`core/risk.py: email_decision`): in bulk mail with no strong rule (`auth_fail`, `display_name_mismatch`, `anchor_href_mismatch`), a text High or Suspicious and any Suspicious link become Can't assess. A High link still counts. Low needs an authenticated bulk sender; authentication alone never produces Low.
3. **Link wrappers**: a link on `core/lists/redirectors.txt` is shown as Can't assess and left out of the worst-link band, so tracking links do not push the band up in bulk mail. Outside bulk mail a wrapper still gives Can't assess, as before (ADR 0005). It is never Low.
4. **No headers**: for pasted fields, a text-only High is capped at Suspicious (header checks are unavailable).
5. **Wording** (amends ADR 0002 for email only): when the gate produces Can't assess, the advice reads "This looks like bulk or marketing mail, which the text model was not trained on, so it cannot be rated. Check the sender and the links yourself before acting on it." The band name and headline stay "Can't assess". The model's n-grams are still listed.

Lists: `redirectors.txt` is rspamd `conf/maps.d/redirectors.inc` (Apache-2.0, downloaded 2026-10-16, `twitter.com` removed) plus a few hand-curated email-service click domains. It is used only for email links; `shorteners.txt` and the URL model are unchanged.

## Not done
- EasyPrivacy: its email section holds tracking-pixel path patterns, not click domains, and mapping them to registered domains would blacklist whole publisher sites. Dropped.
- Majestic Million (CC BY 3.0): approved but not used. A "famous domain" discount would change URL bands and needs its own check against PhiUSIIL phishing on top domains.
- Scoring the anchor-text domain of a wrapped link.
- Rule `bulk_mail` as a visible warning: bulk status is shown as a note in the header checks instead.

## Consequences
- Recall cost: phishing that carries `List-Unsubscribe` and no strong rule is now Can't assess instead of High/Suspicious. Phishers can add that header; replayed or ESP-relayed phishing can pass DMARC. This is why authentication never gives Low.
- Measured once on the held-out 123 (`reports/results/email_modern_ham_own_bulkgate.json`, no tuning): flagged (High or Suspicious) 100% -> 82%, High 82% -> 67%, Can't assess 0 -> 22. Only 31 of 123 were detected as bulk, so most of the remaining flags are non-bulk mail the gate does not touch. 29 High links remain.
- Not measured: the recall cost on phishing (Nazario newest year is the locked temporal set, used once, and `evaluate` must not be re-run). Add a recall-cost measurement before relying on this in the wild.
- This is still not a fix for the model: retraining on modern ham is the root-cause work.

## Addendum 2026-10-17: recall cost measured on phishing_pot
Source: phishing_pot (https://github.com/rf-peixoto/phishing_pot), git commit `2933c0341b1248678c1e246b36d352add2edf0f1`, licence CC BY-NC 4.0. Used non-commercially, as a counts-only measurement with owner approval. No message text, sender or link is stored or redistributed; only `reports/results/email_phish_pot.json` (counts and rates). It was not used for training or tuning and was measured once (the first attempt crashed on a malformed header before writing anything; fixed in 54aa377, then run again, no tuning).

Scored 12,247 of 12,269 `.eml` (2 not an email, 20 over the size limit). Email model v1, URL model v2. This is a public sample of phishing, not a population recall, and its era and mix are unknown.

| Band | Ungated | Gated |
|---|---|---|
| High | 55.9% (6,847) | 51.8% (6,347) |
| Suspicious | 42.3% (5,175) | 36.9% (4,519) |
| Can't assess | 0.4% (53) | 10.0% (1,229) |
| Low | 1.4% (172) | 1.2% (152) |
| High or Suspicious | 98.2% | 88.7% (95% CI 88.2-89.3) |

- Lost their flag because of the gate: 1,156 of 12,247 (9.4%, 95% CI 8.9-10.0). Band changed at all: 1,189 (9.7%).
- Text model alone flagged 95.2%; 2,442 (19.9%) messages were detected as bulk.
- Reading: the gate trades about 9 points of phishing recall for 18 points fewer false flags on the author's own mail (100% -> 82%). Whether that is worth it is a policy call; it is a reason to prefer the v2 model (ADR 0009, proposed) over relying on the gate.
- Limits: 82% (own mail) and 88.7% (phishing) come from different samples; neither is a general accuracy figure.
