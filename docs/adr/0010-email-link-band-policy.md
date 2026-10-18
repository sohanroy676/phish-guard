# ADR-0010: Email link-band policy (tracker and sender-owned links)

## Status
Implemented on `feature/email-link-policy`; phishing cost measured, benefit NOT measured (no fresh sample). Not Accepted until the benefit check runs

## Date
2026-10-17

## Context
The v2 text model (ADR 0009) cut text-only false flags on the 123 held-out own messages from 93.5% to 17.9%. The final band still flags 59.3% (High 31, Suspicious 42, Can't assess 22, Low 28) because the worst link decides: worst link was High on 29 and Suspicious on 40 of the 123 (`email_modern_ham_own_v2.json`). The same link counts appeared with v1, so the link side did not change.

Why links over-flag modern mail:
- The URL model (ADR 0006) scores only the registered domain of a link. Its training data (PhiUSIIL) has no email tracking, CDN or ESP domains, so a short or unusual tracker domain looks like a phishing host.
- "Worst link wins" means one odd tracking link in a mail with ten good ones sets the band.
- The ADR 0008 gate turns a Suspicious link into Can't assess in bulk mail, but a High link still counts, and non-bulk mail is untouched.

Constraint: any change here lowers phishing recall somewhere. Phishers can use their own domain with valid SPF, DKIM and DMARC, and links on compromised well-known sites.

## Decision (proposed)
Extend the link-wrapper idea of ADR 0008 with one evidence-based exemption, and keep every other part of the band policy as is.

1. **Sender-aligned, well-known links are left out of the worst-link band.** A link is left out only when both hold: (a) its registered domain equals, or is under, the registered domain in the From header of a message whose topmost Authentication-Results shows an aligned `dmarc=pass` (`BulkInfo.authenticated`), and (b) that registered domain is on a bundled list of widely used domains. Either condition alone is not enough: (a) alone would let an attacker send DMARC-valid mail from their own domain with links to the same domain; (b) alone would exempt links to a big domain placed in a forged mail.
2. **Left-out links are shown, not hidden.** Each is listed with the note "link to the sender's own domain, not counted", like wrapper links in ADR 0008, and is never rated Low.
3. **Everything else is unchanged:** a High link on any other domain still counts, rules still raise and never lower, the bulk gate and its wording stay. No threshold changes.
4. **The list** (`core/lists/popular_domains.txt`) is a bundled static file, not a network lookup. Candidate source: Majestic Million (CC BY 3.0, as in ADR 0008). The licence and the exact terms must be re-checked from the source before download, because the earlier note was not verified. The cut-off (top N) is chosen before measuring, from the list's own rank, not tuned on the 123.

## Acceptance checks (before this ADR becomes Accepted)
Counts only, each run once, no tuning on the held-out data:
- **Phishing cost on URLs:** the share of PhiUSIIL phishing URLs whose registered domain is on the list (expected small; if it exceeds 1%, shrink N or drop the exemption).
- **Phishing cost on mail:** on phishing_pot, how many messages lose a flag because of the exemption (needs an aligned `dmarc=pass`, so expected rare). Compare with the 7.4% the gate already removes.
- **Benefit:** on a fresh sample of automated mail that was never scored (not the 123), the drop in High or Suspicious from this rule. A new sample from consenting mailboxes needs the owner's approval first, like ADR 0009.

## Alternatives considered
- **Grow `redirectors.txt` only:** safe, but hand-curated and never complete.
- **Allowlist by popularity alone:** simple, but exempts links to big domains in forged mail and compromised pages; needs the DMARC alignment to be safe.
- **Aligned domain alone, no popularity list:** removes a lot of flags, but opens a gap for attacker-owned domains with valid DMARC.
- **Count the share of bad links instead of the worst:** hides a single phishing link among many good ones, which is how real phishing is built.
- **Retrain the URL model with email link data:** needs a labelled modern link set that does not exist.
- **Do nothing:** keeps about 56% of own bulk mail flagged through links.

## Consequences
- Some phishing sent through a big compromised sender domain with valid authentication will lose its link signal. The text model, rules and header checks remain.
- Authentication data are only available with real headers, so pasted-field mode gets no exemption.
- This is a design for one mailbox group's problem; the benefit is measured on a small sample and is not a general rate.
- Implementation, the list and the measurements are a later branch; the app keeps the ADR 0008 behaviour until then.

## Results (2026-10-18)
Counts only, each check run once, nothing tuned on the 123 held-out messages.

- **Licence.** The Majestic Million page states "Licensed under a Creative Commons Attribution 3.0 Unported License" (fetched from majestic.com/reports/majestic-million). `popular_domains.txt` carries the attribution and the CSV's SHA-256.
- **List.** Pre-registered top N was 10,000; the fallback was 5,000 if the PhiUSIIL check exceeded 1%. Shared hosts are removed (public-suffix private section, `free_hosting`, `shorteners`, new `user_content_hosts.txt`). Bundled: top 5,000, 4,789 domains after removal. Rebuild: `phishguard.training.build_popular_domains`.
- **Phishing cost on URLs (PhiUSIIL, label 0, 100,937 rows, 43,510 domains).** Unfiltered top 10,000: 26.3% of rows, dominated by hosting platforms (web.app, firebaseapp.com, workers.dev), which is why shared hosts are removed. After removal: 2.48% of rows at top 10,000; 1.69% of rows (0.29% of unique domains) at top 5,000. **The 1% bar is missed by rows** (met by domains). The list was not shrunk or edited further, to avoid tuning on this data. The remaining rows are cloud and site-builder domains; the exemption also needs the sender to be that same domain with an aligned `dmarc=pass`, which the mail check below measures.
- **Phishing cost on mail (phishing_pot, 12,247, email v2 + ADR 0008 gate, `email_phish_pot_v2_linkpolicy.json`).** The policy changed the band of 10 messages (0.08%) and removed the High or Suspicious flag from 1 (0.008%). Gated flagged 82.46% -> 82.45%. Bar (at most 1.0 point extra loss) met by a wide margin. phishing_pot was re-scored once for this ADR with the owner's permission; do not re-run.
- **Benefit.** Not measured. A fresh sample of automated mail needs the mailbox owners' approval, which has not been given. The effect on the 123 held-out messages was deliberately not measured.

**Reading.** The exemption costs almost no phishing recall, but its benefit is unproven, and the URL-row bar was missed. Keep the code, treat the status as pending, and measure the benefit before relying on it.

## Implementation notes
`BulkInfo.aligned_domain` (set on any aligned `dmarc=pass`, not only bulk mail); `bulk.is_sender_owned_link` and `link_discount`; used by the email router and the measurement tools. A link with any URL rule hit is never exempted. Exempt links get Can't assess like wrappers, so they are never Low and are shown as "Link to the sender's own domain, not counted". No exemption in pasted-fields mode.

## Benefit check, pre-registered (2026-10-18)
Written before the run. The owner approved reusing the unused part of the ADR 0009 mailboxes instead of a new export.
- **Sample:** automated mail from `data/raw/email_modern/v2_eml/` that passed every ADR 0009 ham filter (allowed category, English, not a duplicate, not near-identical to the 123 held-out messages) and was dropped only by the per-sender cap, so it was never trained on or scored. At most 10 messages per sender domain, in the seeded order. The sample is checked against the training selection by hash.
- **Measure:** `python -m phishguard.training.measure_link_policy`, run once, never overwritten, counts only (`reports/results/email_adr10_benefit.json`). Same model and ADR 0008 gate in both arms; only the sender-owned exemption differs. The email model v1 (the deployed default) is the primary result; v2 is reported in the same run.
- **Bar:** the share of High or Suspicious drops by at least 5 points absolute (v1), and the 95% Wilson interval of the share of messages that lost a flag stays above zero. Met: status becomes Accepted. Not met: the owner chooses Accepted-without-benefit or Rejected (revert the exemption and `popular_domains.txt`).
- **Limits:** senders overlap with the v2 training data, and only six mailboxes are covered, so the result is not a population rate. It cannot show that the exemption is safe against forged mail; that rests on the phishing_pot check.
