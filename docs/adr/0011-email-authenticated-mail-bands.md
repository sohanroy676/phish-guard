# ADR-0011: Email bands for authenticated mail

## Status
Proposed (design only, nothing implemented, nothing tuned)

## Date
2026-10-18

## Context
The ADR 0010 flag-source breakdown (`reports/results/email_flag_sources.json`, 1,004 unused automated messages, six consenting mailboxes) shows where the remaining false flags come from. Under email v2 (the new default, ADR 0009):
- 284 of 400 flags (71%) need only the links. 343 messages (34.2% of all mail) have a counted link that the URL model rates High or Suspicious on its own. The URL model was trained on PhiUSIIL URLs and is out of domain for long tracking and campaign URLs on third-party hosts.
- 97 messages (9.7%) stay flagged by high-severity rules alone: `anchor_href_mismatch` 84, `display_name_mismatch` 12, `auth_fail` 1. On authenticated bulk mail the first is usually a tracker redirect behind friendly anchor text.
- The ADR 0008 gate already sets aside Suspicious links in bulk mail, but a High link still counts, and the ADR 0010 exemption only covers the sender's own popular domain.
Cost side: the same rules and links are the main protection against real phishing that reaches the user with a clean-looking sender, and phishing_pot was already used twice (ADR 0008, ADR 0010), so it cannot be a fresh test again.

## Decision (proposed, to be accepted only after the checks below)
Two small, separable changes, each decided on its own result:
1. **Link band in authenticated bulk mail.** When the message is bulk with an aligned `dmarc=pass` and the link has no URL rule hit, a model-only High or Suspicious link band becomes Can't assess (shown as "not counted", never Low). A link with a rule hit still counts. Today only Suspicious is demoted.
2. **`anchor_href_mismatch` on authenticated bulk mail.** When the mismatch is only that the href is a known link wrapper or on the sender's own registered domain, it is reported as a warning, not a high rule. Any other mismatch, and every mismatch outside authenticated bulk mail, stays high.
`display_name_mismatch`, `auth_fail`, `reply_to_mismatch`, the thresholds, the text model and the band wording are not touched.

## Acceptance checks (pre-register before any run)
- **Principle first:** the two rules are chosen from how tracking mail works, not from the 1,004 sample. That sample has been looked at, so its numbers can only be reported as exploratory.
- **Benefit (confirmatory):** a fresh sample of automated mail from a mailbox or time range not used so far, with the owner's approval (like ADR 0009). Bar: the flagged share drops by at least 5 points absolute with the 95% Wilson interval of the share of messages that lost a flag above zero. If no fresh sample exists, the result is recorded as exploratory and the owner decides.
- **Cost:** gated phishing recall must not fall by more than 2 points absolute on phishing mail that has not been used to choose this policy. phishing_pot has been used twice; a third run needs the owner's explicit permission, or a different phishing set (licence check first). The locked and temporal Nazario sets stay untouched, and `evaluate` and `--force` are never run.
- **Safety invariants as tests:** a High or Suspicious link with a URL rule hit still flags; unauthenticated or non-bulk mail is unchanged; pasted fields are unchanged; a mismatch to an unrelated, non-wrapper domain stays high; the golden scores stay unchanged.
- Counts only, never text, domains or file names; one run, never overwritten.

## Alternatives considered
- **Do nothing.** Keeps maximum recall, leaves about 40% of modern automated mail flagged, which teaches users to ignore the tool.
- **Retrain the URL model on tracking URLs.** Needs a labelled source of legitimate tracking URLs; out of scope for v1.x and prone to leaking sender identity.
- **Drop all link bands for authenticated mail.** Simple, but a compromised or look-alike sender that passes dmarc on its own domain would hide its payload; Can't assess with a rule-hit exception is weaker but safer.
- **Allow-list ESP domains.** Already partly done by `redirectors.txt`; an open-redirect on an ESP is exactly the evasion a phisher uses, so it is only used to discount, never to mark Low.

## Consequences
- Fewer false flags on bulk mail from authenticated senders; a High link inside such mail is shown as "not counted" instead of raising the band.
- Some phishing sent through an authenticated bulk service would drop from Suspicious/High to Can't assess. This is the recall cost the bar above caps at 2 points.
- Needs a new golden check and a counts-only measurement tool, built only after the owner accepts the plan.
