# ADR-0009: Email model v2 trained on modern legitimate mail

## Status
Proposed (not accepted: the data source is not yet approved)

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
