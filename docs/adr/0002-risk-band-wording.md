# ADR-0002: Risk band wording

## Status
Accepted

## Date
2026-10-16

## Context
The architecture docs name the bands High / Suspicious / Low / Can't assess, while the roadmap expects different user-facing text. The wording must be fixed so the UI, API and golden tests agree, and so the app never implies a link is safe.

## Decision
Internal band keys map to fixed user-facing wording:
- `high`: "Likely phishing"
- `suspicious`: "Suspicious: be careful"
- `low`: "No strong phishing signs found"
- `cant_assess`: "Can't assess"

The word "Safe" is never used. Wording lives in one place, `core/risk.py`.

## Alternatives considered
- Showing percent scores: rejected, it implies false precision.
- A "Safe" band: rejected, an offline model cannot guarantee safety.

## Consequences
Golden tests pin the bands and wording. Changing the text needs a new ADR.
