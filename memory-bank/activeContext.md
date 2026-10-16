# Active Context

## Current focus
v0.1.0 skeleton (branch `feature/skeleton`): layout, tooling, health endpoint, React shell.

## Recent decisions
- Band wording fixed in ADR 0002 (Likely phishing / Suspicious: be careful / No strong phishing signs found / Can't assess).
- CI aligned to Python 3.12, requirements.lock, ruff, Node 22, gitleaks on.
- Local machine has no `make`; Python 3.12 is available via `py -3.12`.

## Blockers / open questions
- Install GNU make (or run Makefile recipes by hand) on this Windows machine.

## Next step
Finish v0.1.0 exit gate, then start v0.2.0 URL core.
