# CLAUDE.md

PhishGuard scores URLs and emails for phishing risk with explainable ML, fully offline. It never visits links, and users get a risk band (High / Suspicious / Low / Can't assess, never "Safe"), model reasons, rule warnings, private history and a live SSE dashboard. v1 is a solo 2–3 week build; see the roadmap for the version plan.

The tool-agnostic summary, commands and critical conventions live in AGENTS.md:

@AGENTS.md

## Project context (memory bank)

@memory-bank/projectBrief.md
@memory-bank/tech-stack.md
@memory-bank/systemPatterns.md
@memory-bank/activeContext.md
@memory-bank/progress.md

Read these on demand rather than every session:
- `memory-bank/architecture.md`: folder layout, module responsibilities, data flow
- `memory-bank/detailedRoadmap.md`: per-version tasks, tests, expected results and red flags
- `ROADMAP.md`: Now / Next / Later plan and what is explicitly not planned
- `docs/adr/`: architecture decision records (start from `adr-template.md`)
- `PRE-DEPLOY-CHECKLIST.md`: run before deploying anywhere reachable

Keep `memory-bank/activeContext.md` and `memory-bank/progress.md` current at the end of each session.

## Rules and commands

Rules in `.claude/rules/` load automatically: security, commit style, testing, self-review, git workflow and session efficiency.

Slash commands in `.claude/commands/`:
- `/new-feature`: implement a feature end to end on a feature branch
- `/debug`: reproduce, root-cause and fix a bug with a regression test
- `/commit`: review, test, lint and commit current changes, then regenerate `CHANGELOG.md`
