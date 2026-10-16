# Session & Token Efficiency

- Do not re-read entire files that are already visible in context unless they've changed.
- When exploring a codebase, read only the files relevant to the current task, not the whole directory tree.
- Prefer targeted `grep`/search over opening large files fully when just locating something.
- At the end of a work session (or after completing 1-2 features), update the memory bank files (`memory-bank/progress.md`, `memory-bank/activeContext.md`) with current state, then recommend `/clear` or a fresh session for the next feature rather than continuing indefinitely in one conversation.
- At the start of a new session, rely on the memory-bank files that `CLAUDE.md` imports (brief, tech stack, patterns, active context, progress) to rebuild context instead of asking the user to re-explain. Read `memory-bank/architecture.md` and `memory-bank/detailedRoadmap.md` when the task touches structure or the current version's scope.
