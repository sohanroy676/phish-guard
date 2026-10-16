"""Word lists used by URL features and rules, packaged as plain text files."""

from functools import cache
from importlib import resources


@cache
def load_list(name: str) -> frozenset[str]:
    """Return the entries of `<name>.txt` (lowercase, comments and blanks skipped)."""
    text = resources.files(__package__).joinpath(f"{name}.txt").read_text(encoding="utf-8")
    lines = (line.strip().lower() for line in text.splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))
