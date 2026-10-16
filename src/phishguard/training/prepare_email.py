"""Parse, dedupe, group and split the email corpora -> data/processed/email_{dev,test,temporal}.csv.

Phishing is the Nazario corpus (one mbox per year). Ham is SpamAssassin ham plus a seeded sample of
the Enron maildir. All features come from core/email, so training and serving cannot drift.
"""

import argparse
import hashlib
import mailbox
import os
import random
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from phishguard.core.email.features import FEATURE_NAMES, email_features, model_text
from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, parse_raw
from phishguard.core.email.rules import run_rules
from phishguard.core.registry import sha256_file
from phishguard.training.common import load_config, resolve, write_json
from phishguard.training.kinds import KINDS
from phishguard.training.minhash import group_ids

MIN_WORDS = 3
# Non-English input is out of scope and its words ("de", "en", ...) would become phishing features,
# because the ham corpora are English. A text with almost no common English words is dropped.
ENGLISH_WORDS = frozenset(
    "the and to of a in is you your for that this it with on be are as we at have will not".split()
)
ENGLISH_MIN_SHARE = 0.08
ENGLISH_CHECK_FROM_WORDS = 15  # shorter texts are kept: too little text to judge
ENRON_SKIP_FOLDERS = frozenset({"deleted_items", "junk", "spam", "junk_file", "junk_mail"})
SPAMASSASSIN_HAM_DIRS = ("easy_ham", "easy_ham_2", "hard_ham")
META_COLUMNS = ["y", "group", "source", "year", "text", "rule_score"]
OUT_COLUMNS = META_COLUMNS + list(FEATURE_NAMES)


@dataclass(frozen=True)
class Record:
    y: int  # 1 = phishing
    source: str  # nazario | spamassassin | enron
    year: int | None  # only Nazario files are dated
    raw: bytes


def looks_english(text: str) -> bool:
    words = text.split()
    if len(words) < ENGLISH_CHECK_FROM_WORDS:
        return True
    return sum(w in ENGLISH_WORDS for w in words) / len(words) >= ENGLISH_MIN_SHARE


def iter_nazario(directory: Path) -> Iterator[Record]:
    for path in sorted(directory.glob("phishing-*.mbox")):
        match = re.search(r"(\d{4})", path.name)
        year = int(match.group(1)) if match else None
        box = mailbox.mbox(path)
        try:
            for key in box.iterkeys():
                yield Record(1, "nazario", year, box.get_bytes(key))
        finally:
            box.close()


def list_files(directory: Path, skip_folders: frozenset[str] = frozenset()) -> list[Path]:
    """Every regular file below `directory`, sorted, without skipped folders or `cmds` files."""
    files: list[Path] = []
    for root, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d.lower() not in skip_folders)
        files.extend(Path(root) / n for n in sorted(names) if n != "cmds")
    return files


def iter_ham(directory: Path, source: str, skip_folders=frozenset(), sample=None, seed=0):
    files = list_files(directory, skip_folders)
    if sample is not None and sample < len(files):
        files = sorted(random.Random(seed).sample(files, sample))
    for path in files:
        yield Record(0, source, None, path.read_bytes())


def load_records(cfg: dict[str, Any]) -> Iterator[Record]:
    raw = resolve(cfg["raw_dir"])
    yield from iter_nazario(raw / "nazario")
    for name in SPAMASSASSIN_HAM_DIRS:
        yield from iter_ham(raw / "spamassassin" / name, "spamassassin")
    yield from iter_ham(
        raw / "enron",
        "enron",
        ENRON_SKIP_FOLDERS,
        sample=cfg.get("enron_sample"),
        seed=cfg["seed"],
    )


def check_sources(cfg: dict[str, Any]) -> dict[str, str]:
    """Verify every pinned raw file against configs/email.yaml. Returns the hashes found."""
    found: dict[str, str] = {}
    for rel, expected in (cfg.get("sources") or {}).items():
        path = resolve(cfg["raw_dir"]) / rel
        if not path.is_file():
            raise FileNotFoundError(f"Source file not found: {path}")
        found[rel] = sha256_file(path)
        if expected and expected != found[rel]:
            raise ValueError(f"{rel} does not match its sha256 in configs/email.yaml.")
    return found


def build_frame(records: Iterable[Record]) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Parse every record with core/email. Drops unreadable, tiny and exact-duplicate messages."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    counts: dict[str, Any] = {"per_source": {}}

    def bump(source: str, key: str) -> None:
        stats = counts["per_source"].setdefault(source, {})
        stats[key] = stats.get(key, 0) + 1

    for rec in records:
        bump(rec.source, "seen")
        try:
            parsed = parse_raw(rec.raw)
        except EmailTooLarge:
            bump(rec.source, "too_large")
            continue
        except NotAnEmail:
            bump(rec.source, "unparseable")
            continue
        text = model_text(parsed)
        if len(text.split()) < MIN_WORDS:
            bump(rec.source, "too_short")
            continue
        if not looks_english(text):
            bump(rec.source, "non_english")
            continue
        key = (rec.y, hashlib.md5(text.encode("utf-8")).hexdigest())
        if key in seen:
            bump(rec.source, "exact_duplicate")
            continue
        seen.add(key)
        hits = run_rules(parsed, headers=False)  # body rules only: baseline must not need headers
        rows.append(
            {
                "y": rec.y,
                "source": rec.source,
                "year": rec.year,
                "text": text,
                "rule_score": 10 * sum(h.severity == "high" for h in hits) + len(hits),
                **email_features(parsed),
            }
        )
        bump(rec.source, "kept")
    frame = pd.DataFrame(rows, columns=[c for c in OUT_COLUMNS if c != "group"])
    frame["year"] = frame["year"].astype("Int64")
    return frame, counts


def split_frame(
    frame: pd.DataFrame, seed: int, test_fraction: float
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Group near-duplicates, then return (dev, test, temporal, counts).

    No group appears in more than one of dev, test and temporal. The temporal set is the newest
    Nazario year plus the locked-test ham, because ham has no dates (a held-out ham estimate).
    """
    frame = frame.copy()
    frame["group"] = [f"g{i}" for i in group_ids(frame["text"].tolist(), seed)]
    counts: dict[str, int] = {"rows_before_grouping": len(frame)}

    # One text appearing with both labels would be identical input with opposite labels.
    conflicting = frame.groupby("group")["y"].transform("nunique") > 1
    counts["conflicting_dropped"] = int(conflicting.sum())
    frame = frame[~conflicting].reset_index(drop=True)

    newest = frame["year"].max()
    is_newest = (frame["year"] == newest).fillna(False).to_numpy(dtype=bool)
    # Newest-year mail that sits in a group with older mail would leak into dev or test.
    newest_in_group = frame.assign(_n=is_newest).groupby("group")["_n"]
    mixed = (newest_in_group.transform("any") & ~newest_in_group.transform("all")).to_numpy(bool)
    counts["temporal_mixed_group_dropped"] = int((mixed & is_newest).sum())
    temporal = frame[is_newest & ~mixed].reset_index(drop=True)
    pool = frame[~is_newest].reset_index(drop=True)

    splitter = StratifiedGroupKFold(
        n_splits=round(1 / test_fraction), shuffle=True, random_state=seed
    )
    _, test_idx = next(splitter.split(pool, pool["y"], groups=pool["group"]))
    is_test = pool.index.isin(test_idx)
    dev, test = pool[~is_test].reset_index(drop=True), pool[is_test].reset_index(drop=True)
    temporal = pd.concat([temporal, test[test["y"] == 0]], ignore_index=True)

    counts["newest_year"] = int(newest) if pd.notna(newest) else -1
    for name, part in (("dev", dev), ("test", test), ("temporal", temporal)):
        counts[f"{name}_rows"] = len(part)
        counts[f"{name}_phishing"] = int(part["y"].sum())
        counts[f"{name}_groups"] = int(part["group"].nunique())
    return dev[OUT_COLUMNS], test[OUT_COLUMNS], temporal[OUT_COLUMNS], counts


def run(config_path: Path | None = None) -> dict[str, Any]:
    cfg = load_config(config_path or KINDS["email"].config)
    hashes = check_sources(cfg)
    frame, counts = build_frame(load_records(cfg))
    dev, test, temporal, split_counts = split_frame(frame, cfg["seed"], cfg["test_fraction"])
    out_dir = resolve(cfg["processed_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, part in (("dev", dev), ("test", test), ("temporal", temporal)):
        part.to_csv(out_dir / f"email_{name}.csv", index=False)
    report = {**counts, **split_counts, "source_sha256": hashes, "seed": cfg["seed"]}
    write_json(resolve(cfg["reports_dir"]) / "prepare_email.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the email splits.")
    parser.add_argument("kind", choices=["email"])
    parser.parse_args()
    report = run()
    for key, value in report.items():
        if key != "source_sha256":
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
