"""Prepare the v2 email splits (ADR 0009): modern legitimate mail vs Nazario phishing.

    python -m phishguard.training.prepare_email_v2 --config configs/email_v2.yaml

Ham is automated mail (Gmail Promotions, Updates, Social, Purchases) from consenting mailboxes,
converted to `.eml` under `<modern_dir>/<person_N>/`. Phishing is the Nazario corpus with its
temporal hold-out, exactly as v1. The parsing, language filter, exact-duplicate removal, MinHash
grouping and splitting are the v1 functions; this module only adds the ham-side filters.

Outputs `data/processed/email_v2_{dev,test,temporal}.csv` and `reports/prepare_email_v2.json`.
The report holds counts only, per `person_N`: never text, subjects, addresses or names.
"""

import argparse
import hashlib
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from phishguard.core.email.features import model_text, sender_context
from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, ParsedEmail, parse_raw
from phishguard.core.url.normalize import get_extractor
from phishguard.training.common import load_config, resolve, write_json
from phishguard.training.minhash import group_ids
from phishguard.training.prepare_email import (
    MIN_WORDS,
    Record,
    build_frame,
    check_sources,
    iter_nazario,
    looks_english,
    split_frame,
)

ALLOWED_CATEGORIES = frozenset({"promotions", "updates", "social", "purchases"})
FORBIDDEN_LABELS = frozenset({"spam", "trash", "sent", "chat", "chats"})
DEFAULT_CAP = 10


def gmail_labels(parsed: ParsedEmail) -> set[str]:
    raw = next((v for k, v in parsed.headers if k == "x-gmail-labels"), "")
    return {t.strip().lower().replace("category ", "") for t in raw.split(",") if t.strip()}


def message_id(parsed: ParsedEmail) -> str:
    return next((v.strip() for k, v in parsed.headers if k == "message-id"), "")


def sender_domain(parsed: ParsedEmail) -> str | None:
    host = (parsed.from_addr or "").rsplit("@", 1)[-1].strip().lower()
    if not host:
        return None
    return get_extractor()(host).top_domain_under_public_suffix or None


def load_holdout(directory: Path, skip: str) -> tuple[set[str], list[str]]:
    """Message-IDs and plain model texts of the held-out sample. Never used for training."""
    ids: set[str] = set()
    texts: list[str] = []
    for path in sorted(directory.rglob("*.eml")):
        if skip in path.relative_to(directory).parts:
            continue
        try:
            parsed = parse_raw(path.read_bytes())
        except (EmailTooLarge, NotAnEmail):
            continue
        if mid := message_id(parsed):
            ids.add(mid)
        texts.append(model_text(parsed))
    return ids, texts


def modern_candidates(directory: Path) -> Iterator[tuple[str, bytes]]:
    """(person alias, raw bytes) for every `.eml` under `<directory>/<alias>/`, in sorted order."""
    for person in sorted(p for p in directory.iterdir() if p.is_dir()):
        for path in sorted(person.rglob("*.eml")):
            yield person.name, path.read_bytes()


def select_modern(
    candidates: Iterator[tuple[str, bytes]],
    held_ids: set[str],
    held_texts: list[str],
    seed: int,
    cap: int = DEFAULT_CAP,
    leftover: list[tuple[str, bytes, str]] | None = None,
) -> tuple[list[Record], dict[str, Counter]]:
    """Apply the ham-side filters. Returns the kept records and per-person drop counts.

    `leftover`, when given, collects (alias, raw, domain) of messages that passed every filter and
    were dropped only by the sender cap, in the same seeded order. They were never trained on.
    """
    stats: dict[str, Counter] = {}
    pool: list[tuple[str, bytes, str, str, str]] = []  # alias, raw, text, domain, key
    seen_ids: set[str] = set()
    for alias, raw in candidates:
        c = stats.setdefault(alias, Counter())
        c["seen"] += 1
        try:
            parsed = parse_raw(raw)
        except (EmailTooLarge, NotAnEmail):
            c["unparseable"] += 1
            continue
        labels = gmail_labels(parsed)
        if labels & FORBIDDEN_LABELS:
            c["spam_trash_sent_chat"] += 1
        elif not labels & ALLOWED_CATEGORIES:
            c["no_allowed_category"] += 1
        elif (mid := message_id(parsed)) and mid in held_ids:
            c["held_out_message_id"] += 1
        elif mid and mid in seen_ids:
            c["duplicate_message_id"] += 1
        elif not (domain := sender_domain(parsed)):
            c["no_sender_domain"] += 1
        else:
            text = model_text(parsed)
            if len(text.split()) < MIN_WORDS:
                c["too_short"] += 1
            elif not looks_english(text):
                c["non_english"] += 1
            else:
                if mid:
                    seen_ids.add(mid)
                pool.append((alias, raw, text, domain, hashlib.sha256(raw).hexdigest()))

    # Same templates as the held-out sample would make its measurement optimistic.
    groups = group_ids([p[2] for p in pool] + held_texts, seed)
    held_groups = set(groups[len(pool) :])
    kept: list[tuple[str, bytes, str, str]] = []
    for (alias, raw, _text, domain, key), group in zip(pool, groups, strict=False):
        if group in held_groups:
            stats[alias]["near_duplicate_of_held_out"] += 1
        else:
            kept.append((alias, raw, domain, key))

    # Cap per sender domain, picking by a seeded hash so no date or folder order decides.
    per_domain: Counter = Counter()
    records: list[Record] = []
    for alias, raw, domain, _key in sorted(
        kept, key=lambda k: hashlib.sha256(f"{seed}:{k[3]}".encode()).hexdigest()
    ):
        if per_domain[domain] >= cap:
            stats[alias]["sender_cap"] += 1
            if leftover is not None:
                leftover.append((alias, raw, domain))
            continue
        per_domain[domain] += 1
        stats[alias]["selected"] += 1
        records.append(Record(0, alias, None, raw, domain))
    return records, stats


def run(config_path: Path) -> dict[str, Any]:
    cfg = load_config(config_path)
    hashes = check_sources(cfg)
    held_ids, held_texts = load_holdout(resolve(cfg["holdout_dir"]), skip=cfg["holdout_skip"])
    modern, stats = select_modern(
        modern_candidates(resolve(cfg["modern_dir"])),
        held_ids,
        held_texts,
        cfg["seed"],
        cfg.get("sender_cap", DEFAULT_CAP),
    )
    records = [*iter_nazario(resolve(cfg["raw_dir"]) / "nazario"), *modern]
    frame, counts = build_frame(records, mask_for=sender_context)
    dev, test, temporal, split_counts = split_frame(frame, cfg["seed"], cfg["test_fraction"])
    out_dir = resolve(cfg["processed_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, part in (("dev", dev), ("test", test), ("temporal", temporal)):
        part.to_csv(out_dir / f"email_v2_{name}.csv", index=False)
    report = {
        **counts,
        **split_counts,
        "modern_filters_per_person": {a: dict(c) for a, c in sorted(stats.items())},
        "modern_senders_selected": len({r.domain for r in modern}),
        "held_out_messages": len(held_texts),
        "source_sha256": hashes,
        "seed": cfg["seed"],
    }
    write_json(resolve(cfg["reports_dir"]) / "prepare_email_v2.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the email v2 splits.")
    parser.add_argument("--config", type=Path, required=True)
    report = run(parser.parse_args().config)
    for key, value in report.items():
        if key != "source_sha256":
            print(f"{key}: {value}")


if __name__ == "__main__":
    main()
