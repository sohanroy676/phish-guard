"""Measure the benefit of the ADR 0010 link exemption on unused v2 ham. Measurement only.

    python -m phishguard.training.measure_link_policy --config configs/email_v2.yaml

The sample is automated mail from the v2 mailboxes that passed every ham filter and was dropped
only by the per-sender cap, so it was never trained on and never scored (and is not near-identical
to the 123 held-out messages). At most `SAMPLE_CAP` messages per sender domain are used.

Each message gets the final band twice with the same model and the ADR 0008 gate on: with the
sender-owned link exemption off and on. Results go to `reports/results/email_adr10_benefit.json`:
counts only, per `person_N`, never text, subjects, senders or file names. It is never overwritten.
"""

import argparse
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from phishguard.core.email.bulk import bulk_info
from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, parse_raw
from phishguard.core.email.rules import run_rules as run_email_rules
from phishguard.core.risk import HIGH, SUSPICIOUS, email_decision, model_band
from phishguard.training.common import REPO_ROOT, load_config, resolve, write_json
from phishguard.training.measure_ham import _rate, worst_link_band
from phishguard.training.prepare_email_v2 import (
    DEFAULT_CAP,
    load_holdout,
    modern_candidates,
    select_modern,
)

SAMPLE_CAP = 10
OUT_NAME = "email_adr10_benefit.json"
FLAGGED = (SUSPICIOUS, HIGH)
# Written into ADR 0010 before the single run. Accepted only if the drop in the flagged share is
# at least 5 points and the 95% Wilson interval of the drop stays above zero.
BAR_POINTS = 0.05
NOTE = (
    "Unused automated mail from six consenting mailboxes (ADR 0009 source). Senders overlap with "
    "the v2 training data, so this describes these mailboxes, not a population rate."
)


def pick_sample(leftover: list[tuple[str, bytes, str]], cap: int = SAMPLE_CAP):
    """First `cap` messages per sender domain, in the order they arrive (a seeded hash order)."""
    per_domain: Counter = Counter()
    sample = []
    for alias, raw, domain in leftover:
        if per_domain[domain] < cap:
            per_domain[domain] += 1
            sample.append((alias, raw))
    return sample, len(per_domain)


def score_arms(raw: bytes, scorer, url_scorer) -> dict[str, Any] | None:
    """Final band with the exemption off and on, or None when the message cannot be parsed."""
    try:
        parsed = parse_raw(raw)
    except (EmailTooLarge, NotAnEmail):
        return None
    hits = run_email_rules(parsed)
    text_band = model_band(scorer.score(parsed), scorer.t_high, scorer.t_low)
    bulk = bulk_info(parsed)
    bands = {}
    for arm, arm_bulk in (("off", None), ("on", bulk)):
        link_band, hidden = worst_link_band(parsed, url_scorer, bulk=arm_bulk)
        bands[arm] = email_decision(
            text_band, [link_band], hits, bulk, parsed.has_raw_headers, hidden
        ).band
    return bands


def summarise(rows: list[dict[str, str]]) -> dict[str, Any]:
    n = len(rows)
    flagged_off = sum(r["off"] in FLAGGED for r in rows)
    flagged_on = sum(r["on"] in FLAGGED for r in rows)
    lost = sum(r["off"] in FLAGGED and r["on"] not in FLAGGED for r in rows)
    gained = sum(r["off"] not in FLAGGED and r["on"] in FLAGGED for r in rows)
    drop = _rate(lost, n)
    return {
        "n": n,
        "flagged_off": _rate(flagged_off, n),
        "flagged_on": _rate(flagged_on, n),
        "lost_flag": drop,
        "gained_flag": _rate(gained, n),
        "band_changed": _rate(sum(r["off"] != r["on"] for r in rows), n),
        "drop_points": (flagged_off - flagged_on) / n if n else None,
        "bar_met": bool(n and (flagged_off - flagged_on) / n >= BAR_POINTS and drop["ci95"][0] > 0),
    }


def measure(sample, scorer, url_scorer) -> tuple[dict[str, list], Counter]:
    by_person: dict[str, list] = {}
    skipped: Counter = Counter()
    for alias, raw in sample:
        bands = score_arms(raw, scorer, url_scorer)
        if bands is None:
            skipped["unparseable"] += 1
        else:
            by_person.setdefault(alias, []).append(bands)
    return by_person, skipped


def run(config_path: Path, out_dir: Path, versions: tuple[str, ...]) -> Path:
    from phishguard.core.email.scoring import load_email_scorer
    from phishguard.core.registry import MODELS_DIR
    from phishguard.core.url.scoring import load_url_scorer

    out = out_dir / OUT_NAME
    if out.exists():
        raise FileExistsError(f"{out} exists. This measurement runs once and is not overwritten.")
    cfg = load_config(config_path)
    held_ids, held_texts = load_holdout(resolve(cfg["holdout_dir"]), skip=cfg["holdout_skip"])
    leftover: list[tuple[str, bytes, str]] = []
    selected, _ = select_modern(
        modern_candidates(resolve(cfg["modern_dir"])),
        held_ids,
        held_texts,
        cfg["seed"],
        cfg.get("sender_cap", DEFAULT_CAP),
        leftover,
    )
    sample, senders = pick_sample(leftover)
    if not sample:
        raise ValueError("No unused messages left after the filters.")
    selected_keys = {hashlib.sha256(r.raw).hexdigest() for r in selected}
    if any(hashlib.sha256(raw).hexdigest() in selected_keys for _, raw in sample):
        raise RuntimeError("Sample overlaps the training selection.")
    url_scorer = load_url_scorer("v2", MODELS_DIR)
    results = {}
    for version in versions:
        scorer = load_email_scorer(version, MODELS_DIR)
        by_person, skipped = measure(sample, scorer, url_scorer)
        rows = [r for group in by_person.values() for r in group]
        results[version] = {
            "email_model": {"version": scorer.version, "t_high": scorer.t_high},
            "skipped": dict(skipped),
            "overall": summarise(rows),
            "by_person": {p: summarise(g) for p, g in sorted(by_person.items())},
        }
    write_json(
        out,
        {
            "note": NOTE,
            "bar_points": BAR_POINTS,
            "sample": {"messages": len(sample), "sender_domains": senders, "cap": SAMPLE_CAP},
            "results": results,
        },
    )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--email-versions", nargs="+", default=["v1", "v2"])
    args = ap.parse_args()
    out = run(args.config, REPO_ROOT / "reports" / "results", tuple(args.email_versions))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
