"""Count which component drives the flags on modern automated mail. Measurement only.

    python -m phishguard.training.measure_flag_sources --config configs/email_v2.yaml

Same sample as `measure_link_policy` (unused v2 ham, at most 10 per sender domain), the deployed
configuration (ADR 0008 gate and ADR 0010 exemption on). Each message is scored once and then
re-decided with the text band, the link bands or both forced to Low, and with the gate off. A
flagged message (High or Suspicious) goes into exactly one bucket. Nothing is tuned.

Results go to `reports/results/email_flag_sources.json`: counts only, per `person_N`, never text,
subjects, senders, domains or file names. It is never overwritten.
"""

import argparse
import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from phishguard.core.email.bulk import bulk_info, link_discount
from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, ParsedEmail, parse_raw
from phishguard.core.email.rules import run_rules as run_email_rules
from phishguard.core.risk import HIGH, LOW, SUSPICIOUS, email_decision, higher, model_band
from phishguard.core.url.normalize import UnsupportedURL, normalize_url
from phishguard.training.common import REPO_ROOT, load_config, resolve, write_json
from phishguard.training.measure_ham import _rate, worst_link_band
from phishguard.training.measure_link_policy import pick_sample
from phishguard.training.prepare_email_v2 import (
    DEFAULT_CAP,
    load_holdout,
    modern_candidates,
    select_modern,
)

OUT_NAME = "email_flag_sources.json"
FLAGGED = (SUSPICIOUS, HIGH)
# Checked against email_adr10_benefit.json before anything is written.
EXPECTED_FLAGGED_ON = {"v1": 0.539, "v2": 0.398}
BUCKETS = ("rule", "text_only", "links_only", "either_alone", "interaction")
NOTE = (
    "Unused automated mail from six consenting mailboxes (ADR 0009 source). Senders overlap with "
    "the v2 training data, so this describes these mailboxes, not a population rate."
)


def link_profile(parsed: ParsedEmail, url_scorer, bulk) -> dict[str, Any]:
    """Distinct web links: how many, how many were set aside, and the worst model-only band.

    The model-only band ignores URL rules, so comparing it with the real link band shows whether
    a rule or the URL model raised the band.
    """
    seen: set[str] = set()
    counted = discounted = 0
    model_only = LOW
    for link in parsed.links:
        if link.href in seen:
            continue
        seen.add(link.href)
        try:
            url = normalize_url(link.href)
        except UnsupportedURL:
            continue
        if link_discount(url, bulk):
            discounted += 1
            continue
        counted += 1
        model_only = higher(
            model_only, model_band(url_scorer.score(url), url_scorer.t_high, url_scorer.t_low)
        )
    return {"counted": counted, "discounted": discounted, "model_only": model_only}


def bucket(deployed: str, no_text: str, no_links: str, rules_only: str) -> str | None:
    """Why a deployed band is flagged: which removal keeps the flag alive."""
    if deployed not in FLAGGED:
        return None
    if rules_only in FLAGGED:
        return "rule"
    if no_text in FLAGGED and no_links in FLAGGED:
        return "either_alone"
    if no_text in FLAGGED:
        return "links_only"
    if no_links in FLAGGED:
        return "text_only"
    return "interaction"


def score_one(raw: bytes, scorer, url_scorer) -> dict[str, Any] | None:
    try:
        parsed = parse_raw(raw)
    except (EmailTooLarge, NotAnEmail):
        return None
    hits = run_email_rules(parsed)
    text_band = model_band(scorer.score(parsed), scorer.t_high, scorer.t_low)
    bulk = bulk_info(parsed)
    link_band, hidden = worst_link_band(parsed, url_scorer, bulk=bulk)
    raw_link_band, _ = worst_link_band(parsed, url_scorer, skip_wrappers=False)
    headers = parsed.has_raw_headers

    def decide(text: str, links: str, b=bulk, hid=hidden) -> str:
        return email_decision(text, [links], hits, b, headers, hid).band

    deployed = decide(text_band, link_band)
    profile = link_profile(parsed, url_scorer, bulk)
    return {
        "deployed": deployed,
        "ungated": decide(text_band, raw_link_band, None, False),
        "bucket": bucket(
            deployed,
            decide(LOW, link_band),
            decide(text_band, LOW, bulk, False),
            decide(LOW, LOW, bulk, False),
        ),
        "text_band": text_band,
        "link_band": link_band,
        "link_model_only": profile["model_only"],
        "no_links": profile["counted"] == 0,
        "bulk": bulk.is_bulk,
        "aligned": bulk.aligned_domain is not None,
        "rule_ids": sorted({h.rule_id for h in hits}),
        "gated": deployed == "cant_assess" and bulk.is_bulk,
    }


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    flagged = [r for r in rows if r["deployed"] in FLAGGED]

    def share(pred, population=rows):
        return _rate(sum(1 for r in population if pred(r)), n)

    return {
        "n": n,
        "flagged": _rate(len(flagged), n),
        "buckets": {b: share(lambda r, b=b: r["bucket"] == b) for b in BUCKETS},
        "text_band": {
            b: share(lambda r, b=b: r["text_band"] == b) for b in (HIGH, SUSPICIOUS, LOW)
        },
        "worst_link_band": {
            b: share(lambda r, b=b: r["link_band"] == b) for b in (HIGH, SUSPICIOUS, LOW)
        },
        "flagged_by_link_model_alone": share(lambda r: r["link_model_only"] in FLAGGED, flagged),
        "flagged_with_no_counted_links": share(lambda r: r["no_links"], flagged),
        "bulk": share(lambda r: r["bulk"]),
        "aligned_dmarc_pass": share(lambda r: r["aligned"]),
        "gated_to_cant_assess": share(lambda r: r["gated"]),
        "flagged_ungated": share(lambda r: r["ungated"] in FLAGGED),
        "lost_flag_to_gate": share(
            lambda r: r["ungated"] in FLAGGED and r["deployed"] not in FLAGGED
        ),
        "flagged_with_rule": share(lambda r: bool(r["rule_ids"]), flagged),
        "rule_ids_on_flagged": dict(Counter(i for r in flagged for i in r["rule_ids"])),
    }


def measure(sample, scorer, url_scorer) -> tuple[dict[str, list], Counter]:
    by_person: dict[str, list] = {}
    skipped: Counter = Counter()
    for alias, raw in sample:
        row = score_one(raw, scorer, url_scorer)
        if row is None:
            skipped["unparseable"] += 1
        else:
            by_person.setdefault(alias, []).append(row)
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
        overall = summarise(rows)
        expected = EXPECTED_FLAGGED_ON.get(version)
        if expected is not None and abs(overall["flagged"]["rate"] - expected) > 0.002:
            raise RuntimeError(
                f"{version}: deployed flagged {overall['flagged']['rate']:.3f} does not match "
                f"the ADR 0010 result {expected}. Nothing written."
            )
        results[version] = {
            "email_model": {"version": scorer.version, "t_high": scorer.t_high},
            "skipped": dict(skipped),
            "overall": overall,
            "by_person": {p: summarise(g) for p, g in sorted(by_person.items())},
        }
    write_json(
        out,
        {
            "note": NOTE,
            "sample": {"messages": len(sample), "sender_domains": senders},
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
