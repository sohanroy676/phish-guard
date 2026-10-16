"""Measure the email model on a folder of legitimate mail. Measurement only, never training.

    python -m phishguard.training.measure_ham --dir data/raw/email_modern/own --label own

Reads `.eml` files (one subfolder per category, e.g. newsletter, receipt, notification), scores
them with the same path the app uses and writes counts and rates to
`reports/results/email_modern_ham_<label>.json`. No message text, subject, sender, address or
file name is written. An existing result file is never overwritten.
"""

import argparse
import math
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, ParsedEmail, parse_raw
from phishguard.core.email.rules import run_rules as run_email_rules
from phishguard.core.risk import HIGH, SUSPICIOUS, assess, combine_email, higher, model_band
from phishguard.core.url.normalize import UnsupportedURL, normalize_url
from phishguard.core.url.rules import run_rules as run_url_rules
from phishguard.training.common import REPO_ROOT, resolve, write_json

BANDS = ("low", "cant_assess", "suspicious", "high")
UNSORTED = "uncategorised"
NOTE = (
    "Measurement on a small, hand-supplied, non-random sample of legitimate mail. It is not a "
    "population false-positive rate and was not used for training or tuning."
)


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """95% Wilson interval for k/n; [0, 1] when n is 0."""
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [max(0.0, centre - half), min(1.0, centre + half)]


def worst_link_band(parsed: ParsedEmail, url_scorer) -> str:
    """Worst URL band among the distinct web links, as the app shows it."""
    bands = ["low"]
    seen: set[str] = set()
    for link in parsed.links:
        if link.href in seen:
            continue
        seen.add(link.href)
        try:
            url = normalize_url(link.href)
        except UnsupportedURL:
            continue
        risk = assess(
            url_scorer.score(url), url_scorer.t_high, url_scorer.t_low, run_url_rules(url)
        )
        bands.append(risk.band)
    return higher(*bands)


def score_one(parsed: ParsedEmail, scorer, url_scorer) -> dict[str, Any]:
    hits = run_email_rules(parsed)
    score = scorer.score(parsed)
    text_band = model_band(score, scorer.t_high, scorer.t_low)
    link_band = worst_link_band(parsed, url_scorer) if url_scorer else "low"
    return {
        "score": score,
        "text_band": text_band,
        "link_band": link_band,
        "final_band": combine_email(text_band, [link_band], hits),
        "rule_ids": sorted({h.rule_id for h in hits}),
        "raw_headers": parsed.has_raw_headers,
    }


def _rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n if n else None, "ci95": wilson(k, n)}


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    scores = np.array([r["score"] for r in rows]) if rows else np.array([])
    fired = Counter(rid for r in rows for rid in r["rule_ids"])
    flagged = sum(r["final_band"] in (SUSPICIOUS, HIGH) for r in rows)
    text_flagged = sum(r["text_band"] in (SUSPICIOUS, HIGH) for r in rows)
    return {
        "n": n,
        "final_band_counts": {b: sum(r["final_band"] == b for r in rows) for b in BANDS},
        "text_band_counts": {b: sum(r["text_band"] == b for r in rows) for b in BANDS},
        "link_band_counts": {b: sum(r["link_band"] == b for r in rows) for b in BANDS},
        "fpr_final_high": _rate(sum(r["final_band"] == HIGH for r in rows), n),
        "fpr_final_high_or_suspicious": _rate(flagged, n),
        "fpr_text_high": _rate(sum(r["text_band"] == HIGH for r in rows), n),
        "fpr_text_high_or_suspicious": _rate(text_flagged, n),
        "rule_hits": dict(sorted(fired.items())),
        "with_raw_headers": sum(r["raw_headers"] for r in rows),
        "text_score": (
            {"median": float(np.median(scores)), "p90": float(np.quantile(scores, 0.9))}
            if n
            else None
        ),
    }


def collect(directory: Path, scorer, url_scorer) -> tuple[dict[str, list[dict]], Counter]:
    """Score every `.eml` under `directory`, grouped by first-level subfolder."""
    by_category: dict[str, list[dict]] = {}
    skipped: Counter = Counter()
    for path in sorted(directory.rglob("*.eml")):
        rel = path.relative_to(directory).parts
        category = rel[0] if len(rel) > 1 else UNSORTED
        try:
            parsed = parse_raw(path.read_bytes())
        except OSError:
            skipped["unreadable"] += 1
        except EmailTooLarge:
            skipped["too_large"] += 1
        except NotAnEmail:
            skipped["not_an_email"] += 1
        else:
            by_category.setdefault(category, []).append(score_one(parsed, scorer, url_scorer))
    return by_category, skipped


def measure(directory: Path, label: str, scorer, url_scorer, out_dir: Path) -> Path:
    out = out_dir / f"email_modern_ham_{label}.json"
    if out.exists():
        raise FileExistsError(f"{out} exists. Use a new --label; results are not overwritten.")
    if not directory.is_dir():
        raise FileNotFoundError(f"{directory} is not a folder.")
    by_category, skipped = collect(directory, scorer, url_scorer)
    rows = [r for group in by_category.values() for r in group]
    if not rows:
        raise ValueError(f"No readable .eml files under {directory}.")
    write_json(
        out,
        {
            "label": label,
            "note": NOTE,
            "email_model": {
                "version": scorer.version,
                "name": scorer.name,
                "t_high": scorer.t_high,
                "t_low": scorer.t_low,
            },
            "url_model": (
                {"version": url_scorer.version, "name": url_scorer.name} if url_scorer else None
            ),
            "skipped": dict(skipped),
            "overall": summarise(rows),
            "by_category": {c: summarise(g) for c, g in sorted(by_category.items())},
        },
    )
    return out


def main() -> None:
    from phishguard.core.email.scoring import load_email_scorer
    from phishguard.core.registry import MODELS_DIR
    from phishguard.core.url.scoring import load_url_scorer

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, help="folder of .eml files, one subfolder per category")
    ap.add_argument("--label", required=True, help="short name for the result file")
    ap.add_argument("--email-version", default="v1")
    ap.add_argument("--url-version", default="v2")
    args = ap.parse_args()
    if not args.label.replace("-", "").replace("_", "").isalnum():
        ap.error("--label may only contain letters, digits, - and _")

    scorer = load_email_scorer(args.email_version, MODELS_DIR)
    url_scorer = load_url_scorer(args.url_version, MODELS_DIR)
    out = measure(
        resolve(args.dir), args.label, scorer, url_scorer, REPO_ROOT / "reports" / "results"
    )
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
