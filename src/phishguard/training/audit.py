"""Data audit: class counts, duplicates and scheme leakage -> reports/audit_url.md."""

import argparse
from pathlib import Path
from typing import Any

import pandas as pd

from phishguard.core.registry import sha256_file
from phishguard.training.common import (
    load_config,
    normalize_frame,
    read_phiusiil,
    resolve,
)

SCHEME_GAP_WARN = 0.20


def _class_stats(frame: pd.DataFrame, y: int) -> dict[str, Any]:
    part = frame[frame["y"] == y]
    n = len(part)
    return {
        "rows": n,
        "https_rate": float((part["scheme"] == "https").mean()) if n else 0.0,
        "empty_path_rate": float(part["path"].isin(["", "/"]).mean()) if n else 0.0,
        "domains": int(part["group"].nunique()),
    }


def compute_audit(raw: pd.DataFrame) -> dict[str, Any]:
    """`raw` comes from read_phiusiil (columns URL, label, y)."""
    frame, unsupported = normalize_frame(raw)
    dup_key = frame["scheme"] + "|" + frame["text"]
    labels_per_text = frame.groupby("text")["y"].nunique()
    stats: dict[str, Any] = {
        "rows": len(raw),
        "label_1_rows": int((raw["label"] == 1).sum()),
        "label_0_rows": int((raw["label"] == 0).sum()),
        "phishing": int(raw["y"].sum()),
        "legitimate": int((raw["y"] == 0).sum()),
        "exact_duplicate_urls": int(raw["URL"].duplicated().sum()),
        "unsupported_urls": unsupported,
        "normalised_duplicates": int(dup_key.duplicated().sum()),
        "conflicting_texts": int((labels_per_text > 1).sum()),
        "distinct_domains": int(frame["group"].nunique()),
        "phishing_stats": _class_stats(frame, 1),
        "legitimate_stats": _class_stats(frame, 0),
    }
    gap = abs(stats["phishing_stats"]["https_rate"] - stats["legitimate_stats"]["https_rate"])
    stats["https_gap"] = gap
    warnings = []
    if stats["phishing"] > stats["legitimate"]:
        warnings.append(
            "Phishing rows outnumber legitimate rows. PhiUSIIL has about 100k phishing and "
            "135k legitimate, so the label mapping may be flipped (label 1 = legitimate)."
        )
    if gap > SCHEME_GAP_WARN:
        warnings.append(
            f"The https rate differs by {gap:.0%} between classes. `is_https` would act as a "
            "shortcut feature: set `exclude_features: [is_https]` in configs/url.yaml and let "
            "the scheme be handled by rules instead."
        )
    stats["warnings"] = warnings
    return stats


def render_markdown(stats: dict[str, Any], sha256: str, source: str) -> str:
    p, leg = stats["phishing_stats"], stats["legitimate_stats"]
    lines = [
        "# URL data audit",
        "",
        f"Source: `{source}`  ",
        f"SHA-256: `{sha256}`",
        "",
        "## Warnings",
        *(f"- {w}" for w in stats["warnings"] or ["None."]),
        "",
        "## Class counts (y = 1 is phishing; PhiUSIIL label 1 is legitimate)",
        "| | rows |",
        "|---|---|",
        f"| Total | {stats['rows']} |",
        f"| Phishing (label 0) | {stats['phishing']} |",
        f"| Legitimate (label 1) | {stats['legitimate']} |",
        "",
        "## Cleaning",
        f"- Exact duplicate URLs: {stats['exact_duplicate_urls']}",
        f"- Unsupported (not http/https or unreadable): {stats['unsupported_urls']}",
        f"- Duplicates after normalisation (scheme + host/path/query): "
        f"{stats['normalised_duplicates']}",
        f"- Host/path/query strings labelled both ways: {stats['conflicting_texts']}",
        f"- Distinct registered domains: {stats['distinct_domains']}",
        "",
        "## Per class (normalisable URLs)",
        "| | rows | https rate | empty-path rate | domains |",
        "|---|---|---|---|---|",
        f"| Phishing | {p['rows']} | {p['https_rate']:.1%} | {p['empty_path_rate']:.1%} "
        f"| {p['domains']} |",
        f"| Legitimate | {leg['rows']} | {leg['https_rate']:.1%} | "
        f"{leg['empty_path_rate']:.1%} | {leg['domains']} |",
        "",
        f"https-rate gap: {stats['https_gap']:.1%}",
        "",
    ]
    return "\n".join(lines)


def run(config_path: Path | None = None) -> Path:
    cfg = load_config(config_path) if config_path else load_config()
    raw_path = resolve(cfg["raw_path"])
    if not raw_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {raw_path}. Download PhiUSIIL into data/raw/.")
    sha = sha256_file(raw_path)
    stats = compute_audit(read_phiusiil(raw_path))
    out = resolve(cfg["reports_dir"]) / "audit_url.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(stats, sha, str(cfg["raw_path"])), encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the url or email data.")
    parser.add_argument("kind", choices=["url", "email"])
    args = parser.parse_args()
    if args.kind == "email":
        from phishguard.training.audit_email import run as run_email

        print(f"Wrote {run_email()}")
    else:
        print(f"Wrote {run()}")


if __name__ == "__main__":
    main()
