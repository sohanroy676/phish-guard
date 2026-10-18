"""Measure what the bulk-mail gate costs in phishing recall. Measurement only, never training.

    python -m phishguard.training.measure_phish --dir data/raw/email_phishing_pot --label pot

Reads `.eml` files, scores each one with the gate (ADR 0008) and without it (the pre-gate
decision: no bulk markers, link wrappers scored like any link) and with the ADR 0010 link
policy (sender-owned links left out), and writes counts and rates to
`reports/results/email_phish_<label>.json`. No message text, subject, sender, address or file
name is written. An existing result file is never overwritten. Never run on the locked or
temporal evaluation sets.
"""

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from phishguard.core.email.bulk import bulk_info
from phishguard.core.email.parse import EmailTooLarge, NotAnEmail, ParsedEmail, parse_raw
from phishguard.core.email.rules import run_rules as run_email_rules
from phishguard.core.risk import HIGH, SUSPICIOUS, email_decision, model_band
from phishguard.training.common import REPO_ROOT, resolve, write_json
from phishguard.training.measure_ham import BANDS, _rate, worst_link_band

NOTE = (
    "Measurement on a public sample of phishing mail (phishing_pot, CC BY-NC 4.0). It is not a "
    "population recall and was not used for training or tuning."
)


def score_one(parsed: ParsedEmail, scorer, url_scorer) -> dict[str, Any]:
    hits = run_email_rules(parsed)
    text_band = model_band(scorer.score(parsed), scorer.t_high, scorer.t_low)
    bulk = bulk_info(parsed)
    gated_link, hidden = worst_link_band(parsed, url_scorer) if url_scorer else ("low", False)
    plain_link, _ = worst_link_band(parsed, url_scorer, False) if url_scorer else ("low", False)
    gated = email_decision(text_band, [gated_link], hits, bulk, parsed.has_raw_headers, hidden)
    ungated = email_decision(text_band, [plain_link], hits)
    policy_link, policy_hidden = (
        worst_link_band(parsed, url_scorer, bulk=bulk) if url_scorer else ("low", False)
    )
    policy = email_decision(
        text_band, [policy_link], hits, bulk, parsed.has_raw_headers, policy_hidden
    )
    return {
        "text_band": text_band,
        "gated_band": gated.band,
        "policy_band": policy.band,
        "ungated_band": ungated.band,
        "bulk_mail": bulk.is_bulk,
        "raw_headers": parsed.has_raw_headers,
    }


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)

    def block(key: str) -> dict[str, Any]:
        flagged = sum(r[key] in (SUSPICIOUS, HIGH) for r in rows)
        return {
            "band_counts": {b: sum(r[key] == b for r in rows) for b in BANDS},
            "high": _rate(sum(r[key] == HIGH for r in rows), n),
            "high_or_suspicious": _rate(flagged, n),
            "cant_assess": _rate(sum(r[key] == "cant_assess" for r in rows), n),
            "low": _rate(sum(r[key] == "low" for r in rows), n),
        }

    return {
        "n": n,
        "gated": block("gated_band"),
        "ungated": block("ungated_band"),
        "text_only": block("text_band"),
        "changed_by_gate": _rate(sum(r["gated_band"] != r["ungated_band"] for r in rows), n),
        "lost_flag": _rate(
            sum(
                r["ungated_band"] in (SUSPICIOUS, HIGH)
                and r["gated_band"] not in (SUSPICIOUS, HIGH)
                for r in rows
            ),
            n,
        ),
        "policy": block("policy_band"),
        "changed_by_link_policy": _rate(sum(r["policy_band"] != r["gated_band"] for r in rows), n),
        "lost_flag_to_link_policy": _rate(
            sum(
                r["gated_band"] in (SUSPICIOUS, HIGH) and r["policy_band"] not in (SUSPICIOUS, HIGH)
                for r in rows
            ),
            n,
        ),
        "bulk_mail": sum(r["bulk_mail"] for r in rows),
        "with_raw_headers": sum(r["raw_headers"] for r in rows),
    }


def collect(directory: Path, scorer, url_scorer) -> tuple[list[dict], Counter]:
    rows: list[dict] = []
    skipped: Counter = Counter()
    for path in sorted(directory.rglob("*.eml")):
        try:
            parsed = parse_raw(path.read_bytes())
        except OSError:
            skipped["unreadable"] += 1
        except EmailTooLarge:
            skipped["too_large"] += 1
        except NotAnEmail:
            skipped["not_an_email"] += 1
        else:
            rows.append(score_one(parsed, scorer, url_scorer))
    return rows, skipped


def measure(directory: Path, label: str, scorer, url_scorer, out_dir: Path) -> Path:
    out = out_dir / f"email_phish_{label}.json"
    if out.exists():
        raise FileExistsError(f"{out} exists. Use a new --label; results are not overwritten.")
    if not directory.is_dir():
        raise FileNotFoundError(f"{directory} is not a folder.")
    rows, skipped = collect(directory, scorer, url_scorer)
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
        },
    )
    return out


def main() -> None:
    from phishguard.core.email.scoring import load_email_scorer
    from phishguard.core.registry import MODELS_DIR
    from phishguard.core.url.scoring import load_url_scorer

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", required=True, help="folder of phishing .eml files")
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
