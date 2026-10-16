"""Audit the email corpora -> reports/audit_email.md.

Looks for artefacts a model could learn instead of phishing: features that separate the two ham
corpora from each other (they are both "legitimate", so a gap is a source effect), and tokens that
identify one corpus.
"""

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import roc_auc_score

from phishguard.core.email.features import FEATURE_NAMES
from phishguard.training.common import load_config, resolve
from phishguard.training.kinds import KINDS
from phishguard.training.prepare_email import build_frame, check_sources, load_records

SOURCE_GAP_WARN = 0.30  # |AUC - 0.5| between the two ham corpora
NEAR_PERFECT = 0.95  # a single feature this good deserves a look
TOP_TOKENS = 20
MIN_TOKEN_SHARE = 0.02


def _auc(values: pd.Series, positive: pd.Series) -> float | None:
    if positive.nunique() < 2:
        return None
    return float(roc_auc_score(positive, values))


def feature_aucs(frame: pd.DataFrame) -> dict[str, dict[str, float | None]]:
    ham = frame[frame["y"] == 0]
    two_ham = ham[ham["source"].isin(["enron", "spamassassin"])]
    return {
        name: {
            "phish_vs_ham": _auc(frame[name], frame["y"] == 1),
            "enron_vs_spamassassin": _auc(two_ham[name], two_ham["source"] == "enron"),
        }
        for name in FEATURE_NAMES
    }


def distinctive_tokens(frame: pd.DataFrame) -> dict[str, list[tuple[str, float]]]:
    """Tokens found in a much larger share of one source's mail than of any other source's."""
    vec = CountVectorizer(binary=True, min_df=5, max_features=50_000)
    matrix = vec.fit_transform(frame["text"])
    vocab = np.array(vec.get_feature_names_out())
    sources = sorted(frame["source"].unique())
    share = {
        s: np.asarray(matrix[(frame["source"] == s).to_numpy()].mean(axis=0)).ravel()
        for s in sources
    }
    out: dict[str, list[tuple[str, float]]] = {}
    for s in sources:
        others = np.max([share[o] for o in sources if o != s] or [np.zeros(len(vocab))], axis=0)
        gap = share[s] - others
        order = [i for i in np.argsort(-gap) if share[s][i] >= MIN_TOKEN_SHARE][:TOP_TOKENS]
        out[s] = [(str(vocab[i]), float(share[s][i])) for i in order]
    return out


def compute_audit(frame: pd.DataFrame, counts: dict[str, Any]) -> dict[str, Any]:
    aucs = feature_aucs(frame)
    source_artefacts = [
        n
        for n, a in aucs.items()
        if a["enron_vs_spamassassin"] is not None
        and abs(a["enron_vs_spamassassin"] - 0.5) > SOURCE_GAP_WARN
    ]
    near_perfect = [
        n
        for n, a in aucs.items()
        if a["phish_vs_ham"] is not None
        and max(a["phish_vs_ham"], 1 - a["phish_vs_ham"]) > NEAR_PERFECT
    ]
    years = frame[frame["y"] == 1]["year"].value_counts().sort_index()
    return {
        "per_source": counts["per_source"],
        "kept_by_year": {int(k): int(v) for k, v in years.items()},
        "feature_aucs": aucs,
        "source_artefact_features": source_artefacts,
        "near_perfect_features": near_perfect,
        "tokens": distinctive_tokens(frame),
    }


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_markdown(stats: dict[str, Any], hashes: dict[str, str]) -> str:
    lines = ["# Email data audit", "", "## Messages per source", ""]
    lines += ["| source | seen | kept | unparseable | too large | too short | exact duplicates |"]
    lines += ["|---|---|---|---|---|---|---|"]
    for source, s in sorted(stats["per_source"].items()):
        lines.append(
            f"| {source} | {s.get('seen', 0)} | {s.get('kept', 0)} | {s.get('unparseable', 0)} | "
            f"{s.get('too_large', 0)} | {s.get('too_short', 0)} | {s.get('exact_duplicate', 0)} |"
        )
    lines += ["", "## Kept phishing per Nazario year", ""]
    lines += [f"- {year}: {n}" for year, n in stats["kept_by_year"].items()]
    lines += [
        "",
        "## Single-feature ROC-AUC",
        "",
        "| feature | phishing vs ham | Enron vs SpamAssassin |",
    ]
    lines += ["|---|---|---|"]
    for name, a in stats["feature_aucs"].items():
        lines.append(f"| {name} | {_fmt(a['phish_vs_ham'])} | {_fmt(a['enron_vs_spamassassin'])} |")
    artefacts = stats["source_artefact_features"]
    lines += ["", "## Flags", ""]
    lines.append(
        "Features that separate the two ham corpora (source artefacts; add to `exclude_features` "
        f"or move to rules): {', '.join(artefacts) if artefacts else 'none'}"
    )
    perfect = stats["near_perfect_features"]
    lines.append(
        f"Features with a near-perfect phishing vs ham AUC (> {NEAR_PERFECT}): "
        f"{', '.join(perfect) if perfect else 'none'}"
    )
    lines += ["", "## Most source-specific tokens", ""]
    lines.append(
        "Tokens like corpus names, list footers or dates belong in `artefact_stoplist.txt`."
    )
    for source, tokens in stats["tokens"].items():
        lines += ["", f"### {source}", ""]
        lines.append(", ".join(f"{t} ({share:.0%})" for t, share in tokens) or "none")
    lines += ["", "## Source files", ""]
    lines += [f"- `{rel}`: `{sha}`" for rel, sha in sorted(hashes.items())]
    lines.append("")
    return "\n".join(lines)


def run(config_path: Path | None = None) -> Path:
    cfg = load_config(config_path or KINDS["email"].config)
    hashes = check_sources(cfg)
    frame, counts = build_frame(load_records(cfg))
    out = resolve(cfg["reports_dir"]) / "audit_email.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(compute_audit(frame, counts), hashes), encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the email corpora.")
    parser.add_argument("kind", choices=["email"])
    parser.parse_args()
    print(f"Wrote {run()}")


if __name__ == "__main__":
    main()
