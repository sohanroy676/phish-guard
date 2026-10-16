"""Locked test evaluation -> reports/results/url_locked.json. The locked test is used once."""

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from phishguard.core.registry import load_manifest, load_model
from phishguard.core.url.features import FEATURE_NAMES
from phishguard.core.url.normalize import normalize_url
from phishguard.core.url.rules import run_rules
from phishguard.training.common import load_config, resolve, write_json
from phishguard.training.thresholds import rates_at
from phishguard.training.train import build_inputs

# Heuristic baseline: rule hits only. Any high-severity hit flags (score >= 10),
# any hit at all is the looser setting (score >= 1).
BASELINE_T_HIGH, BASELINE_T_LOW = 10.0, 1.0


def baseline_scores(urls: pd.Series) -> np.ndarray:
    scores = []
    for raw in urls:
        hits = run_rules(normalize_url(raw))
        scores.append(10 * sum(h.severity == "high" for h in hits) + len(hits))
    return np.array(scores, dtype=float)


def summarise(y: np.ndarray, scores: np.ndarray, t_high: float, t_low: float) -> dict[str, Any]:
    fpr_high, recall_high = rates_at(y, scores, t_high)
    fpr_low, recall_low = rates_at(y, scores, t_low)
    flagged = scores >= t_high
    return {
        "pr_auc": float(average_precision_score(y, scores)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "t_high": t_high,
        "t_low": t_low,
        "fpr_at_t_high": fpr_high,
        "recall_at_t_high": recall_high,
        "fpr_at_t_low": fpr_low,
        "recall_at_t_low": recall_low,
        "confusion_at_t_high": {
            "tp": int((flagged & (y == 1)).sum()),
            "fp": int((flagged & (y == 0)).sum()),
            "tn": int((~flagged & (y == 0)).sum()),
            "fn": int((~flagged & (y == 1)).sum()),
        },
    }


def run(config_path: Path | None = None, force: bool = False) -> dict[str, Any]:
    cfg = load_config(config_path) if config_path else load_config()
    # v1 keeps its original file name; later versions get their own locked result file.
    name = "url_locked.json" if cfg["version"] == "v1" else f"url_locked_{cfg['version']}.json"
    out_path = resolve(cfg["reports_dir"]) / "results" / name
    if out_path.exists() and not force:
        raise FileExistsError(
            f"{out_path} exists. The locked test is used once; pass --force to overwrite."
        )
    test_path = resolve(cfg["processed_dir"]) / "url_test.csv"
    if not test_path.is_file():
        raise FileNotFoundError(f"{test_path} not found. Run prepare first.")
    test = pd.read_csv(test_path)
    y = test["y"].to_numpy()
    models_dir = resolve(cfg["models_dir"])
    manifest = load_manifest("url", cfg["version"], models_dir)
    inputs = build_inputs(test["url"], list(range(len(FEATURE_NAMES))))

    results: dict[str, Any] = {}
    for name, entry in manifest["models"].items():
        model = load_model("url", cfg["version"], name, models_dir)
        data = inputs[entry["input"]]
        if entry["input"] == "features":
            data = data[:, [FEATURE_NAMES.index(n) for n in entry["feature_names"]]]
        scores = model.predict_proba(data)[:, 1]
        results[name] = summarise(y, scores, entry["t_high"], entry["t_low"])

    results["heuristic_baseline"] = summarise(
        y, baseline_scores(test["url"]), BASELINE_T_HIGH, BASELINE_T_LOW
    )
    base_pr = results["heuristic_baseline"]["pr_auc"]
    payload = {
        "model_version": cfg["version"],
        "data_sha256": manifest["data_sha256"],
        "n_test": len(test),
        "n_phishing": int(y.sum()),
        "results": results,
        "beats_baseline": {name: results[name]["pr_auc"] > base_pr for name in manifest["models"]},
    }
    write_json(out_path, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate on the locked URL test set.")
    parser.add_argument("kind", choices=["url"])
    parser.add_argument("--force", action="store_true", help="overwrite existing results")
    args = parser.parse_args()
    payload = run(force=args.force)
    for name, res in payload["results"].items():
        print(name, "pr_auc", round(res["pr_auc"], 4), "fpr@high", round(res["fpr_at_t_high"], 4))
    print("beats_baseline:", payload["beats_baseline"])


if __name__ == "__main__":
    main()
