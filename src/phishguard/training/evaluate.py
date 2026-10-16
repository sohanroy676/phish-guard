"""Locked (and temporal) test evaluation -> reports/results/<kind>_<set>.json. Used once."""

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from phishguard.core.registry import load_manifest, load_model
from phishguard.training.common import load_config, resolve, write_json
from phishguard.training.kinds import KINDS, Kind
from phishguard.training.thresholds import rates_at

# Heuristic baseline: rule hits only. Any high-severity hit flags (score >= 10),
# any hit at all is the looser setting (score >= 1).
BASELINE_T_HIGH, BASELINE_T_LOW = 10.0, 1.0


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


def _result_path(cfg: dict[str, Any], kind: str, set_name: str) -> Path:
    # URL v1 keeps its original file name; every other version gets its own result file.
    suffix = "" if kind == "url" and cfg["version"] == "v1" else f"_{cfg['version']}"
    return resolve(cfg["reports_dir"]) / "results" / f"{kind}_{set_name}{suffix}.json"


def _evaluate_set(
    spec: Kind, cfg: dict[str, Any], set_name: str, csv_name: str, manifest: dict[str, Any]
) -> dict[str, Any]:
    test_path = resolve(cfg["processed_dir"]) / csv_name
    if not test_path.is_file():
        raise FileNotFoundError(f"{test_path} not found. Run prepare first.")
    test = pd.read_csv(test_path)
    y = test["y"].to_numpy()
    models_dir = resolve(cfg["models_dir"])
    inputs = spec.build_inputs(test, list(range(len(spec.feature_names))))

    results: dict[str, Any] = {}
    for name, entry in manifest["models"].items():
        model = load_model(spec.name, cfg["version"], name, models_dir)
        data = inputs[entry["input"]]
        if entry["input"] == "features":
            data = data[:, [spec.feature_names.index(n) for n in entry["feature_names"]]]
        scores = model.predict_proba(data)[:, 1]
        results[name] = summarise(y, scores, entry["t_high"], entry["t_low"])

    results["heuristic_baseline"] = summarise(
        y, spec.baseline(test), BASELINE_T_HIGH, BASELINE_T_LOW
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
    if set_name in spec.notes:
        payload["note"] = spec.notes[set_name]
    return payload


def run_sets(
    config_path: Path | None = None, force: bool = False, kind: str = "url"
) -> dict[str, dict[str, Any]]:
    spec = KINDS[kind]
    cfg = load_config(config_path or spec.config)
    paths = {name: _result_path(cfg, kind, name) for name in spec.test_sets}
    # Check every output first, so a refused run never leaves some sets spent and others not.
    existing = [p for p in paths.values() if p.exists()]
    if existing and not force:
        raise FileExistsError(
            f"{existing[0]} exists. The locked test is used once; pass --force to overwrite."
        )
    manifest = load_manifest(kind, cfg["version"], resolve(cfg["models_dir"]))
    payloads = {
        name: _evaluate_set(spec, cfg, name, csv_name, manifest)
        for name, csv_name in spec.test_sets.items()
    }
    for name, payload in payloads.items():
        write_json(paths[name], payload)
    return payloads


def run(config_path: Path | None = None, force: bool = False, kind: str = "url") -> dict[str, Any]:
    """Evaluate every test set of the kind and return the locked-test payload."""
    return run_sets(config_path, force, kind)["locked"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate on the locked test sets.")
    parser.add_argument("kind", choices=list(KINDS))
    parser.add_argument("--force", action="store_true", help="overwrite existing results")
    args = parser.parse_args()
    for set_name, payload in run_sets(force=args.force, kind=args.kind).items():
        print(f"[{set_name}] n={payload['n_test']} phishing={payload['n_phishing']}")
        for name, res in payload["results"].items():
            print(
                f"  {name} pr_auc {res['pr_auc']:.4f} fpr@high {res['fpr_at_t_high']:.4f} "
                f"recall@high {res['recall_at_t_high']:.4f}"
            )
        print("  beats_baseline:", payload["beats_baseline"])


if __name__ == "__main__":
    main()
