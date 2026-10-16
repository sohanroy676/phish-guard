"""Grouped CV, threshold selection, final fit -> models/url/<version>/."""

import argparse
import itertools
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedGroupKFold

from phishguard.core.registry import sha256_file
from phishguard.core.url.features import (
    FEATURE_NAMES,
    feature_matrix,
    host_text,
    url_text,
)
from phishguard.training.common import load_config, resolve, write_json
from phishguard.training.models import FACTORIES, MODEL_INPUTS, selected_features
from phishguard.training.thresholds import pick_t_high, pick_t_low, rates_at


def build_inputs(urls: pd.Series, cols: list[int]) -> dict[str, Any]:
    """Model inputs for a list of raw URLs, built only with core feature code."""
    return {
        "url_text": np.array([url_text(u) for u in urls], dtype=object),
        "host_text": np.array([host_text(u) for u in urls], dtype=object),
        "features": feature_matrix(urls)[:, cols],
    }


def _grid(grid: dict[str, list]) -> list[dict[str, Any]]:
    keys = list(grid)
    return [dict(zip(keys, combo, strict=True)) for combo in itertools.product(*grid.values())]


def _oof_scores(name, params, seed, data, y, folds) -> np.ndarray:
    oof = np.zeros(len(y))
    for train_idx, val_idx in folds:
        model = FACTORIES[name](params, seed).fit(data[train_idx], y[train_idx])
        oof[val_idx] = model.predict_proba(data[val_idx])[:, 1]
    return oof


def train_model(name, cfg, inputs, y, folds) -> tuple[Any, dict[str, Any]]:
    """Pick params by grouped-CV PR-AUC, set thresholds on OOF scores, fit on all dev."""
    data = inputs[MODEL_INPUTS[name]]
    best: tuple[float, dict[str, Any], np.ndarray] | None = None
    for params in _grid(cfg["grids"][name]):
        oof = _oof_scores(name, params, cfg["seed"], data, y, folds)
        pr_auc = float(average_precision_score(y, oof))
        if best is None or pr_auc > best[0]:
            best = (pr_auc, params, oof)
    pr_auc, params, oof = best
    t_high = pick_t_high(y, oof, cfg["target_fpr"])
    t_low = pick_t_low(y, oof, cfg["target_fpr_low"], t_high)
    fpr_high, recall_high = rates_at(y, oof, t_high)
    fpr_low, recall_low = rates_at(y, oof, t_low)
    entry = {
        "input": MODEL_INPUTS[name],
        "params": params,
        "t_high": t_high,
        "t_low": t_low,
        "dev_oof": {
            "pr_auc": pr_auc,
            "fpr_at_t_high": fpr_high,
            "recall_at_t_high": recall_high,
            "fpr_at_t_low": fpr_low,
            "recall_at_t_low": recall_low,
        },
    }
    final = FACTORIES[name](params, cfg["seed"]).fit(data, y)
    return final, entry


def run(config_path: Path | None = None) -> dict[str, Any]:
    cfg = load_config(config_path) if config_path else load_config()
    dev_path = resolve(cfg["processed_dir"]) / "url_dev.csv"
    if not dev_path.is_file():
        raise FileNotFoundError(f"{dev_path} not found. Run prepare first.")
    dev = pd.read_csv(dev_path)
    y = dev["y"].to_numpy()
    cols = selected_features(cfg["exclude_features"])
    inputs = build_inputs(dev["url"], cols)
    splitter = StratifiedGroupKFold(n_splits=cfg["n_folds"], shuffle=True, random_state=cfg["seed"])
    folds = list(splitter.split(dev, y, groups=dev["group"]))

    out_dir = resolve(cfg["models_dir"]) / "url" / cfg["version"]
    out_dir.mkdir(parents=True, exist_ok=True)
    models: dict[str, Any] = {}
    for name in FACTORIES:
        final, entry = train_model(name, cfg, inputs, y, folds)
        path = out_dir / f"{name}.joblib"
        joblib.dump(final, path, compress=3)
        entry["file"] = path.name
        entry["sha256"] = sha256_file(path)
        if entry["input"] == "features":
            entry["feature_names"] = [FEATURE_NAMES[i] for i in cols]
        models[name] = entry

    manifest = {
        "kind": "url",
        "version": cfg["version"],
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "seed": cfg["seed"],
        "data_sha256": sha256_file(dev_path),
        "target_fpr": cfg["target_fpr"],
        "target_fpr_low": cfg["target_fpr_low"],
        "exclude_features": cfg["exclude_features"],
        "dev_rows": len(dev),
        "primary": max(models, key=lambda m: models[m]["dev_oof"]["pr_auc"]),
        "models": models,
    }
    write_json(out_dir / "manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the URL models.")
    parser.add_argument("kind", choices=["url"])
    parser.parse_args()
    manifest = run()
    for name, entry in manifest["models"].items():
        print(name, entry["dev_oof"], "t_high", entry["t_high"], "t_low", entry["t_low"])


if __name__ == "__main__":
    main()
