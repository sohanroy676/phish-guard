"""Clean, dedupe, group and split the URL data -> data/processed/url_{dev,test}.csv."""

import argparse
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from phishguard.core.registry import sha256_file
from phishguard.training.common import (
    load_config,
    normalize_frame,
    read_phiusiil,
    resolve,
    write_json,
)

OUT_COLUMNS = ["url", "y", "group"]


def prepare_frame(
    raw: pd.DataFrame, seed: int, test_fraction: float
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Return (dev, test, counts). No registered domain appears in both dev and test."""
    frame, unsupported = normalize_frame(raw)
    counts = {"raw_rows": len(raw), "unsupported": unsupported}

    # The n-gram model sees only the registered domain (`group`, ADR 0006): one row per
    # domain and label, so a domain with many hosts or paths does not outweigh the others.
    before = len(frame)
    frame = frame.drop_duplicates(subset=["y", "group"]).reset_index(drop=True)
    counts["duplicates_dropped"] = before - len(frame)

    # The same domain with both labels would give the model identical input with opposite labels.
    conflicting = frame.groupby("group")["y"].transform("nunique") > 1
    counts["conflicting_dropped"] = int(conflicting.sum())
    frame = frame[~conflicting].reset_index(drop=True)

    splitter = StratifiedGroupKFold(
        n_splits=round(1 / test_fraction), shuffle=True, random_state=seed
    )
    _, test_idx = next(splitter.split(frame, frame["y"], groups=frame["group"]))
    is_test = frame.index.isin(test_idx)
    dev, test = frame[~is_test][OUT_COLUMNS], frame[is_test][OUT_COLUMNS]
    for name, part in (("dev", dev), ("test", test)):
        counts[f"{name}_rows"] = len(part)
        counts[f"{name}_phishing"] = int(part["y"].sum())
        counts[f"{name}_domains"] = int(part["group"].nunique())
    return dev.reset_index(drop=True), test.reset_index(drop=True), counts


def run(config_path: Path | None = None) -> dict[str, Any]:
    cfg = load_config(config_path) if config_path else load_config()
    raw_path = resolve(cfg["raw_path"])
    if not raw_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {raw_path}. Download PhiUSIIL into data/raw/.")
    sha = sha256_file(raw_path)
    if cfg.get("raw_sha256") and cfg["raw_sha256"] != sha:
        raise ValueError("The dataset file does not match raw_sha256 in configs/url.yaml.")
    dev, test, counts = prepare_frame(read_phiusiil(raw_path), cfg["seed"], cfg["test_fraction"])
    out_dir = resolve(cfg["processed_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    dev.to_csv(out_dir / "url_dev.csv", index=False)
    test.to_csv(out_dir / "url_test.csv", index=False)
    counts_out: dict[str, Any] = {**counts, "raw_sha256": sha, "seed": cfg["seed"]}
    write_json(resolve(cfg["reports_dir"]) / "prepare_url.json", counts_out)
    return counts_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the URL splits.")
    parser.add_argument("kind", choices=["url"])
    parser.parse_args()
    for key, value in run().items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
