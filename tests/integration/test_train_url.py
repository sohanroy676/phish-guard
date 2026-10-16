import json

import pytest
import sklearn
import yaml

from phishguard.core.registry import load_model, sha256_file
from phishguard.training import evaluate, prepare_url, train
from synthetic import make_synthetic_raw

pytestmark = pytest.mark.slow


@pytest.fixture
def cfg_path(tmp_path):
    raw = make_synthetic_raw(n_domains=80)
    raw[["URL", "label"]].to_csv(tmp_path / "raw.csv", index=False)
    cfg = {
        "raw_path": str(tmp_path / "raw.csv"),
        "raw_sha256": None,
        "processed_dir": str(tmp_path / "processed"),
        "reports_dir": str(tmp_path / "reports"),
        "models_dir": str(tmp_path / "models"),
        "version": "vtest",
        "seed": 3,
        "test_fraction": 0.2,
        "n_folds": 3,
        "target_fpr": 0.01,
        "target_recall_low": 0.95,
        "exclude_features": ["is_https"],
        "grids": {
            "lr_char": {"C": [1.0], "ngram_range": [[2, 3]], "max_features": [5000]},
            "rf_hand": {"n_estimators": [20], "min_samples_leaf": [1]},
        },
    }
    path = tmp_path / "url.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


def test_prepare_train_evaluate_end_to_end(cfg_path, tmp_path):
    prepare_url.run(cfg_path)
    manifest = train.run(cfg_path)

    assert manifest["sklearn_version"] == sklearn.__version__
    assert manifest["exclude_features"] == ["is_https"]
    for entry in manifest["models"].values():
        assert entry["dev_oof"]["fpr_at_t_high"] <= 0.01
        assert entry["t_low"] <= entry["t_high"]
        path = tmp_path / "models" / "url" / "vtest" / entry["file"]
        assert entry["sha256"] == sha256_file(path)
    assert "is_https" not in manifest["models"]["rf_hand"]["feature_names"]
    assert len(manifest["models"]["rf_hand"]["feature_names"]) == 29
    on_disk = json.loads((tmp_path / "models/url/vtest/manifest.json").read_text(encoding="utf-8"))
    assert on_disk["primary"] in manifest["models"]
    load_model("url", "vtest", "lr_char", tmp_path / "models")

    payload = evaluate.run(cfg_path)
    assert set(payload["results"]) == {"lr_char", "rf_hand", "heuristic_baseline"}
    for res in payload["results"].values():
        assert 0.0 <= res["fpr_at_t_high"] <= 1.0
        assert {"pr_auc", "recall_at_t_high", "confusion_at_t_high"} <= set(res)
    # Synthetic phishing URLs are trivially caught by the keyword rule, so only require a tie
    # here; the real locked test must beat the baseline strictly.
    base_pr = payload["results"]["heuristic_baseline"]["pr_auc"]
    assert set(payload["beats_baseline"]) == {"lr_char", "rf_hand"}
    assert all(payload["results"][m]["pr_auc"] >= base_pr for m in payload["beats_baseline"])
    assert (tmp_path / "reports" / "results" / "url_locked.json").is_file()


def test_evaluate_refuses_to_overwrite_locked_results(cfg_path):
    prepare_url.run(cfg_path)
    train.run(cfg_path)
    evaluate.run(cfg_path)
    with pytest.raises(FileExistsError, match="--force"):
        evaluate.run(cfg_path)
    evaluate.run(cfg_path, force=True)


def test_prepare_rejects_dataset_with_wrong_hash(cfg_path):
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    cfg["raw_sha256"] = "0" * 64
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    with pytest.raises(ValueError, match="raw_sha256"):
        prepare_url.run(cfg_path)


def test_train_requires_prepare_first(cfg_path):
    with pytest.raises(FileNotFoundError, match="prepare"):
        train.run(cfg_path)
