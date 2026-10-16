import json
import mailbox

import pytest
import sklearn
import yaml

from phishguard.core.email.features import FEATURE_NAMES
from phishguard.core.registry import load_model, sha256_file
from phishguard.training import evaluate, prepare_email, train
from synthetic import make_synthetic_emails

pytestmark = pytest.mark.slow


def write_corpora(raw_dir):
    """Lay synthetic mail out like the real corpora: mbox per year, SpamAssassin dirs, maildir."""
    (raw_dir / "nazario").mkdir(parents=True)
    boxes = {}
    counter = 0
    for _y, source, year, raw in make_synthetic_emails(n=60):
        counter += 1
        if source == "nazario":
            box = boxes.setdefault(
                year, mailbox.mbox(raw_dir / "nazario" / f"phishing-{year}.mbox")
            )
            box.add(raw)
        else:
            if source == "spamassassin":
                folder = raw_dir / "spamassassin" / ("easy_ham" if counter % 4 else "hard_ham")
            else:
                folder = raw_dir / "enron" / "maildir" / "user" / "inbox"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{counter:04d}.msg").write_bytes(raw)
    for box in boxes.values():
        box.flush()
        box.close()


@pytest.fixture
def cfg_path(tmp_path):
    write_corpora(tmp_path / "raw")
    cfg = {
        "raw_dir": str(tmp_path / "raw"),
        "sources": {},
        "enron_sample": None,
        "processed_dir": str(tmp_path / "processed"),
        "reports_dir": str(tmp_path / "reports"),
        "models_dir": str(tmp_path / "models"),
        "version": "vtest",
        "seed": 3,
        "test_fraction": 0.2,
        "n_folds": 3,
        "target_fpr": 0.01,
        "target_fpr_low": 0.10,
        "exclude_features": ["has_html"],
        "grids": {
            "lr_text": {"C": [1.0], "ngram_range": [[1, 2]], "max_features": [5000]},
            "rf_struct": {"n_estimators": [20], "min_samples_leaf": [1]},
        },
    }
    path = tmp_path / "email.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


def test_prepare_train_evaluate_end_to_end(cfg_path, tmp_path):
    report = prepare_email.run(cfg_path)
    assert report["newest_year"] == 2024
    assert report["dev_rows"] > 0 and report["test_rows"] > 0 and report["temporal_rows"] > 0

    manifest = train.run(cfg_path, kind="email")
    assert manifest["kind"] == "email"
    assert manifest["sklearn_version"] == sklearn.__version__
    assert manifest["primary"] in {"lr_text", "rf_struct"}
    for entry in manifest["models"].values():
        assert entry["dev_oof"]["fpr_at_t_high"] <= 0.01
        assert entry["t_low"] <= entry["t_high"]
        path = tmp_path / "models" / "email" / "vtest" / entry["file"]
        assert sha256_file(path) == entry["sha256"]
    assert manifest["models"]["rf_struct"]["feature_names"] == [
        n for n in FEATURE_NAMES if n != "has_html"
    ]
    load_model("email", "vtest", "lr_text", tmp_path / "models")

    payloads = evaluate.run_sets(cfg_path, kind="email")
    assert set(payloads) == {"locked", "temporal"}
    results = tmp_path / "reports" / "results"
    locked = json.loads((results / "email_locked_vtest.json").read_text())
    temporal = json.loads((results / "email_temporal_vtest.json").read_text())
    assert set(locked["results"]) == {"lr_text", "rf_struct", "heuristic_baseline"}
    assert "note" not in locked and "held-out ham" in temporal["note"]


def test_evaluate_refuses_to_reuse_any_test_set(cfg_path, tmp_path):
    prepare_email.run(cfg_path)
    train.run(cfg_path, kind="email")
    evaluate.run_sets(cfg_path, kind="email")
    (tmp_path / "reports" / "results" / "email_temporal_vtest.json").unlink()
    with pytest.raises(FileExistsError, match="--force"):
        evaluate.run_sets(cfg_path, kind="email")
    assert not (tmp_path / "reports" / "results" / "email_temporal_vtest.json").exists()
    evaluate.run_sets(cfg_path, force=True, kind="email")
    assert (tmp_path / "reports" / "results" / "email_temporal_vtest.json").exists()


def test_prepare_rejects_a_source_with_the_wrong_hash(cfg_path, tmp_path):
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["sources"] = {"nazario/phishing-2022.mbox": "0" * 64}
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    with pytest.raises(ValueError, match="sha256"):
        prepare_email.run(cfg_path)


def test_train_requires_prepare_first(cfg_path):
    with pytest.raises(FileNotFoundError, match="prepare"):
        train.run(cfg_path, kind="email")
