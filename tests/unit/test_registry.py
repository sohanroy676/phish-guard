import json

import joblib
import pytest
import sklearn

from phishguard.core.registry import ModelIntegrityError, load_manifest, load_model, sha256_file


@pytest.fixture
def models_root(tmp_path):
    vdir = tmp_path / "url" / "v1"
    vdir.mkdir(parents=True)
    joblib.dump({"hello": "world"}, vdir / "m.joblib")
    manifest = {
        "sklearn_version": sklearn.__version__,
        "models": {"m": {"file": "m.joblib", "sha256": sha256_file(vdir / "m.joblib")}},
    }
    (vdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_load_model_ok(models_root):
    assert load_model("url", "v1", "m", models_root) == {"hello": "world"}


def test_sha_mismatch_rejected(models_root):
    joblib.dump({"tampered": True}, models_root / "url" / "v1" / "m.joblib")
    with pytest.raises(ModelIntegrityError, match="SHA-256"):
        load_model("url", "v1", "m", models_root)


def test_sklearn_version_mismatch_rejected(models_root):
    path = models_root / "url" / "v1" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["sklearn_version"] = "0.0.1"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ModelIntegrityError, match="scikit-learn"):
        load_manifest("url", "v1", models_root)


@pytest.mark.parametrize("version", ["../v1", "..", "v1/../v1", "/etc", "a\\b", ""])
def test_unsafe_version_rejected(models_root, version):
    with pytest.raises(ModelIntegrityError):
        load_manifest("url", version, models_root)


def test_missing_manifest_and_missing_model_name(models_root):
    with pytest.raises(ModelIntegrityError):
        load_manifest("url", "v9", models_root)
    with pytest.raises(ModelIntegrityError, match="no model named"):
        load_model("url", "v1", "nope", models_root)


def test_missing_model_file_rejected(models_root):
    (models_root / "url" / "v1" / "m.joblib").unlink()
    with pytest.raises(ModelIntegrityError, match="missing"):
        load_model("url", "v1", "m", models_root)


def test_manifest_file_name_cannot_escape_directory(models_root):
    path = models_root / "url" / "v1" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["models"]["m"]["file"] = "../../outside.joblib"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ModelIntegrityError, match="Invalid model file"):
        load_model("url", "v1", "m", models_root)
