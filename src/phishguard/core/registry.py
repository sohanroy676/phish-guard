"""Load models from models/<kind>/<version>/ after checking manifest, hash and sklearn version."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import joblib
import sklearn

MODELS_DIR = Path(__file__).resolve().parents[3] / "models"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ModelIntegrityError(RuntimeError):
    """The model files are missing, altered or built for a different scikit-learn."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version_dir(kind: str, version: str, root: Path) -> Path:
    for label, value in (("kind", kind), ("version", version)):
        if not _SAFE_NAME.match(value) or ".." in value:
            raise ModelIntegrityError(f"Invalid model {label}: {value!r}")
    return root / kind / version


def load_manifest(kind: str, version: str, root: Path = MODELS_DIR) -> dict[str, Any]:
    path = _version_dir(kind, version, root) / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelIntegrityError(f"Cannot read manifest for {kind}/{version}.") from exc
    if manifest.get("sklearn_version") != sklearn.__version__:
        raise ModelIntegrityError(
            f"{kind}/{version} was built with scikit-learn {manifest.get('sklearn_version')}, "
            f"but {sklearn.__version__} is installed."
        )
    return manifest


def load_model(kind: str, version: str, name: str, root: Path = MODELS_DIR) -> Any:
    """Return the fitted estimator `name`, only after its SHA-256 matches the manifest."""
    manifest = load_manifest(kind, version, root)
    entry = manifest.get("models", {}).get(name)
    if entry is None:
        raise ModelIntegrityError(f"{kind}/{version} has no model named {name!r}.")
    if not _SAFE_NAME.match(entry["file"]):
        raise ModelIntegrityError(f"Invalid model file name: {entry['file']!r}")
    path = _version_dir(kind, version, root) / entry["file"]
    if not path.is_file():
        raise ModelIntegrityError(f"Model file missing: {entry['file']}")
    if sha256_file(path) != entry["sha256"]:
        raise ModelIntegrityError(f"SHA-256 mismatch for {kind}/{version}/{entry['file']}.")
    return joblib.load(path)
