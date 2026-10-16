"""Score a normalised URL with the primary model from the registry."""

from dataclasses import dataclass
from typing import Any

from phishguard.core.registry import MODELS_DIR, ModelIntegrityError, load_manifest, load_model
from phishguard.core.url.features import host_text
from phishguard.core.url.normalize import NormalizedURL


@dataclass(frozen=True)
class UrlScorer:
    model: Any
    name: str
    version: str
    t_high: float
    t_low: float

    def score(self, url: NormalizedURL) -> float:
        """Phishing probability in 0..1 from the host only (ADR 0004)."""
        return float(self.model.predict_proba([host_text(url)])[0, 1])


def load_url_scorer(version: str, root=MODELS_DIR) -> UrlScorer:
    manifest = load_manifest("url", version, root)
    name = manifest.get("primary", "")
    entry = manifest.get("models", {}).get(name)
    if entry is None or entry.get("input") != "host_text":
        raise ModelIntegrityError(f"url/{version} primary model {name!r} is not a host_text model.")
    model = load_model("url", version, name, root)
    return UrlScorer(model, name, version, float(entry["t_high"]), float(entry["t_low"]))
