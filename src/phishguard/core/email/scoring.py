"""Score a parsed email with the primary text model from the registry."""

from dataclasses import dataclass
from typing import Any

from phishguard.core.email.features import model_text
from phishguard.core.email.parse import ParsedEmail
from phishguard.core.registry import MODELS_DIR, ModelIntegrityError, load_manifest, load_model


@dataclass(frozen=True)
class EmailScorer:
    model: Any
    name: str
    version: str
    t_high: float
    t_low: float

    def text(self, parsed: ParsedEmail) -> str:
        """The string the model reads: masked subject and body, no headers or link targets."""
        return model_text(parsed)

    def score(self, parsed: ParsedEmail) -> float:
        """Phishing probability in 0..1 from that string only."""
        return float(self.model.predict_proba([self.text(parsed)])[0, 1])


def load_email_scorer(version: str, root=MODELS_DIR) -> EmailScorer:
    manifest = load_manifest("email", version, root)
    name = manifest.get("primary", "")
    entry = manifest.get("models", {}).get(name)
    if entry is None or entry.get("input") != "text":
        raise ModelIntegrityError(f"email/{version} primary model {name!r} is not a text model.")
    model = load_model("email", version, name, root)
    return EmailScorer(model, name, version, float(entry["t_high"]), float(entry["t_low"]))
