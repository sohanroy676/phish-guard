"""What differs between the URL and email pipelines, so train.py and evaluate.py stay shared."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from phishguard.core.email.features import FEATURE_NAMES as EMAIL_FEATURE_NAMES
from phishguard.core.url.features import (
    FEATURE_NAMES as URL_FEATURE_NAMES,
)
from phishguard.core.url.features import (
    domain_text,
    feature_matrix,
    host_text,
    url_text,
)
from phishguard.core.url.normalize import normalize_url
from phishguard.core.url.rules import run_rules
from phishguard.training.common import REPO_ROOT

TEMPORAL_HAM_NOTE = (
    "Ham mail has no dates, so the temporal set reuses the held-out locked-test ham. Its FPR is a "
    "held-out ham estimate, not a temporal measurement. Only the phishing side is temporal."
)


def url_inputs(frame: pd.DataFrame, cols: list[int]) -> dict[str, Any]:
    """Model inputs for a frame with a raw `url` column, built only with core feature code."""
    urls = frame["url"]
    return {
        "url_text": np.array([url_text(u) for u in urls], dtype=object),
        "host_text": np.array([host_text(u) for u in urls], dtype=object),
        "domain_text": np.array([domain_text(u) for u in urls], dtype=object),
        "features": feature_matrix(urls)[:, cols],
    }


def url_baseline(frame: pd.DataFrame) -> np.ndarray:
    scores = []
    for raw in frame["url"]:
        hits = run_rules(normalize_url(raw))
        scores.append(10 * sum(h.severity == "high" for h in hits) + len(hits))
    return np.array(scores, dtype=float)


def email_inputs(frame: pd.DataFrame, cols: list[int]) -> dict[str, Any]:
    """Email rows are prepared once (prepare_email.py runs core/email); training only reads them."""
    matrix = frame[list(EMAIL_FEATURE_NAMES)].to_numpy(dtype=float)
    return {"text": frame["text"].fillna("").to_numpy(dtype=object), "features": matrix[:, cols]}


def email_baseline(frame: pd.DataFrame) -> np.ndarray:
    return frame["rule_score"].to_numpy(dtype=float)  # body rules only, see prepare_email


@dataclass(frozen=True)
class Kind:
    name: str
    config: Any
    feature_names: tuple[str, ...]
    build_inputs: Callable[[pd.DataFrame, list[int]], dict[str, Any]]
    baseline: Callable[[pd.DataFrame], np.ndarray]
    # result name -> processed csv; each is evaluated once and written to its own results file
    test_sets: dict[str, str]
    notes: dict[str, str] = field(default_factory=dict)


KINDS = {
    "url": Kind(
        "url",
        REPO_ROOT / "configs" / "url.yaml",
        URL_FEATURE_NAMES,
        url_inputs,
        url_baseline,
        {"locked": "url_test.csv"},
    ),
    "email": Kind(
        "email",
        REPO_ROOT / "configs" / "email.yaml",
        EMAIL_FEATURE_NAMES,
        email_inputs,
        email_baseline,
        {"locked": "email_test.csv", "temporal": "email_temporal.csv"},
        {"temporal": TEMPORAL_HAM_NOTE},
    ),
}
