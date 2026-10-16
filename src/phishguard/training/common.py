"""Helpers shared by the offline training scripts. Never imported by the app."""

import json
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from phishguard.core.url.features import domain_text, url_text
from phishguard.core.url.normalize import NormalizedURL, UnsupportedURL, normalize_url

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_URL_CONFIG = REPO_ROOT / "configs" / "url.yaml"


def load_config(path: Path = DEFAULT_URL_CONFIG) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve(path: str | Path, base: Path = REPO_ROOT) -> Path:
    p = Path(path)
    return p if p.is_absolute() else base / p


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def group_key(u: NormalizedURL) -> str:
    """Registered domain, or the host for IPs and names with no public suffix."""
    return domain_text(u)


def read_phiusiil(path: Path) -> pd.DataFrame:
    """Read the URL and label columns and map the labels so that y = 1 means phishing.

    PhiUSIIL labels 1 = legitimate and 0 = phishing, so y = 1 - label.
    """
    df = pd.read_csv(path, usecols=lambda c: c in {"URL", "label"})
    missing = {"URL", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"{path.name} is missing column(s): {', '.join(sorted(missing))}")
    if not set(df["label"].dropna().unique()) <= {0, 1} or df["label"].isna().any():
        raise ValueError("The label column must contain only 0 and 1.")
    out = df[["URL", "label"]].copy()
    out["y"] = 1 - out["label"].astype(int)
    return out


def normalize_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Normalise every URL. Returns the rows that parsed and how many were unsupported.

    Adds scheme, path, text (host+path+query) and group columns.
    """
    rows = []
    unsupported = 0
    for raw, y in zip(df["URL"], df["y"], strict=True):
        try:
            u = normalize_url(raw)
        except UnsupportedURL:
            unsupported += 1
            continue
        rows.append((raw, int(y), u.scheme, u.path, url_text(u), group_key(u)))
    cols = ["url", "y", "scheme", "path", "text", "group"]
    return pd.DataFrame(rows, columns=cols), unsupported
