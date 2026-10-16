"""Pipeline factories. Inputs come only from phishguard.core (url and email features)."""

from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from phishguard.core.url.features import FEATURE_NAMES

# model name -> what the model reads: a text input or the "features" matrix
MODEL_INPUTS = {
    "lr_char": "domain_text",
    "rf_hand": "features",
    "lr_text": "text",
    "rf_struct": "features",
}


def selected_features(exclude: list[str], names: tuple[str, ...] = FEATURE_NAMES) -> list[int]:
    unknown = set(exclude) - set(names)
    if unknown:
        raise ValueError(f"Unknown feature(s) in exclude_features: {sorted(unknown)}")
    return [i for i, name in enumerate(names) if name not in exclude]


def _tfidf_lr(analyzer: str, params: dict[str, Any], seed: int) -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer=analyzer,
                    ngram_range=tuple(params["ngram_range"]),
                    max_features=params["max_features"],
                    sublinear_tf=True,
                    min_df=2,
                    lowercase=True,
                ),
            ),
            (
                "lr",
                LogisticRegression(
                    C=params["C"],
                    class_weight="balanced",
                    solver="liblinear",
                    random_state=seed,
                ),
            ),
        ]
    )


def lr_char(params: dict[str, Any], seed: int) -> Pipeline:
    return _tfidf_lr("char", params, seed)


def lr_text(params: dict[str, Any], seed: int) -> Pipeline:
    return _tfidf_lr("word", params, seed)


def rf_hand(params: dict[str, Any], seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=params["n_estimators"],
        min_samples_leaf=params["min_samples_leaf"],
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed,
    )


FACTORIES = {"lr_char": lr_char, "rf_hand": rf_hand, "lr_text": lr_text, "rf_struct": rf_hand}
