"""Pipeline factories. Inputs come only from phishguard.core.url (url_text, feature_matrix)."""

from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from phishguard.core.url.features import FEATURE_NAMES

# model name -> what the model reads: "url_text" strings or the "features" matrix
MODEL_INPUTS = {"lr_char": "url_text", "rf_hand": "features"}


def selected_features(exclude: list[str]) -> list[int]:
    unknown = set(exclude) - set(FEATURE_NAMES)
    if unknown:
        raise ValueError(f"Unknown feature(s) in exclude_features: {sorted(unknown)}")
    return [i for i, name in enumerate(FEATURE_NAMES) if name not in exclude]


def lr_char(params: dict[str, Any], seed: int) -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
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


def rf_hand(params: dict[str, Any], seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=params["n_estimators"],
        min_samples_leaf=params["min_samples_leaf"],
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed,
    )


FACTORIES = {"lr_char": lr_char, "rf_hand": rf_hand}
