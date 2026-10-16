"""Model reasons for the n-gram logistic regression: coefficient x TF-IDF value."""

from typing import Any

TOP_REASONS = 4


def lr_reasons(pipeline: Any, host: str, limit: int = TOP_REASONS) -> list[str]:
    """Return the host fragments that push the score toward phishing, strongest first.

    Fragments contained in an already chosen, stronger fragment are skipped.
    """
    tfidf, lr = pipeline.named_steps["tfidf"], pipeline.named_steps["lr"]
    row = tfidf.transform([host])
    names = tfidf.get_feature_names_out()
    coef = lr.coef_[0]
    pairs = sorted(
        ((float(v * coef[i]), str(names[i])) for i, v in zip(row.indices, row.data, strict=True)),
        reverse=True,
    )
    chosen: list[str] = []
    for weight, fragment in pairs:
        if weight <= 0 or len(chosen) == limit:
            break
        if fragment.strip() and not any(fragment in c for c in chosen):
            chosen.append(fragment)
    return [f'The host contains "{frag}", a pattern common in phishing links.' for frag in chosen]
