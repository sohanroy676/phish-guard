"""Threshold selection on out-of-fold scores. A URL is flagged when score >= threshold."""

import math

import numpy as np


def _split(y: np.ndarray, scores: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    if y.shape != scores.shape:
        raise ValueError("y and scores must have the same length.")
    return scores[y == 0], scores[y == 1]


def rates_at(y: np.ndarray, scores: np.ndarray, threshold: float) -> tuple[float, float]:
    """Return (false positive rate, recall) when flagging score >= threshold."""
    neg, pos = _split(y, scores)
    fpr = float((neg >= threshold).mean()) if len(neg) else 0.0
    recall = float((pos >= threshold).mean()) if len(pos) else 0.0
    return fpr, recall


def pick_t_high(y: np.ndarray, scores: np.ndarray, target_fpr: float) -> float:
    """Lowest threshold whose FPR is <= target_fpr.

    If the target cannot be met by flagging anything, the result is above every score.
    """
    neg, _ = _split(y, scores)
    if len(neg) == 0:
        raise ValueError("Need legitimate (y=0) samples to choose t_high.")
    allowed = math.floor(target_fpr * len(neg) + 1e-9)
    if allowed >= len(neg):
        return float(neg.min())
    ordered = np.sort(neg)[::-1]
    boundary = ordered[allowed]  # the first negative that may NOT be flagged
    higher = ordered[ordered > boundary]
    if len(higher) == 0:
        return float(np.nextafter(boundary, np.inf))
    return float((boundary + higher.min()) / 2)


def pick_t_low(y: np.ndarray, scores: np.ndarray, target_recall: float, t_high: float) -> float:
    """Highest threshold that still catches `target_recall` of phishing, capped at t_high."""
    _, pos = _split(y, scores)
    if len(pos) == 0:
        raise ValueError("Need phishing (y=1) samples to choose t_low.")
    needed = max(1, math.ceil(target_recall * len(pos) - 1e-9))
    t_low = float(np.sort(pos)[::-1][needed - 1])
    return min(t_low, t_high)
