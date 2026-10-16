import numpy as np
import pytest

from phishguard.training.thresholds import pick_t_high, pick_t_low, rates_at


def _data(seed=0, n=2000):
    rng = np.random.default_rng(seed)
    y = np.r_[np.zeros(n), np.ones(n)].astype(int)
    scores = np.r_[rng.beta(2, 6, n), rng.beta(6, 2, n)]
    return y, scores


def test_t_high_respects_target_fpr():
    y, s = _data()
    t = pick_t_high(y, s, 0.01)
    assert rates_at(y, s, t)[0] <= 0.01


def test_t_high_is_not_needlessly_strict():
    y, s = _data()
    t = pick_t_high(y, s, 0.01)
    assert rates_at(y, s, t)[0] >= 0.005  # close to the target, not 0


def test_t_high_with_tied_scores_never_exceeds_target():
    y = np.array([0] * 100 + [1] * 10)
    s = np.array([0.5] * 100 + [0.9] * 10)
    t = pick_t_high(y, s, 0.01)
    assert rates_at(y, s, t)[0] <= 0.01
    assert rates_at(y, s, t)[1] == 1.0


def test_t_high_all_same_scores_flags_nothing():
    y = np.array([0, 0, 1, 1] * 50)
    s = np.full(200, 0.3)
    t = pick_t_high(y, s, 0.01)
    assert rates_at(y, s, t) == (0.0, 0.0)


def test_t_high_small_negative_set_cannot_flag_any_negative():
    y = np.array([0] * 10 + [1] * 10)
    s = np.r_[np.linspace(0.1, 0.9, 10), np.linspace(0.5, 1.0, 10)]
    assert rates_at(y, s, pick_t_high(y, s, 0.01))[0] == 0.0


def test_t_high_requires_negatives():
    with pytest.raises(ValueError):
        pick_t_high(np.ones(5, dtype=int), np.linspace(0, 1, 5), 0.01)


def test_t_low_keeps_recall_and_stays_below_t_high():
    y, s = _data()
    t_high = pick_t_high(y, s, 0.01)
    t_low = pick_t_low(y, s, 0.95, t_high)
    assert t_low <= t_high
    assert rates_at(y, s, t_low)[1] >= 0.95 or t_low == t_high


def test_t_low_clamped_when_recall_target_is_easy():
    y = np.array([0] * 100 + [1] * 100)
    s = np.r_[np.linspace(0, 0.4, 100), np.linspace(0.8, 1, 100)]
    t_high = pick_t_high(y, s, 0.01)
    assert pick_t_low(y, s, 0.95, t_high) <= t_high


def test_t_low_requires_positives():
    with pytest.raises(ValueError):
        pick_t_low(np.zeros(5, dtype=int), np.linspace(0, 1, 5), 0.95, 0.5)


def test_length_mismatch_rejected():
    with pytest.raises(ValueError):
        pick_t_high(np.array([0, 1]), np.array([0.1]), 0.01)
