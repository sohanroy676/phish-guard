"""Near-duplicate grouping with MinHash and LSH (numpy only, no extra dependency).

Phishing and ham corpora are full of copies and near-copies (campaign re-sends, list footers,
quoted threads). Rows in one group must never be split between dev and test, or the test leaks.
"""

import random
from collections.abc import Sequence
from zlib import crc32

import numpy as np

SHINGLE_WORDS = 5
N_PERMUTATIONS = 64
BANDS = 16  # 16 bands x 4 rows: two texts with Jaccard 0.7 collide in some band ~99% of the time
THRESHOLD = 0.7
_PRIME = (1 << 31) - 1  # hashes and coefficients stay below 2^31, so a*h+b fits in uint64


def shingles(text: str, k: int = SHINGLE_WORDS) -> set[str]:
    """Word k-grams. A text shorter than k words is one shingle, an empty text has none."""
    words = text.split()
    if not words:
        return set()
    if len(words) < k:
        return {" ".join(words)}
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def _coefficients(seed: int, n: int = N_PERMUTATIONS) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    a = np.array([rng.randrange(1, _PRIME) for _ in range(n)], dtype=np.uint64)
    b = np.array([rng.randrange(0, _PRIME) for _ in range(n)], dtype=np.uint64)
    return a[:, None], b[:, None]


def signature(items: set[str], a: np.ndarray, b: np.ndarray) -> np.ndarray:
    hashes = np.fromiter((crc32(s.encode("utf-8")) for s in items), dtype=np.uint64)
    return ((a * (hashes % _PRIME)[None, :] + b) % _PRIME).min(axis=1)


def _find(parent: list[int], i: int) -> int:
    root = i
    while parent[root] != root:
        root = parent[root]
    while parent[i] != root:  # path compression
        parent[i], i = root, parent[i]
    return root


def group_ids(texts: Sequence[str], seed: int = 42, threshold: float = THRESHOLD) -> list[int]:
    """One group id per text. Texts whose estimated Jaccard similarity is >= threshold are
    joined (transitively); a text with no words is always alone."""
    a, b = _coefficients(seed)
    rows = N_PERMUTATIONS // BANDS
    sigs: dict[int, np.ndarray] = {}
    for i, text in enumerate(texts):
        items = shingles(text)
        if items:
            sigs[i] = signature(items, a, b)

    parent = list(range(len(texts)))
    for band in range(BANDS):
        buckets: dict[tuple[int, ...], int] = {}
        for i, sig in sigs.items():
            key = tuple(sig[band * rows : (band + 1) * rows].tolist())
            first = buckets.setdefault(key, i)
            # Compare with the bucket's first member only: linear time even for huge buckets.
            if first != i and float(np.mean(sigs[first] == sig)) >= threshold:
                parent[_find(parent, i)] = _find(parent, first)
    return [_find(parent, i) for i in range(len(texts))]
