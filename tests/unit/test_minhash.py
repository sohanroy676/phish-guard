import random
import time

from phishguard.training.minhash import group_ids, shingles


def words(seed: int, n: int = 60) -> str:
    rng = random.Random(seed)
    return " ".join(f"w{rng.randrange(10_000)}" for _ in range(n))


def test_shingles_edge_cases():
    assert shingles("") == set()
    assert shingles("   ") == set()
    assert shingles("one two") == {"one two"}
    assert len(shingles("a b c d e f g")) == 3


def test_near_duplicates_share_a_group_and_unrelated_texts_do_not():
    base = words(1)
    near = base.replace("w", "x", 1)  # one word changed
    ids = group_ids([base, near, words(2), words(3)])
    assert ids[0] == ids[1]
    assert len({ids[0], ids[2], ids[3]}) == 3


def test_exact_duplicates_and_short_texts_group():
    ids = group_ids(["hello there", "hello there", "other short", ""])
    assert ids[0] == ids[1] != ids[2]
    assert ids[3] not in ids[:3]


def test_empty_texts_are_never_joined_together():
    ids = group_ids(["", "", ""])
    assert len(set(ids)) == 3


def test_grouping_is_transitive_through_a_chain():
    a = words(5, 200).split()
    texts = []
    for step in range(4):  # each text drifts a little from the previous one
        b = a.copy()
        for k in range(step * 12, step * 12 + 12):
            b[k] = f"z{step}_{k}"
        texts.append(" ".join(b))
        a = b
    assert len(set(group_ids(texts))) == 1


def test_deterministic_for_a_seed():
    texts = [words(i % 7) for i in range(30)]
    assert group_ids(texts, seed=1) == group_ids(texts, seed=1)


def test_many_identical_texts_stay_fast():
    start = time.perf_counter()
    ids = group_ids([words(9)] * 2000)
    assert len(set(ids)) == 1
    assert time.perf_counter() - start < 10


def test_empty_input():
    assert group_ids([]) == []
