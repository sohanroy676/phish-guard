import json
from types import SimpleNamespace

import pytest

from phishguard.training import measure_link_policy as mlp
from phishguard.training.prepare_email_v2 import select_modern

SECRET_SUBJECT = "Zebra-quartz-subject"
BODY = "Hello, thank you for your order. We will ship the items that you have bought from us. "


class FakeScorer:
    version, name, t_high, t_low = "vT", "fake", 0.8, 0.5

    def score(self, parsed):
        return 0.1


# Every link scores High, so only the exemption can keep a message from being flagged.
BAD_URL = SimpleNamespace(version="vU", name="fake", t_high=0.8, t_low=0.5, score=lambda url: 0.95)

BULK = "List-Unsubscribe: <mailto:u@amazon.com>\n"
AUTH = "Authentication-Results: mx.example; dmarc=pass header.from=amazon.com\n"


def eml(link, headers=BULK + AUTH, sender="Shop <orders@amazon.com>"):
    return (
        f"From: {sender}\nSubject: {SECRET_SUBJECT}\n{headers}\n"
        f"Your order shipped. Track it at {link} today.\n"
    ).encode()


def test_exemption_only_lowers_the_band_for_authenticated_sender_owned_links():
    owned = mlp.score_arms(eml("https://www.amazon.com/orders/1"), FakeScorer(), BAD_URL)
    assert owned["off"] in mlp.FLAGGED
    assert owned["on"] not in mlp.FLAGGED


def test_other_domain_unauthenticated_and_forged_senders_are_not_exempt():
    for raw in (
        eml("https://evil-login.example/orders/1"),  # not the sender's domain
        eml("https://www.amazon.com/orders/1", headers=BULK),  # no dmarc pass
        eml("https://www.amazon.com/orders/1", sender="Shop <x@evil.example>"),  # misaligned
    ):
        bands = mlp.score_arms(raw, FakeScorer(), BAD_URL)
        assert bands["on"] == bands["off"]


def test_unparseable_message_is_none():
    assert mlp.score_arms(b"", FakeScorer(), BAD_URL) is None


def test_pick_sample_caps_each_sender_domain():
    left = [("person_1", b"a%d" % i, "shop.com") for i in range(5)] + [("person_2", b"x", "b.com")]
    sample, senders = mlp.pick_sample(left, cap=2)
    assert len(sample) == 3
    assert senders == 2


def test_summarise_counts_drop_and_bar():
    rows = [{"off": "high", "on": "cant_assess"}] * 3 + [{"off": "low", "on": "low"}] * 7
    s = mlp.summarise(rows)
    assert s["lost_flag"]["k"] == 3
    assert s["gained_flag"]["k"] == 0
    assert s["drop_points"] == pytest.approx(0.3)
    assert s["bar_met"] is True
    small = mlp.summarise([{"off": "high", "on": "high"}] * 39 + [{"off": "high", "on": "low"}])
    assert small["bar_met"] is False
    assert mlp.summarise([])["bar_met"] is False


def test_leftover_holds_only_cap_dropped_messages():
    def ham(i):
        body = BODY + f"unique{i} " * 5
        return (
            f"From: a@shop.com\nSubject: s{i}\nX-Gmail-Labels: Category Promotions\n\n{body}"
        ).encode()

    items = [("person_1", ham(i)) for i in range(4)]
    leftover: list = []
    records, stats = select_modern(iter(items), set(), [], 42, 2, leftover)
    assert len(records) == 2
    assert len(leftover) == 2 == stats["person_1"]["sender_cap"]
    kept = {r.raw for r in records}
    assert not any(raw in kept for _, raw, _ in leftover)


def test_result_is_counts_only(tmp_path):
    sample = [("person_1", eml("https://www.amazon.com/orders/1"))]
    by_person, skipped = mlp.measure(sample, FakeScorer(), BAD_URL)
    text = json.dumps({"p": {k: mlp.summarise(v) for k, v in by_person.items()}, "s": skipped})
    for secret in (SECRET_SUBJECT, "amazon", "orders"):
        assert secret not in text
