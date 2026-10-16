import json
from types import SimpleNamespace

import pytest

from phishguard.training.measure_phish import measure

SECRET_SUBJECT = "Zebra-quartz-subject"
SECRET_SENDER = "billing@secret-sender.example"


class FakeScorer:
    version, name, t_high, t_low = "vT", "fake", 0.8, 0.5

    def score(self, parsed):
        return 0.9 if "urgent" in parsed.text.lower() else 0.1


FAKE_URL = SimpleNamespace(version="vU", name="fake", t_high=0.8, t_low=0.5, score=lambda url: 0.1)

PHISH = "urgent verify your account now"
BULK_HEADERS = "List-Unsubscribe: <mailto:unsub@secret-sender.example>\nPrecedence: bulk\n"


def eml(body, extra=""):
    return f"From: Shop <{SECRET_SENDER}>\nSubject: {SECRET_SUBJECT}\n{extra}\n{body}\n".encode()


def make_tree(root):
    root.mkdir(parents=True)
    (root / "plain.eml").write_bytes(eml(PHISH))
    (root / "bulky.eml").write_bytes(eml(PHISH, BULK_HEADERS))
    (root / "quiet.eml").write_bytes(eml("hello there"))
    (root / "junk.eml").write_bytes(b"")
    return root


def test_gate_changes_only_bulk_looking_phish(tmp_path):
    out = measure(make_tree(tmp_path / "in"), "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    data = json.loads(out.read_text(encoding="utf-8"))
    o = data["overall"]
    assert o["n"] == 3
    assert data["skipped"] == {"not_an_email": 1}
    assert o["text_only"]["band_counts"]["high"] == 2
    assert o["ungated"]["high_or_suspicious"]["k"] == 2
    assert o["gated"]["high_or_suspicious"]["k"] <= o["ungated"]["high_or_suspicious"]["k"]
    assert o["lost_flag"]["k"] <= o["changed_by_gate"]["k"]


def test_result_holds_no_message_content(tmp_path):
    out = measure(make_tree(tmp_path / "in"), "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    text = out.read_text(encoding="utf-8")
    for secret in (SECRET_SUBJECT, SECRET_SENDER, "plain.eml", "bulky", "verify"):
        assert secret not in text


def test_never_overwrites(tmp_path):
    root = make_tree(tmp_path / "in")
    measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    with pytest.raises(FileExistsError):
        measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")


def test_missing_or_empty_folder(tmp_path):
    with pytest.raises(FileNotFoundError):
        measure(tmp_path / "nope", "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        measure(tmp_path / "empty", "t", FakeScorer(), FAKE_URL, tmp_path / "out")
