import json
from types import SimpleNamespace

import pytest

from phishguard.training.measure_ham import measure, wilson

SECRET_SUBJECT = "Zebra-quartz-subject"
SECRET_SENDER = "billing@secret-sender.example"


class FakeScorer:
    version, name, t_high, t_low = "vT", "fake", 0.8, 0.5

    def score(self, parsed):
        return 0.9 if "urgent" in parsed.text.lower() else 0.1


FAKE_URL = SimpleNamespace(version="vU", name="fake", t_high=0.8, t_low=0.5, score=lambda url: 0.1)


def eml(body="Your monthly receipt is attached.", extra=""):
    return f"From: Shop <{SECRET_SENDER}>\nSubject: {SECRET_SUBJECT}\n{extra}\n{body}\n".encode()


def make_tree(root):
    for cat, items in {
        "receipt": [eml(), eml("urgent urgent act now")],
        "newsletter": [eml("Weekly digest, see https://example.com/post")],
    }.items():
        (root / cat).mkdir(parents=True)
        for i, data in enumerate(items):
            (root / cat / f"{i}.eml").write_bytes(data)
    (root / "loose.eml").write_bytes(eml())
    return root


def test_wilson_bounds():
    assert wilson(0, 0) == [0.0, 1.0]
    lo, hi = wilson(0, 50)
    assert lo == 0.0 and 0.0 < hi < 0.1
    lo, hi = wilson(50, 50)
    assert hi == 1.0 and lo > 0.9
    lo, hi = wilson(5, 50)
    assert lo < 0.1 < hi


def test_counts_and_categories(tmp_path):
    root = make_tree(tmp_path / "in")
    out = measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["overall"]["n"] == 4
    assert set(data["by_category"]) == {"receipt", "newsletter", "uncategorised"}
    assert data["by_category"]["receipt"]["text_band_counts"]["high"] == 1
    assert data["overall"]["fpr_text_high"]["k"] == 1
    assert data["overall"]["fpr_final_high"]["n"] == 4


def test_result_holds_no_message_content(tmp_path):
    root = make_tree(tmp_path / "in")
    out = measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    text = out.read_text(encoding="utf-8")
    for leak in (SECRET_SUBJECT, SECRET_SENDER, "secret-sender", "receipt is attached", "0.eml"):
        assert leak not in text


def test_never_overwrites(tmp_path):
    root = make_tree(tmp_path / "in")
    measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    with pytest.raises(FileExistsError):
        measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")


def test_empty_and_missing_folders_fail_clearly(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        measure(tmp_path / "empty", "e", FakeScorer(), FAKE_URL, tmp_path / "out")
    with pytest.raises(FileNotFoundError):
        measure(tmp_path / "nope", "n", FakeScorer(), FAKE_URL, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_bad_files_are_counted_and_skipped(tmp_path):
    root = tmp_path / "in"
    (root / "a").mkdir(parents=True)
    (root / "a" / "ok.eml").write_bytes(eml())
    (root / "a" / "junk.eml").write_bytes(b"just some words, no headers at all")
    (root / "a" / "huge.eml").write_bytes(b"From: a@b.com\n\n" + b"x" * 1_100_000)
    out = measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["overall"]["n"] == 1
    assert data["skipped"] == {"not_an_email": 1, "too_large": 1}


def test_header_rule_raises_final_band_but_not_text_band(tmp_path):
    root = tmp_path / "in"
    (root / "a").mkdir(parents=True)
    failing = eml(extra="Authentication-Results: mx.example; spf=fail; dmarc=fail\n")
    (root / "a" / "x.eml").write_bytes(failing)
    out = measure(root, "t", FakeScorer(), FAKE_URL, tmp_path / "out")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["overall"]["text_band_counts"]["low"] == 1
    assert data["overall"]["final_band_counts"]["suspicious"] == 1
    assert data["overall"]["rule_hits"] == {"auth_fail": 1}
