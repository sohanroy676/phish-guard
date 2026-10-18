import json
from types import SimpleNamespace

import pytest

from phishguard.training import measure_flag_sources as mfs

SECRET_SUBJECT = "Zebra-quartz-subject"
SECRET_HOST = "secret-sender-host.example"
BODY = "Your order shipped. Track it at {link} today.\n"


def scorer(value):
    return SimpleNamespace(
        version="vT", name="fake", t_high=0.8, t_low=0.5, score=lambda parsed: value
    )


def url_scorer(value):
    return SimpleNamespace(version="vU", name="fake", t_high=0.8, t_low=0.5, score=lambda u: value)


def eml(link="https://shop.example/orders/1", headers=""):
    return (
        f"From: Shop <orders@{SECRET_HOST}>\nSubject: {SECRET_SUBJECT}\n{headers}\n"
        + BODY.format(link=link)
    ).encode()


def test_bucket_logic():
    f, low = "high", "low"
    assert mfs.bucket(low, f, f, f) is None
    assert mfs.bucket(f, low, low, f) == "rule"
    assert mfs.bucket(f, f, f, low) == "either_alone"
    assert mfs.bucket(f, low, f, low) == "text_only"
    assert mfs.bucket(f, f, low, low) == "links_only"
    assert mfs.bucket(f, low, low, low) == "interaction"


def test_text_model_alone_drives_the_flag():
    row = mfs.score_one(eml(), scorer(0.95), url_scorer(0.1))
    assert row["deployed"] in mfs.FLAGGED
    assert row["bucket"] == "text_only"


def test_link_alone_drives_the_flag():
    row = mfs.score_one(eml(), scorer(0.1), url_scorer(0.95))
    assert row["bucket"] == "links_only"
    assert row["link_model_only"] == "high"


def test_both_alone_suffice_when_both_are_high():
    row = mfs.score_one(eml(), scorer(0.95), url_scorer(0.95))
    assert row["bucket"] == "either_alone"


def test_clean_message_has_no_bucket_and_no_counted_links_flag():
    row = mfs.score_one(eml(link="no links here"), scorer(0.1), url_scorer(0.95))
    assert row["bucket"] is None
    assert row["no_links"] is True


def test_gate_turns_bulk_flag_into_cant_assess():
    row = mfs.score_one(
        eml(headers="List-Unsubscribe: <mailto:u@x.example>\n"), scorer(0.95), url_scorer(0.1)
    )
    assert row["bulk"] is True
    assert row["ungated"] in mfs.FLAGGED
    assert row["deployed"] == "cant_assess"
    assert row["gated"] is True


def test_unparseable_message_is_none():
    assert mfs.score_one(b"", scorer(0.1), url_scorer(0.1)) is None


def test_summary_keys_are_counts_and_carry_no_text():
    rows = [
        mfs.score_one(eml(), scorer(0.95), url_scorer(0.1)),
        mfs.score_one(eml(), scorer(0.1), url_scorer(0.1)),
    ]
    summary = mfs.summarise(rows)
    assert summary["n"] == 2
    assert summary["flagged"]["k"] == 1
    assert summary["buckets"]["text_only"]["k"] == 1
    text = json.dumps(summary)
    assert SECRET_SUBJECT not in text and SECRET_HOST not in text


def test_refuses_to_overwrite(tmp_path):
    (tmp_path / mfs.OUT_NAME).write_text("{}")
    with pytest.raises(FileExistsError):
        mfs.run(tmp_path / "cfg.yaml", tmp_path, ("v1",))
