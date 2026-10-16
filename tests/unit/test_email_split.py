import pytest

from phishguard.training.prepare_email import (
    FEATURE_NAMES,
    OUT_COLUMNS,
    Record,
    build_frame,
    check_sources,
    list_files,
    looks_english,
    split_frame,
)
from synthetic import make_synthetic_emails


@pytest.fixture(scope="module")
def built():
    records = [Record(*t) for t in make_synthetic_emails(n=60)]
    frame, counts = build_frame(records)
    return frame, counts


@pytest.fixture(scope="module")
def split(built):
    return split_frame(built[0], seed=1, test_fraction=0.2)


def test_build_frame_drops_and_counts_bad_messages(built):
    frame, counts = built
    stats = counts["per_source"]
    assert stats["enron"]["too_short"] == 1
    assert stats["enron"]["unparseable"] == 1
    assert stats["nazario"]["exact_duplicate"] == 1
    assert len(frame) == sum(s.get("kept", 0) for s in stats.values())


def test_frame_has_all_columns_without_group_yet(built):
    frame, _ = built
    assert set(OUT_COLUMNS) - {"group"} == set(frame.columns)
    assert set(FEATURE_NAMES) <= set(frame.columns)


def test_no_group_spans_dev_test_or_dev_temporal(split):
    dev, test, temporal, _ = split
    assert not set(dev["group"]) & set(test["group"])
    assert not set(dev["group"]) & set(temporal["group"])


def test_conflicting_text_is_dropped(split):
    dev, test, temporal, counts = split
    assert counts["conflicting_dropped"] == 2
    for part in (dev, test, temporal):
        assert (part.groupby("group")["y"].nunique() <= 1).all()


def test_temporal_is_newest_year_phishing_plus_locked_ham(split):
    dev, test, temporal, counts = split
    assert counts["newest_year"] == 2024
    phishing = temporal[temporal["y"] == 1]
    assert set(phishing["year"].dropna()) == {2024}
    ham = temporal[temporal["y"] == 0]
    assert set(ham["text"]) == set(test[test["y"] == 0]["text"])
    assert not (dev["year"] == 2024).any() and not (test["year"] == 2024).any()


def test_newest_year_copy_of_older_mail_is_dropped_from_temporal(split):
    _, _, _, counts = split
    assert counts["temporal_mixed_group_dropped"] == 1


def test_splits_keep_both_classes_and_dont_lose_rows(split, built):
    dev, test, temporal, counts = split
    for part in (dev, test, temporal):
        assert part["y"].nunique() == 2
    pool = len(built[0]) - counts["conflicting_dropped"] - counts["temporal_mixed_group_dropped"]
    temporal_phishing = int(temporal["y"].sum())
    assert len(dev) + len(test) + temporal_phishing == pool


def test_split_is_reproducible(built):
    first = split_frame(built[0], seed=7, test_fraction=0.2)[1]["text"].tolist()
    again = split_frame(built[0], seed=7, test_fraction=0.2)[1]["text"].tolist()
    assert first == again


def test_list_files_skips_cmds_and_skipped_folders(tmp_path):
    (tmp_path / "u" / "inbox").mkdir(parents=True)
    (tmp_path / "u" / "Deleted_Items").mkdir()
    (tmp_path / "u" / "inbox" / "1").write_bytes(b"x")
    (tmp_path / "u" / "Deleted_Items" / "2").write_bytes(b"x")
    (tmp_path / "cmds").write_bytes(b"x")
    names = [p.name for p in list_files(tmp_path, frozenset({"deleted_items"}))]
    assert names == ["1"]


def test_check_sources_rejects_a_wrong_hash_and_missing_file(tmp_path):
    (tmp_path / "a.mbox").write_bytes(b"data")
    cfg = {"raw_dir": str(tmp_path), "sources": {"a.mbox": "0" * 64}}
    with pytest.raises(ValueError, match="sha256"):
        check_sources(cfg)
    with pytest.raises(FileNotFoundError):
        check_sources({"raw_dir": str(tmp_path), "sources": {"b.mbox": None}})
    assert (
        len(check_sources({"raw_dir": str(tmp_path), "sources": {"a.mbox": None}})["a.mbox"]) == 64
    )


def test_audit_flags_source_artefacts_and_renders(built):
    from phishguard.training.audit_email import compute_audit, render_markdown

    frame, counts = built
    stats = compute_audit(frame, counts)
    assert set(stats["feature_aucs"]) == set(FEATURE_NAMES)
    assert set(stats["tokens"]) == {"nazario", "spamassassin", "enron"}
    assert sum(stats["kept_by_year"].values()) == counts["per_source"]["nazario"]["kept"]
    assert set(stats["kept_by_year"]) == {2022, 2023, 2024}
    text = render_markdown(stats, {"nazario/phishing-2022.mbox": "ab" * 32})
    assert "# Email data audit" in text and "Enron vs SpamAssassin" in text
    assert "nazario/phishing-2022.mbox" in text


def test_english_filter_keeps_english_and_short_texts_and_drops_other_languages():
    english = "please verify your account and update the password for this service at once " * 2
    spanish = "por favor verifique su cuenta y actualice la contraseña de este servicio ahora " * 2
    assert looks_english(english)
    assert not looks_english(spanish)
    assert looks_english("hola amigo")  # too short to judge
    assert not looks_english("к ак дела " * 30)
