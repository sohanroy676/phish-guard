from pathlib import Path

import pandas as pd
import pytest

from phishguard.training.common import REPO_ROOT, read_phiusiil
from phishguard.training.prepare_url import prepare_frame


def test_split_label_mapping_makes_one_phishing(tmp_path):
    csv = tmp_path / "d.csv"
    csv.write_text("URL,label\nhttp://a.xyz/x,0\nhttps://b.com/,1\n", encoding="utf-8")
    df = read_phiusiil(csv)
    assert df["y"].tolist() == [1, 0]


def test_split_rejects_bad_labels_and_missing_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("URL,label\nhttp://a.xyz/x,2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="only 0 and 1"):
        read_phiusiil(bad)
    nocol = tmp_path / "nocol.csv"
    nocol.write_text("URL,other\nhttp://a.xyz/x,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing column"):
        read_phiusiil(nocol)


def test_split_no_domain_in_both_dev_and_test(synthetic_raw):
    dev, test, _ = prepare_frame(synthetic_raw, seed=1, test_fraction=0.2)
    assert not set(dev["group"]) & set(test["group"])
    assert len(dev) > len(test) > 0


def test_split_has_both_classes_in_both_parts(synthetic_raw):
    dev, test, _ = prepare_frame(synthetic_raw, seed=1, test_fraction=0.2)
    assert set(dev["y"]) == {0, 1}
    assert set(test["y"]) == {0, 1}


def test_split_cleaning_counts(synthetic_raw):
    dev, test, counts = prepare_frame(synthetic_raw, seed=1, test_fraction=0.2)
    assert counts["unsupported"] == 1  # the ftp URL
    assert counts["duplicates_dropped"] >= 1
    assert counts["conflicting_dropped"] == 2  # both labelled copies of conflict.example.com/page
    urls = set(dev["url"]) | set(test["url"])
    assert not any("conflict.example.com" in u for u in urls)
    assert not any(u.startswith("ftp:") for u in urls)
    assert counts["dev_rows"] + counts["test_rows"] == len(dev) + len(test)


def test_split_is_deterministic_and_seed_sensitive(synthetic_raw):
    a = prepare_frame(synthetic_raw, seed=7, test_fraction=0.2)[1]
    b = prepare_frame(synthetic_raw, seed=7, test_fraction=0.2)[1]
    c = prepare_frame(synthetic_raw, seed=8, test_fraction=0.2)[1]
    assert a["url"].tolist() == b["url"].tolist()
    assert set(a["group"]) != set(c["group"])


def test_split_ip_hosts_group_by_host(synthetic_raw):
    dev, test, _ = prepare_frame(synthetic_raw, seed=1, test_fraction=0.2)
    both = pd.concat([dev, test])
    assert set(both[both["url"].str.contains("192.168.4.4")]["group"]) == {"192.168.4.4"}


def test_split_real_data_has_no_domain_overlap():
    processed = Path(REPO_ROOT) / "data" / "processed"
    if not (processed / "url_dev.csv").is_file():
        pytest.skip("run prepare on the real dataset first")
    dev = pd.read_csv(processed / "url_dev.csv")
    test = pd.read_csv(processed / "url_test.csv")
    assert not set(dev["group"]) & set(test["group"])
