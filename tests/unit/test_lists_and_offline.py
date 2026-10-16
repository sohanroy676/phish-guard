import socket

import pytest

from phishguard.core.lists import load_list
from phishguard.core.url.normalize import get_extractor, normalize_url

NAMES = [
    "brands",
    "shorteners",
    "free_hosting",
    "keywords",
    "email_keywords",
    "artefact_stoplist",
]


@pytest.mark.parametrize("name", NAMES)
def test_list_loads_clean(name):
    entries = load_list(name)
    assert entries
    assert all(e == e.strip().lower() and not e.startswith("#") for e in entries)


def test_list_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_list("nope")


def test_extractor_has_no_fetch_urls():
    assert tuple(get_extractor().suffix_list_urls) == ()


def test_normalize_makes_no_network_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    assert normalize_url("https://a.example.co.uk/").suffix == "co.uk"
