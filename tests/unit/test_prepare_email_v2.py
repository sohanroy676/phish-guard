import pandas as pd

from phishguard.core.email.features import sender_context
from phishguard.training.prepare_email import Record, build_frame, split_frame
from phishguard.training.prepare_email_v2 import gmail_labels, select_modern

BODY = "Hello, thank you for your order. We will ship the items that you have bought from us. "


def eml(sender, subject, body=BODY, labels="Category Promotions", mid=None):
    head = f"From: {sender}\nSubject: {subject}\nX-Gmail-Labels: {labels}\n"
    if mid:
        head += f"Message-ID: <{mid}>\n"
    return (head + "\n" + body).encode()


def pick(items, held_ids=frozenset(), held_texts=(), cap=10):
    records, stats = select_modern(iter(items), set(held_ids), list(held_texts), 42, cap)
    return records, stats


def test_labels_are_normalised():
    from phishguard.core.email.parse import parse_raw

    parsed = parse_raw(eml("a@b.com", "s", labels="Category Updates,Inbox"))
    assert gmail_labels(parsed) == {"updates", "inbox"}


def test_forbidden_and_uncategorised_mail_is_dropped():
    items = [
        (
            "person_1",
            eml("a@shop.com", "one", body=BODY + "alpha", labels="Spam,Category Promotions"),
        ),
        ("person_1", eml("a@shop.com", "two", body=BODY + "beta", labels="Sent")),
        ("person_1", eml("a@shop.com", "three", body=BODY + "gamma", labels="Inbox")),
        ("person_1", eml("a@shop.com", "four", body=BODY + "delta", labels="Category Updates")),
    ]
    records, stats = pick(items)
    assert len(records) == 1
    assert stats["person_1"]["spam_trash_sent_chat"] == 2
    assert stats["person_1"]["no_allowed_category"] == 1


def test_held_out_message_id_and_template_are_dropped():
    held = eml("a@shop.com", "h", mid="held@x")
    items = [
        ("person_1", eml("a@shop.com", "x", mid="held@x")),
        ("person_2", eml("b@other.com", "y", mid="new@x")),
    ]
    from phishguard.core.email.features import model_text
    from phishguard.core.email.parse import parse_raw

    records, stats = pick(items, {"<held@x>"}, [model_text(parse_raw(held))])
    # the second mail is the same template as the held-out text, so it is dropped as well
    assert records == []
    assert stats["person_1"]["held_out_message_id"] == 1
    assert stats["person_2"]["near_duplicate_of_held_out"] == 1


def test_duplicate_message_id_across_people_keeps_the_first():
    items = [
        ("person_1", eml("a@shop.com", "x", body=BODY + "one", mid="same@x")),
        ("person_2", eml("a@shop.com", "x", body=BODY + "two different words here", mid="same@x")),
    ]
    records, stats = pick(items)
    assert [r.source for r in records] == ["person_1"]
    assert stats["person_2"]["duplicate_message_id"] == 1


def test_sender_cap_applies_per_registered_domain_not_address():
    items = [
        (
            "person_1",
            eml(
                f"n{i}@{'mail.' if i % 2 else ''}shop.co.uk",
                f"s{i}",
                body=f"{BODY} product number {'zebra giraffe lion tiger'.split()[i % 4]} {i * 'x'}",
            ),
        )
        for i in range(8)
    ]
    records, stats = pick(items, cap=3)
    assert len(records) == 3
    assert {r.domain for r in records} == {"shop.co.uk"}
    assert stats["person_1"]["sender_cap"] == 5


def test_non_english_and_tiny_mail_are_dropped():
    items = [
        (
            "person_1",
            eml("a@shop.com", "x", body="oui bonjour merci beaucoup pour votre achat " * 6),
        ),
        ("person_1", eml("a@shop.com", "y", body="ok")),
    ]
    records, stats = pick(items)
    assert records == []
    assert stats["person_1"]["non_english"] == 1
    assert stats["person_1"]["too_short"] == 1


def test_domain_joins_groups_so_a_sender_lands_in_one_split():
    def rec(i, domain):
        body = f"{BODY} unique words about topic{i} and nothing alike {'q' * i} {i}" * 2
        return Record(0, "person_1", None, eml(f"s@{domain}", f"subj {i}", body), domain)

    records = [rec(i, "a.com" if i % 2 else "b.com") for i in range(40)]
    records += [
        Record(
            1,
            "nazario",
            2020 + i % 2,
            eml(f"p{i}@evil.example", f"urgent {i}", f"verify your account now {'z' * i} {BODY}"),
        )
        for i in range(60)
    ]
    frame, _ = build_frame(records, mask_for=sender_context)
    dev, test, temporal, _ = split_frame(frame, 42, 0.2)
    groups = pd.concat([dev, test])["group"]
    ham_groups = set(groups[pd.concat([dev, test])["y"] == 0])
    # all ham from one domain share a group, so there are at most two ham groups
    assert len(ham_groups) <= 2
    assert not set(dev["group"]) & set(test["group"])
