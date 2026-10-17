import base64

import pytest

from phishguard.core.email.parse import (
    MAX_BYTES,
    MAX_DEPTH,
    MAX_LINKS,
    MAX_TEXT_CHARS,
    EmailTooLarge,
    Link,
    NotAnEmail,
    from_fields,
    parse_raw,
)

HEAD = "From: Bank <alerts@bank.example>\nTo: me@x.org\nSubject: Hello\n"


def html_mail(body: str) -> str:
    return HEAD + 'Content-Type: text/html; charset="utf-8"\n\n' + body


def nested(levels: int) -> str:
    out = HEAD + 'Content-Type: multipart/mixed; boundary="b0"\n\n'
    for i in range(levels):
        out += f'--b{i}\nContent-Type: multipart/mixed; boundary="b{i + 1}"\n\n'
    return out + f"--b{levels}\nContent-Type: text/plain\n\ndeep body\n--b{levels}--\n"


def test_anchor_text_and_href_are_returned_as_a_pair():
    parsed = parse_raw(html_mail('<a href="http://evil.xyz/login">www.paypal.com</a>'))
    assert parsed.links == (Link("http://evil.xyz/login", "www.paypal.com"),)
    assert parsed.has_html


def test_malformed_encoded_word_header_does_not_crash():
    parsed = parse_raw("From: a@b.example\nSubject: =?utf-8?B?abcde?=\n\nhi")
    assert "abc" in parsed.subject


def test_headers_are_decoded_and_flagged_raw():
    parsed = parse_raw(
        "From: =?utf-8?q?Ren=C3=A9e?= <R@Bank.Example>\nSubject: =?utf-8?q?Hi_=E2=9C=93?=\n\nhi"
    )
    assert parsed.has_raw_headers
    assert parsed.from_display == "Renée"
    assert parsed.from_addr == "r@bank.example"
    assert parsed.subject == "Hi ✓"


def test_plain_text_urls_become_links_without_trailing_punctuation():
    parsed = parse_raw(HEAD + "\nGo to http://a.example/x, or www.b.example.")
    assert [link.href for link in parsed.links] == ["http://a.example/x", "www.b.example"]


def test_script_and_style_content_is_not_text():
    body = "<style>.x{color:red}</style><script>steal()</script><p>Visible</p>"
    parsed = parse_raw(html_mail(body))
    assert parsed.text == "Visible"


def test_html_is_never_rendered_but_kept_as_text():
    parsed = parse_raw(html_mail("<p>a &amp; b</p><img src='http://track.example/p.gif'>"))
    assert parsed.text == "a & b"
    assert parsed.links == ()


def test_javascript_and_mailto_hrefs_are_kept_for_the_rules():
    parsed = parse_raw(html_mail('<a href="javascript:x()">go</a><a href="mailto:a@b.com">m</a>'))
    assert {link.href for link in parsed.links} == {"javascript:x()", "mailto:a@b.com"}


def test_unclosed_anchor_is_still_recorded():
    parsed = parse_raw(html_mail('<a href="http://a.example">one<a href="http://b.example">two'))
    assert [(link.href, link.anchor) for link in parsed.links] == [
        ("http://a.example", "one"),
        ("http://b.example", "two"),
    ]


def test_multipart_alternative_prefers_plain_text_and_keeps_html_links():
    raw = (
        HEAD
        + 'Content-Type: multipart/alternative; boundary="X"\n\n'
        + "--X\nContent-Type: text/plain\n\nplain version\n"
        + "--X\nContent-Type: text/html\n\n<a href='http://e.example'>click</a>\n--X--\n"
    )
    parsed = parse_raw(raw)
    assert parsed.text == "plain version"
    assert parsed.links == (Link("http://e.example", "click"),)


def test_attachments_are_counted_not_read():
    payload = base64.b64encode(b"MZ" * 100).decode()
    raw = (
        HEAD
        + 'Content-Type: multipart/mixed; boundary="X"\n\n'
        + "--X\nContent-Type: text/plain\n\nbody\n"
        + "--X\nContent-Type: application/pdf\nContent-Transfer-Encoding: base64\n\n"
        + payload
        + "\n--X--\n"
    )
    parsed = parse_raw(raw)
    assert parsed.n_attachments == 1
    assert parsed.text == "body"


def test_nested_mime_depth_bomb_is_capped():
    parsed = parse_raw(nested(50))
    assert parsed.truncated
    assert "deep body" not in parsed.text


def test_nesting_within_the_cap_is_read():
    parsed = parse_raw(nested(MAX_DEPTH - 2))
    assert "deep body" in parsed.text


def test_extreme_nesting_never_crashes():
    try:
        parsed = parse_raw(nested(3000))
    except NotAnEmail:
        return
    assert parsed.truncated


def test_unknown_charset_falls_back_to_replacement():
    raw = HEAD + "Content-Type: text/plain; charset=x-nope\nContent-Transfer-Encoding: 8bit\n\n"
    parsed = parse_raw(raw.encode() + b"caf\xe9 ok")
    assert "caf" in parsed.text and parsed.text.endswith("ok")


def test_invalid_bytes_in_declared_charset_are_replaced():
    raw = HEAD + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n"
    assert "�" in parse_raw(raw.encode() + b"bad \xff\xfe bytes").text


def test_bad_header_charset_does_not_crash():
    parsed = parse_raw("From: a@b.example\nSubject: =?x-nope?q?hi?=\n\nbody")
    assert parsed.subject == "=?x-nope?q?hi?="  # left undecoded, never a crash


def test_oversized_input_is_rejected():
    with pytest.raises(EmailTooLarge):
        parse_raw(HEAD.encode() + b"\n" + b"a" * MAX_BYTES)


def test_huge_text_part_is_capped():
    parsed = parse_raw(HEAD + "\n" + "word " * 100_000)
    assert len(parsed.text) <= MAX_TEXT_CHARS
    assert parsed.truncated


def test_link_count_is_capped():
    body = " ".join(f"http://h{i}.example/" for i in range(MAX_LINKS + 50))
    parsed = parse_raw(HEAD + "\n" + body)
    assert len(parsed.links) == MAX_LINKS
    assert parsed.truncated


@pytest.mark.parametrize(
    "data", ["", "just some text, not an email", b"\x00\x01\x02", "<html></html>"]
)
def test_non_email_input_is_rejected(data):
    with pytest.raises(NotAnEmail):
        parse_raw(data)


def test_received_header_alone_marks_raw_headers():
    assert parse_raw("Received: from x by y\nSubject: s\n\nbody").has_raw_headers


def test_subject_only_is_an_email_without_raw_headers():
    assert not parse_raw("Subject: s\n\nbody").has_raw_headers


def test_from_fields_never_has_raw_headers_even_if_body_looks_like_headers():
    body = "Authentication-Results: spf=fail\nFrom: x@y.example\n\nhello"
    parsed = from_fields("Subject", "Bank <a@bank.example>", body)
    assert not parsed.has_raw_headers
    assert parsed.headers == ()
    assert parsed.from_addr == "a@bank.example"
    assert body.splitlines()[0] in parsed.text


def test_from_fields_rejects_oversized_input():
    with pytest.raises(EmailTooLarge):
        from_fields("s", "a@b.example", "x" * MAX_BYTES)
