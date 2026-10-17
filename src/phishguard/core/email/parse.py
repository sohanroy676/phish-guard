"""Stdlib email parser. HTML is parsed for text and links, never rendered."""

import email
import re
from dataclasses import dataclass
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr
from html.parser import HTMLParser

from phishguard.core.email.mask import TRAILING_PUNCT, URL_RE

MAX_BYTES = 1_000_000
MAX_DEPTH = 10
MAX_PARTS = 100
MAX_LINKS = 200
MAX_HEADERS = 500
MAX_TEXT_CHARS = 100_000
MAX_ANCHOR_CHARS = 200

# A real email has at least one of these; plain text and random uploads do not.
_RECOGNISED_HEADERS = frozenset(
    {"from", "to", "subject", "date", "message-id", "received", "reply-to", "return-path"}
)
_SKIPPED_TAGS = frozenset({"script", "style", "head"})
_BREAK_TAGS = frozenset({"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6"})
_SPACE_RE = re.compile(r"\s+")


class EmailTooLarge(ValueError):
    pass


class NotAnEmail(ValueError):
    pass


@dataclass(frozen=True)
class Link:
    href: str
    anchor: str


@dataclass(frozen=True)
class ParsedEmail:
    headers: tuple[tuple[str, str], ...]
    subject: str
    from_display: str
    from_addr: str
    reply_to_addr: str
    text: str
    links: tuple[Link, ...]
    has_html: bool
    n_attachments: int
    has_raw_headers: bool
    truncated: bool


class _HtmlText(HTMLParser):
    """Collects visible text and (href, anchor) pairs. Script, style and head are skipped."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.links: list[Link] = []
        self._skip = 0
        self._href: str | None = None
        self._anchor: list[str] = []

    def _close_anchor(self) -> None:
        if self._href is not None:
            anchor = _SPACE_RE.sub(" ", "".join(self._anchor)).strip()
            self.links.append(Link(self._href, anchor[:MAX_ANCHOR_CHARS]))
        self._href = None
        self._anchor = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIPPED_TAGS:
            self._skip += 1
        elif tag in _BREAK_TAGS:
            self.chunks.append("\n")
        elif tag == "a":
            self._close_anchor()
            href = dict(attrs).get("href")
            if href and href.strip():
                self._href = href.strip()

    def handle_endtag(self, tag):
        if tag in _SKIPPED_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data):
        if self._skip:
            return
        self.chunks.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def finish(self) -> None:
        self.close()
        self._close_anchor()


def _clean(value: str) -> str:
    """Drop NULs and undecodable bytes (surrogates) so the text is always valid unicode."""
    value = value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return value.replace("\x00", "")


def _decode_header(value) -> str:
    text = _clean(str(value))
    try:
        return str(make_header(decode_header(text)))
    except (LookupError, UnicodeError, ValueError, HeaderParseError):
        return text


def _decode_payload(part: Message) -> str:
    raw = part.get_payload(decode=True)
    if not isinstance(raw, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return _clean(raw.decode(charset))
    except (LookupError, UnicodeDecodeError, ValueError):
        return _clean(raw.decode("utf-8", errors="replace"))


def _plain_links(text: str) -> list[Link]:
    return [Link(m.group(0).rstrip(TRAILING_PUNCT), "") for m in URL_RE.finditer(text)]


def _addr(value: str | None) -> tuple[str, str]:
    display, addr = parseaddr(_decode_header(value or ""))
    return display.strip(), addr.strip().lower()


def _merge_links(*groups: list[Link]) -> tuple[tuple[Link, ...], bool]:
    seen: set[Link] = set()
    merged: list[Link] = []
    for link in (link for group in groups for link in group):
        if link not in seen:
            seen.add(link)
            merged.append(link)
    return tuple(merged[:MAX_LINKS]), len(merged) > MAX_LINKS


def _build(
    headers: tuple[tuple[str, str], ...],
    subject: str,
    sender: str,
    reply_to: str,
    plain: list[str],
    html: list[str],
    has_raw_headers: bool,
    n_attachments: int,
    truncated: bool,
) -> ParsedEmail:
    html_text, html_links = [], []
    for markup in html:
        parser = _HtmlText()
        try:
            parser.feed(markup)
            parser.finish()
        except (AssertionError, RecursionError, ValueError):
            truncated = True  # malformed markup: keep what was read so far
        html_text.append("".join(parser.chunks))
        html_links.extend(parser.links)
    text = "\n".join(plain).strip() or "\n".join(html_text).strip()
    links, links_cut = _merge_links(html_links, _plain_links("\n".join(plain)))
    display, from_addr = _addr(sender)
    return ParsedEmail(
        headers=headers,
        subject=subject.strip(),
        from_display=display,
        from_addr=from_addr,
        reply_to_addr=_addr(reply_to)[1],
        text=text[:MAX_TEXT_CHARS],
        links=links,
        has_html=bool(html),
        n_attachments=n_attachments,
        has_raw_headers=has_raw_headers,
        truncated=truncated or links_cut or len(text) > MAX_TEXT_CHARS,
    )


def parse_raw(data: bytes | str) -> ParsedEmail:
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise EmailTooLarge("Email is too large to assess.")
    try:
        msg = email.message_from_bytes(raw)
    except (RecursionError, ValueError) as exc:
        raise NotAnEmail("Not a valid email.") from exc
    names = {name.lower() for name in msg.keys()}
    if not names & _RECOGNISED_HEADERS:
        raise NotAnEmail("Not a valid email.")

    headers = tuple((name.lower(), _decode_header(value)) for name, value in msg.items())
    plain: list[str] = []
    html: list[str] = []
    attachments = 0
    truncated = len(headers) > MAX_HEADERS
    stack: list[tuple[Message, int]] = [(msg, 0)]
    seen_parts = 0
    while stack:
        part, depth = stack.pop()
        seen_parts += 1
        if seen_parts > MAX_PARTS:
            truncated = True
            break
        if part.get_content_maintype() == "message":
            attachments += 1  # forwarded or bounced mail is counted, not read
        elif part.is_multipart():
            if depth >= MAX_DEPTH:
                truncated = True
            else:
                stack.extend((child, depth + 1) for child in reversed(part.get_payload()))
        elif part.get_content_type() in ("text/plain", "text/html") and (
            part.get_content_disposition() != "attachment"
        ):
            (html if part.get_content_type() == "text/html" else plain).append(
                _decode_payload(part)
            )
        else:
            attachments += 1
    return _build(
        headers[:MAX_HEADERS],
        _decode_header(msg.get("subject", "")),
        str(msg.get("from", "")),
        str(msg.get("reply-to", "")),
        plain,
        html,
        has_raw_headers=bool(names & {"from", "received"}),
        n_attachments=attachments,
        truncated=truncated,
    )


def from_fields(subject: str, sender: str, body: str) -> ParsedEmail:
    """Build an email from pasted fields. There are no real headers, so header rules never run."""
    if len(subject) + len(sender) + len(body) > MAX_BYTES:
        raise EmailTooLarge("Email is too large to assess.")
    return _build(
        (),
        _clean(subject),
        _clean(sender),
        "",
        [_clean(body)],
        [],
        has_raw_headers=False,
        n_attachments=0,
        truncated=False,
    )
