import random

import pandas as pd


def make_synthetic_raw(n_domains: int = 60, seed: int = 0) -> pd.DataFrame:
    """PhiUSIIL-shaped frame (URL, label; label 1 = legitimate) with separable classes.

    Includes duplicates, a conflicting pair, an IP host and an unsupported URL.
    """
    rng = random.Random(seed)
    rows = []
    for i in range(n_domains):
        legit = f"https://www.shop{i}.com"
        phish = f"http://secure-login-paypal{i}.xyz"
        for j in range(rng.randint(2, 4)):
            rows.append((f"{legit}/products/item{j}?id={rng.randint(1, 99)}", 1))
            rows.append((f"{phish}/verify/account{j}/signin.php?token={rng.randint(1, 99)}", 0))
    rows += [
        ("https://www.shop1.com/products/item0?id=5", 1),  # exact duplicate below
        ("https://www.shop1.com/products/item0?id=5", 1),
        ("http://conflict.example.com/page", 1),  # same text, both labels
        ("https://conflict.example.com/page", 0),
        ("http://192.168.4.4/login", 0),
        ("ftp://files.example.com/x", 1),  # unsupported scheme
    ]
    return pd.DataFrame(rows, columns=["URL", "label"]).assign(y=lambda d: 1 - d["label"])


def _words(rng: random.Random, n: int = 40) -> str:
    # Letters only: digits would be masked to one token and make every text look identical.
    return " ".join("".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=7)) for _ in range(n))


def _mail(subject: str, body: str, sender: str = "Sender <s@mail.example>") -> bytes:
    return f"From: {sender}\nTo: me@x.org\nSubject: {subject}\n\n{body}\n".encode()


def make_synthetic_emails(n: int = 40, seed: int = 0) -> list[tuple[int, str, int | None, bytes]]:
    """(y, source, year, raw) tuples: separable classes plus the awkward cases prepare must handle.

    Phishing is dated 2022-2024 (nazario); ham is undated (spamassassin, enron). Adds an exact
    duplicate, a near-duplicate, a text with both labels, a too-short mail, an unparseable file and
    a newest-year mail that is a near-copy of an older one.
    """
    rng = random.Random(seed)
    out: list[tuple[int, str, int | None, bytes]] = []
    for i in range(n):
        year = 2022 + i % 3
        phish = f"urgent verify your account password immediately {_words(rng)}"
        ham = f"meeting schedule lunch project report thanks {_words(rng)}"
        out.append((1, "nazario", year, _mail(f"Account alert {i}", phish)))
        source = "spamassassin" if i % 2 else "enron"
        out.append((0, source, None, _mail(f"Project note {i}", ham)))
    base = f"urgent verify your account password immediately {_words(rng, 60)}"
    out.append((1, "nazario", 2022, _mail("Dup", base)))
    out.append((1, "nazario", 2022, _mail("Dup", base)))  # exact duplicate
    out.append((1, "nazario", 2023, _mail("Dup", base.replace("a", "x", 1))))  # near duplicate
    out.append(
        (1, "nazario", 2024, _mail("Dup", base.replace("e", "y", 1)))
    )  # newest year, old group
    both = _words(rng, 60)
    out.append((1, "nazario", 2023, _mail("Same", both)))
    out.append((0, "enron", None, _mail("Same", both)))  # same text, both labels
    out.append((0, "enron", None, _mail("Hi", "ok")))  # too short
    out.append((0, "enron", None, b"this is not an email at all"))
    return out
