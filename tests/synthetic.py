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
