"""Build core/lists/popular_domains.txt from the Majestic Million CSV (ADR 0010).

Takes the top N by the list's own rank (chosen before any measurement), then drops shared hosts:
the public-suffix private section (a domain that is itself a suffix), free_hosting.txt, shorteners
and user_content_hosts.txt. Majestic Million is licensed CC BY 3.0 (https://majestic.com/reports/majestic-million).
"""

import argparse
import csv
import hashlib
from pathlib import Path

import tldextract

from phishguard.core.lists import load_list

TOP_N = 5_000


def popular_domains(csv_path: Path, top_n: int = TOP_N) -> list[str]:
    private = tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )
    blocked = load_list("free_hosting") | load_list("shorteners") | load_list("user_content_hosts")
    out = []
    with csv_path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if int(row["GlobalRank"]) > top_n:
                break
            domain = row["Domain"].lower()
            if domain in blocked or private(domain).domain == "":
                continue
            out.append(domain)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    domains = popular_domains(args.csv)
    sha = hashlib.sha256(args.csv.read_bytes()).hexdigest()
    header = (
        "# Widely used registrable domains, for the ADR 0010 sender-owned link exemption.\n"
        "# Source: Majestic Million, https://majestic.com/reports/majestic-million\n"
        f"# (top {TOP_N} by GlobalRank), licensed CC BY 3.0 (attribution: Majestic).\n"
        "# Downloaded 2026-10-18.\n"
        f"# CSV SHA-256 {sha}\n"
        "# Shared hosts removed (public-suffix private section, free_hosting, shorteners,\n"
        "# user_content_hosts). Rebuild with phishguard.training.build_popular_domains.\n"
    )
    args.out.write_text(header + "\n".join(domains) + "\n", encoding="utf-8")
    print(len(domains))


if __name__ == "__main__":
    main()
