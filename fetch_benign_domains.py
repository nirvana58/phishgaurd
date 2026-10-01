#!/usr/bin/env python3
"""
fetch_benign_domains.py

Pulls benign/legitimate domain lists from three independent sources:
  1. Tranco       - manipulation-resistant popularity ranking (research standard)
  2. Majestic Million - backlink-based popularity ranking
  3. Cisco Umbrella   - DNS query volume based ranking

Merges + dedupes them into a single domain pool, tagging each domain with
which source(s) it appeared in (useful signal - domains appearing in all
three rankings are almost certainly legitimate; domains only in one are
worth extra scrutiny).

Output: benign_domains_merged.csv with columns: domain, sources, source_count

Feed this output into your diversify_url_shapes.py step before training,
since all three sources give bare domains, not full URLs with paths.

NOTE: This script needs outbound network access to:
  - tranco-list.eu
  - downloads.majestic.com
  - s3-us-west-1.amazonaws.com (Cisco Umbrella)
Run it in an environment with unrestricted internet access (your own machine,
not a sandboxed tool container that whitelists only specific domains).

Usage:
    pip install requests --break-system-packages
    python fetch_benign_domains.py --top-n 100000 --output benign_domains_merged.csv
"""

import argparse
import csv
import io
import sys
import zipfile
from collections import defaultdict

import requests

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"
MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"
UMBRELLA_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

TIMEOUT = 60


def fetch_tranco(top_n: int) -> set[str]:
    print(f"[Tranco] Downloading top-1m list...")
    resp = requests.get(TRANCO_DOWNLOAD_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    domains = set()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        inner_name = zf.namelist()[0]
        with zf.open(inner_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for i, row in enumerate(reader):
                if i >= top_n:
                    break
                if len(row) >= 2:
                    domains.add(row[1].strip().lower())
    print(f"[Tranco] Got {len(domains)} domains")
    return domains


def fetch_majestic(top_n: int) -> set[str]:
    print(f"[Majestic] Downloading Majestic Million...")
    resp = requests.get(MAJESTIC_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    domains = set()
    reader = csv.DictReader(io.StringIO(resp.text))
    for i, row in enumerate(reader):
        if i >= top_n:
            break
        domain = row.get("Domain", "").strip().lower()
        if domain:
            domains.add(domain)
    print(f"[Majestic] Got {len(domains)} domains")
    return domains


def fetch_umbrella(top_n: int) -> set[str]:
    print(f"[Umbrella] Downloading Cisco Umbrella popularity list...")
    resp = requests.get(UMBRELLA_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    domains = set()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        inner_name = zf.namelist()[0]
        with zf.open(inner_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for i, row in enumerate(reader):
                if i >= top_n:
                    break
                if len(row) >= 2:
                    domains.add(row[1].strip().lower())
    print(f"[Umbrella] Got {len(domains)} domains")
    return domains


def merge_sources(top_n: int) -> dict[str, set[str]]:
    """Returns {domain: {source names it appeared in}}"""
    merged: dict[str, set[str]] = defaultdict(set)

    sources = {
        "tranco": fetch_tranco,
        "majestic": fetch_majestic,
        "umbrella": fetch_umbrella,
    }

    for name, fetch_fn in sources.items():
        try:
            domains = fetch_fn(top_n)
            for d in domains:
                merged[d].add(name)
        except requests.RequestException as e:
            print(f"[WARN] Failed to fetch {name}: {e}", file=sys.stderr)
            print(f"[WARN] Continuing with remaining sources...", file=sys.stderr)

    return merged


def write_output(merged: dict[str, set[str]], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "sources", "source_count"])
        # Sort by source_count descending (domains in more lists = higher confidence)
        for domain, sources in sorted(
            merged.items(), key=lambda kv: (-len(kv[1]), kv[0])
        ):
            writer.writerow([domain, "|".join(sorted(sources)), len(sources)])
    print(f"\nWrote {len(merged)} unique domains to {output_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--top-n",
        type=int,
        default=100_000,
        help="How many domains to pull from each source (default: 100000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="benign_domains_merged.csv",
        help="Output CSV path (default: benign_domains_merged.csv)",
    )
    parser.add_argument(
        "--min-sources",
        type=int,
        default=1,
        help="Only keep domains appearing in at least this many source lists "
        "(default: 1, i.e. keep everything). Use 2 or 3 for higher-confidence "
        "benign domains only.",
    )
    args = parser.parse_args()

    merged = merge_sources(args.top_n)

    if args.min_sources > 1:
        before = len(merged)
        merged = {d: s for d, s in merged.items() if len(s) >= args.min_sources}
        print(
            f"Filtered from {before} to {len(merged)} domains "
            f"(appearing in >= {args.min_sources} sources)"
        )

    write_output(merged, args.output)


if __name__ == "__main__":
    main()