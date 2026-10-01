"""
training/rebalance_safe_urls.py

Rebalances a rank-ordered "safe domain" list so its DENSITY reflects
real-world traffic popularity, instead of treating every domain as equally
common.

Why this matters:
  safe.csv is a flat, rank-ordered domain list (column "sr" = popularity
  rank, "abc" = domain — this is a Tranco/Cisco-Umbrella-style top-1M
  list). K-means and SOM are density-based: they learn "normal" from
  whatever shape of data is MOST COMMON in the training set. Feeding them
  one row per domain treats google.com (a huge share of real-world
  traffic) and some random long-tail domain nobody visits identically —
  one vote each, out of a million.

  Real-world safe web traffic follows something close to a Zipf / power-law
  distribution: a small number of extremely popular domains — which also
  tend to be short, simple, low-entropy names — account for a hugely
  disproportionate share of actual requests. Training on a uniformly
  weighted list inverts this: it teaches the model that short, simple,
  iconic domains (the MOST common real traffic) are numerically rare,
  which is exactly what produced the false-positive SUSPICIOUS verdict on
  google.com — row 1 of 1,000,000, represented once, sitting at the 5th
  percentile for Shannon entropy and 14th percentile for length against a
  population dominated by longer, higher-entropy long-tail domains.

Fix: resample the domain list WITH REPLACEMENT, weighted by rank using a
Zipf-like curve — P(domain) ∝ 1 / rank^s — so popular domains are
duplicated proportionally to (an approximation of) their real-world
traffic share.

Usage:
    python -m training.rebalance_safe_urls \
        --input safe.csv --output safe_rebalanced.csv \
        --out-rows 2000000 --zipf-s 0.8

  --zipf-s controls how aggressively popularity is weighted:
    0.0  = no reweighting (identical to the current uniform behavior)
    0.6  = mild skew
    0.8  = moderate skew (recommended starting point)
    1.0+ = strong skew (classic Zipf's law exponent for word/traffic
           frequency distributions)
  Tune by checking the duplication counts printed at the end — you want
  well-known domains to appear meaningfully more often than obscure ones,
  without the top handful swallowing so much of the training set that
  long-tail structure disappears entirely.
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

import numpy as np


def rebalance(
    input_path: Path,
    output_path: Path,
    out_rows: int,
    zipf_s: float,
    seed: int = 42,
) -> None:
    ranks: list[int] = []
    domains: list[str] = []

    with open(input_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        if "Domain" not in fieldnames:
            print(
                f"Expected a domain column named 'Domain', found columns: {fieldnames}",
                file=sys.stderr,
            )
            sys.exit(1)
        has_rank_col = "sr" in fieldnames

        for i, row in enumerate(reader, start=1):
            d = row.get("Domain", "").strip()
            if not d:
                continue
            domains.append(d)
            if has_rank_col:
                try:
                    ranks.append(int(row["sr"]))
                    continue
                except (ValueError, TypeError):
                    pass
            # Fall back to row order as rank if 'sr' is missing/non-numeric
            ranks.append(i)

    n = len(domains)
    if n == 0:
        print("No domains loaded — nothing to do.", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {n:,} domains.")

    ranks_arr = np.asarray(ranks, dtype=np.float64)
    # Guard against rank 0 / negative values before the power operation.
    ranks_arr = np.clip(ranks_arr, 1.0, None)

    if zipf_s > 0:
        weights = 1.0 / np.power(ranks_arr, zipf_s)
    else:
        weights = np.ones(n)  # zipf_s=0 -> uniform, i.e. today's behavior
    weights = weights / weights.sum()

    rng = np.random.RandomState(seed)
    print(f"Resampling to {out_rows:,} rows (Zipf exponent s={zipf_s})…")
    idx = rng.choice(n, size=out_rows, replace=True, p=weights)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sr", "Domain"])
        for i, j in enumerate(idx, start=1):
            writer.writerow([i, domains[j]])

    print(f"Wrote {output_path}")
    print()

    # Sanity report: how often did well-known domains get duplicated?
    counts = Counter(domains[j] for j in idx)
    print("Duplication count for well-known domains after rebalancing:")
    for d in [
        "google.com", "facebook.com", "microsoft.com", "youtube.com",
        "apple.com", "instagram.com", "amazon.com", "netflix.com",
    ]:
        c = counts.get(d, 0)
        print(f"  {d:18s} -> {c:>8,} times  ({c / out_rows * 100:6.3f}% of output)")

    # Also report how much of the output is "unique" long-tail vs duplicated,
    # as a rough diversity check.
    n_unique_used = len(counts)
    print()
    print(
        f"{n_unique_used:,} distinct source domains appear at least once "
        f"in the {out_rows:,}-row output ({n_unique_used / n * 100:.1f}% of "
        f"the original {n:,}-domain list)."
    )


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--input", type=Path, default=Path("safe.csv"))
    p.add_argument("--output", type=Path, default=Path("safe_rebalanced.csv"))
    p.add_argument(
        "--out-rows", type=int, default=2_000_000,
        help="Total rows in the rebalanced output (sampled with replacement).",
    )
    p.add_argument(
        "--zipf-s", type=float, default=0.8,
        help="Zipf exponent controlling popularity skew (0 = uniform/current behavior).",
    )
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    rebalance(args.input, args.output, args.out_rows, args.zipf_s, args.seed)


if __name__ == "__main__":
    main()
