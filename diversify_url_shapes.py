#!/usr/bin/env python3
"""
diversify_url_shapes.py

Fixes a specific, confirmed data bug: the benign training set (e.g.
safe_rebalanced_part001.csv) is currently 100% uniform on:
  - www. prefix present on every URL
  - path always empty (root only)
  - query string never present
  - num_subdomains never 0, num_dots never below 2

This means the SOM/K-means models have never seen a legitimate URL shaped
like "https://frameley.com/" (no www, num_subdomains=0, num_dots=1) and
flag it as anomalous purely because that shape is missing from training,
not because it's actually suspicious.

This script takes a CSV with columns [sr, Domain, url] (or just a domain
column) and generates realistic shape variation:
  - Strips www. from a configurable fraction of domains
  - Adds occasional non-www subdomains (blog, shop, api, mail, support, app)
  - Adds realistic paths (root, single segment, nested, blog-style slugs)
  - Adds query strings to a fraction of URLs
  - Occasionally emits http:// instead of https://

Output preserves the original domain but produces diversified `url` values,
plus writes out the computed lexical features per row so you can verify
the fix worked (check that num_dots/num_subdomains/path_length distributions
are no longer degenerate) before feeding into training.

Usage:
    python diversify_url_shapes.py \
        --input safe_rebalanced_part001.csv \
        --output safe_diversified.csv \
        --seed 42
"""

import argparse
import csv
import random
from urllib.parse import urlparse

# --- Shape generation pools -------------------------------------------------

NON_WWW_SUBDOMAINS = ["blog", "shop", "api", "mail", "support", "app", "help",
                       "docs", "portal", "news", "store", "my"]

PATH_TEMPLATES = [
    "",                                  # root, no trailing content
    "/",                                 # explicit root slash
    "/about",
    "/about-us",
    "/contact",
    "/login",
    "/signup",
    "/products",
    "/products/{slug}",
    "/blog/{slug}",
    "/blog/{year}/{month}/{slug}",
    "/category/{slug}/{slug2}",
    "/support/{slug}",
    "/news/{slug}",
    "/home",
    "/features",
    "/solutions/{slug}",
    "/resources/{slug}",
    "/resources/{slug}/{slug2}",
    "/articles/{year}/{slug}",
    "/blog/{year}/{slug}",
    "/author/{slug}",
    "/tags/{slug}",
    "/download/{slug}",
    "/account",
    "/account/settings",
    "/dashboard",
    "/search",
    "/legal/{slug}",
    "/static/{slug}",
    "/wp-content/uploads/{year}/{month}/{slug}",
    "/{slug}",
    "/en/{slug}",
    "/docs/api/{slug}",
]

QUERY_TEMPLATES = [
    "",
    "?id={num}",
    "?ref={slug}",
    "?page={num}",
    "?utm_source={slug}&utm_medium=referral",
    "?q={slug}",
    "?category={slug}&sort=popular",
    "?query={slug}",
    "?search={slug}",
    "?keyword={slug}",
    "?term={slug}",
    "?s={slug}",
    "?tag={slug}",
    "?topic={slug}",
    "?author={slug}",
    "?filter={slug}",
    "?sort=newest",
    "?sort=oldest",
    "?sort=price-asc",
    "?sort=price-desc",
    "?order=desc",
    "?limit={num}",
    "?offset={num}",
    "?page={num}&per_page={num}",
    "?page={num}&limit={num}",
    "?cursor={num}",
    "?start={num}&end={num}",
    "?view={slug}",
    "?format={slug}",
    "?type={slug}",
    "?status={slug}",
    "?lang={slug}",
    "?locale={slug}",
    "?region={slug}",
    "?country={slug}",
    "?currency={slug}",
    "?plan={slug}",
    "?product={slug}",
    "?sku={num}",
    "?cart={num}",
    "?order={num}",
    "?session={num}",
    "?token={num}",
    "?referrer={slug}",
    "?source={slug}",
    "?campaign={slug}",
    "?utm_campaign={slug}&utm_content={slug}",
    "?utm_source={slug}&utm_campaign={slug}&utm_term={slug}",
    "?fbclid={num}",
    "?gclid={num}",
    "?share={slug}",
    "?redirect={slug}",
    "?next={slug}",
    "?return={slug}",
    "?callback={slug}",
    "?embed={num}",
    "?preview={num}",
    "?debug={num}",
]

SLUG_WORDS = [
    "overview", "guide", "release-notes", "getting-started", "pricing",
    "features", "team", "careers", "privacy-policy", "terms", "faq",
    "review-2026", "case-study", "update", "announcement", "tutorial",
    "best-practices", "about", "about-us", "contact", "help", "support",
    "documentation", "docs", "api", "reference", "quickstart", "faq",
    "changelog", "roadmap", "status", "security", "compliance", "trust",
    "accessibility", "sitemap", "feedback", "community", "partners",
    "integrations", "marketplace", "enterprise", "business", "developers",
    "customers", "testimonials", "success-stories", "resources", "webinars",
    "events", "ebooks", "whitepapers", "reports", "research", "insights",
    "news", "press", "media", "blog", "articles", "stories", "author",
    "category", "categories", "topics", "tag", "tags", "archive", "latest",
    "popular", "trending", "featured", "new", "sale", "offers", "deals",
    "products", "product", "catalog", "shop", "store", "cart", "checkout",
    "orders", "order-history", "account", "profile", "settings", "preferences",
    "billing", "subscription", "plans", "invoices", "login", "signin",
    "signup", "register", "logout", "forgot-password", "reset-password",
    "verify-email", "activate", "dashboard", "notifications", "messages",
    "search", "results", "filter", "sort", "compare", "download", "uploads",
    "files", "images", "video", "audio", "gallery", "preview", "print",
    "share", "embed", "terms-of-service", "cookie-policy", "legal", "licenses",
    "copyright", "refunds", "shipping", "returns", "warranty", "privacy",
    "maintenance", "error", "not-found", "success", "welcome", "hello",
]


def rand_slug(rng: random.Random) -> str:
    return rng.choice(SLUG_WORDS)


def build_path(rng: random.Random) -> str:
    template = rng.choice(PATH_TEMPLATES)
    return template.format(
        slug=rand_slug(rng),
        slug2=rand_slug(rng),
        year=rng.choice(["2024", "2025", "2026"]),
        month=f"{rng.randint(1, 12):02d}",
    )


def build_query(rng: random.Random) -> str:
    template = rng.choice(QUERY_TEMPLATES)
    return template.format(
        slug=rand_slug(rng),
        num=rng.randint(1, 9999),
    )


def diversify_domain(domain: str, rng: random.Random,
                      www_strip_prob: float,
                      subdomain_prob: float,
                      path_prob: float,
                      query_prob: float,
                      http_prob: float) -> str:
    """Given a bare domain (e.g. 'example.com'), build a realistic,
    shape-varied URL."""

    domain = domain.strip().lower()
    # Strip any existing www. so we control it explicitly below
    if domain.startswith("www."):
        domain = domain[4:]

    # Decide subdomain: none / www / other
    roll = rng.random()
    if roll < subdomain_prob:
        host = f"{rng.choice(NON_WWW_SUBDOMAINS)}.{domain}"
    elif roll < subdomain_prob + (1 - www_strip_prob):
        host = f"www.{domain}"
    else:
        host = domain  # bare domain, no subdomain at all

    scheme = "http" if rng.random() < http_prob else "https"

    path = build_path(rng) if rng.random() < path_prob else ""
    query = build_query(rng) if rng.random() < query_prob else ""

    url = f"{scheme}://{host}{path}{query}"
    return url


def extract_features(url: str) -> dict:
    """Minimal lexical feature check so you can verify the distribution
    is no longer degenerate. Not a replacement for your full feature
    extraction pipeline - just enough to sanity-check this script's output."""
    p = urlparse(url)
    host = p.netloc
    path = p.path
    labels = host.split(".")
    num_dots = host.count(".")
    num_subdomains = max(0, len(labels) - 2)
    path_length = len(path.rstrip("/"))
    has_query = bool(p.query)
    has_www = host.startswith("www.")
    return {
        "num_dots": num_dots,
        "num_subdomains": num_subdomains,
        "path_length": path_length,
        "has_query": int(has_query),
        "has_www": int(has_www),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Input CSV with a Domain column")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--domain-col", default="Domain", help="Name of the domain column (default: Domain)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--www-strip-prob", type=float, default=0.45,
                         help="Fraction of domains that should NOT get a www. prefix (default 0.45)")
    parser.add_argument("--subdomain-prob", type=float, default=0.10,
                         help="Fraction of domains that get a non-www subdomain instead (default 0.10)")
    parser.add_argument("--path-prob", type=float, default=0.55,
                         help="Fraction of URLs that get a non-empty path (default 0.55)")
    parser.add_argument("--query-prob", type=float, default=0.20,
                         help="Fraction of URLs that get a query string (default 0.20)")
    parser.add_argument("--http-prob", type=float, default=0.03,
                         help="Fraction of URLs using http instead of https (default 0.03)")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    rows_out = []
    feature_totals = {"num_dots": [], "num_subdomains": [], "path_length": [],
                       "has_query": [], "has_www": []}

    with open(args.input, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get(args.domain_col, "").strip()
            if not domain:
                continue
            new_url = diversify_domain(
                domain, rng,
                www_strip_prob=args.www_strip_prob,
                subdomain_prob=args.subdomain_prob,
                path_prob=args.path_prob,
                query_prob=args.query_prob,
                http_prob=args.http_prob,
            )
            feats = extract_features(new_url)
            for k, v in feats.items():
                feature_totals[k].append(v)

            out_row = dict(row)
            out_row["url"] = new_url
            rows_out.append(out_row)

    if not rows_out:
        print("No rows processed - check --domain-col matches your CSV header.")
        return

    fieldnames = list(rows_out[0].keys())
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    n = len(rows_out)
    print(f"Wrote {n} diversified rows to {args.output}\n")
    print("--- Post-diversification distribution check ---")
    print(f"% with www. prefix:          {100 * sum(feature_totals['has_www']) / n:.1f}%")
    print(f"% with empty path (root):    {100 * sum(1 for x in feature_totals['path_length'] if x == 0) / n:.1f}%")
    print(f"% with query string:         {100 * sum(feature_totals['has_query']) / n:.1f}%")
    print(f"% with num_subdomains == 0:  {100 * sum(1 for x in feature_totals['num_subdomains'] if x == 0) / n:.1f}%")
    print(f"% with num_dots == 1:        {100 * sum(1 for x in feature_totals['num_dots'] if x == 1) / n:.1f}%")
    print("\nIf these percentages are all still 0%, something's wrong - re-check the domain column name.")


if __name__ == "__main__":
    main()
