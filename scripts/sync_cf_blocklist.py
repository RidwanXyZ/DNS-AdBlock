#!/usr/bin/env python3
"""
Sync Hagezi adblock lists -> Cloudflare Gateway custom list(s).

Usage examples:
  # dry-run (show counts + sample)
  API_TOKEN=xxx ACCOUNT_ID=yyy LIST_ID=zzz python scripts/sync_cf_blocklist.py --config config/sources.json --dry-run

  # push combined list
  API_TOKEN=xxx ACCOUNT_ID=yyy LIST_ID=zzz python scripts/sync_cf_blocklist.py --config config/sources.json

  # push split per-category (requires env LIST_ID_<CATEGORY> e.g. LIST_ID_GAMBLING)
  API_TOKEN=xxx ACCOUNT_ID=yyy python scripts/sync_cf_blocklist.py --config config/sources.json --split

Notes:
- Combined mode: requires LIST_ID env.
- Split mode: requires LIST_ID_<CATEGORY> env (uppercase category), or fallback to LIST_ID.
"""

import os
import sys
import json
import re
import time
import argparse
from typing import List, Set, Dict

import requests
from tqdm import tqdm

# --- Constants
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE
)
MAX_CF_BATCH = 1000

# --- Helpers


def is_valid_domain(s: str) -> bool:
    s = s.strip().lower()
    if len(s) > 253 or ".." in s:
        return False
    return bool(DOMAIN_RE.match(s))


def sanitize_token_part(s: str) -> str:
    # Remove leading wildcards, protocols, ports
    s = s.strip()
    s = re.sub(r"^\*+\.", "", s)
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"/:.*$", "", s)
    s = s.split("/")[0]
    s = s.split(":")[0]
    s = s.strip().lower()
    return s


def parse_adblock_lines(lines: List[str]) -> List[str]:
    domains = []
    for raw in lines:
        if not raw:
            continue
        line = raw.strip()
        if (
            not line
            or line.startswith("!")
            or line.startswith("#")
            or line.startswith("[")
        ):
            continue

        # common pattern: ||domain.tld^
        if line.startswith("||") and "^" in line:
            token = line[2:].split("^", 1)[0]
            token = token.lstrip("*.")
            token = sanitize_token_part(token)
            if is_valid_domain(token):
                domains.append(token)
            continue

        # host-like lines (domain or subdomain)
        # drop rules that contain '/', '?' or '=' as they are path rules
        if (
            "/" not in line
            and "^" not in line
            and " " not in line
            and not line.startswith("/")
        ):
            token = line
            # strip possible wildcard/prefix
            token = token.lstrip("*.")
            token = sanitize_token_part(token)
            if is_valid_domain(token):
                domains.append(token)
            continue

        # fallback: try to extract host part from a URL-like or rule
        # e.g. AdBlock exceptions or other syntaxes
        m = re.search(r"([a-z0-9.-]+\.[a-z]{2,63})", line, re.IGNORECASE)
        if m:
            token = sanitize_token_part(m.group(1))
            if is_valid_domain(token):
                domains.append(token)

    return domains


# --- Cloudflare API helpers


def cf_delete_all_items(account_id: str, list_id: str, headers: Dict[str, str]):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/lists/{list_id}/items"
    r = requests.delete(url, headers=headers, timeout=30)
    return r


def cf_post_batch(
    account_id: str, list_id: str, headers: Dict[str, str], items: List[str]
):
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/lists/{list_id}/items"
    payload = {"items": [{"value": v} for v in items]}
    for attempt in range(4):
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        if r.status_code in (200, 201):
            return r
        wait = (2**attempt) + 0.5
        print(f"[WARN] Batch upload failed status={r.status_code}. Retrying in {wait}s")
        time.sleep(wait)
    # final attempt
    r.raise_for_status()


# --- Main flow


def fetch_url(url: str, timeout: int = 30) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def prepare_domains_from_sources(sources: Dict[str, str]) -> Dict[str, Set[str]]:
    category_map = {}
    for name, url in sources.items():
        try:
            print(f"[*] Fetching {name} -> {url}")
            txt = fetch_url(url)
            domains = parse_adblock_lines(txt.splitlines())
            domains_set = set(domains)
            print(f"  -> parsed {len(domains_set)} domains for {name}")
            category_map[name] = domains_set
        except Exception as e:
            print(f"[ERROR] fetching/parsing {name}: {e}")
            category_map[name] = set()
    return category_map


def push_combined(
    account_id: str, list_id: str, headers: Dict[str, str], all_domains: List[str]
):
    print(f"[INFO] Deleting current items on list {list_id} ...")
    d = cf_delete_all_items(account_id, list_id, headers)
    print(f"  delete status: {d.status_code}")

    print(f"[INFO] Uploading {len(all_domains)} domains in batches of {MAX_CF_BATCH}")
    for i in range(0, len(all_domains), MAX_CF_BATCH):
        batch = all_domains[i : i + MAX_CF_BATCH]
        cf_post_batch(account_id, list_id, headers, batch)
        print(f"  uploaded batch {i // MAX_CF_BATCH + 1} ({len(batch)} items)")


def push_split(
    account_id: str,
    headers: Dict[str, str],
    category_map: Dict[str, Set[str]],
    default_list_id: str = None,
):
    for cat, domains in category_map.items():
        env_name = f"LIST_ID_{cat.upper()}"
        list_id = os.getenv(env_name) or default_list_id
        if not list_id:
            print(
                f"[WARN] No LIST_ID provided for category '{cat}' (env {env_name} or default). Skipping"
            )
            continue
        domain_list = sorted(domains)
        print(
            f"[INFO] Pushing {len(domain_list)} domains to list {list_id} (category {cat})"
        )
        d = cf_delete_all_items(account_id, list_id, headers)
        print(f"  delete status: {d.status_code}")
        for i in range(0, len(domain_list), MAX_CF_BATCH):
            batch = domain_list[i : i + MAX_CF_BATCH]
            cf_post_batch(account_id, list_id, headers, batch)
            print(f"  uploaded batch {i // MAX_CF_BATCH + 1} ({len(batch)} items)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config/sources.json")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--split",
        action="store_true",
        help="Push per-category lists. Requires LIST_ID_<CATEGORY> env vars or default LIST_ID",
    )
    args = p.parse_args()

    api_token = os.getenv("API_TOKEN") or os.getenv("CF_API_TOKEN")
    account_id = os.getenv("ACCOUNT_ID") or os.getenv("CF_ACCOUNT_ID")
    list_id = os.getenv("LIST_ID") or os.getenv("CF_LIST_ID")

    if not api_token or not account_id:
        print("[ERROR] API_TOKEN and ACCOUNT_ID are required environment variables")
        sys.exit(2)

    # Load config
    try:
        cfg = json.load(open(args.config))
    except Exception as e:
        print(f"[ERROR] failed to read config: {e}")
        sys.exit(2)

    sources = cfg.get("sources", {})
    category_map = prepare_domains_from_sources(sources)

    # Merge all domains
    all_domains_set = set()
    for s in category_map.values():
        all_domains_set.update(s)
    all_domains = sorted(all_domains_set)

    print(f"[INFO] Total unique domains merged: {len(all_domains)}")
    sample = all_domains[:40]

    if args.dry_run:
        print("[DRY-RUN] Sample domains:")
        for d in sample:
            print("  -", d)
        print("[DRY-RUN] done. No changes pushed.")
        return

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    if args.split:
        push_split(account_id, headers, category_map, default_list_id=list_id)
    else:
        if not list_id:
            print("[ERROR] LIST_ID is required when not using --split")
            sys.exit(2)
        push_combined(account_id, list_id, headers, all_domains)

    print("[DONE] Sync complete")


if __name__ == "__main__":
    main()