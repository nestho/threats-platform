#!/usr/bin/env python3
"""
Pulls the latest GitHub Security Advisories (GHSA) — official, free, no key.

Uses GitHub's public `/advisories` REST endpoint rather than the older Atom
feed. The Atom feed (`github.com/security-advisories.atom`) returned HTTP 502
from GitHub itself during the 2026-10-27 rebuild, while the REST endpoint was
healthy and carries the same records plus a structured ecosystem field.

The endpoint is public but rate-limited per IP (60 requests/hour). One request
per run stays far below that; when a `GITHUB_TOKEN` is present in the
environment it is used to raise the limit.

Source: https://api.github.com/advisories?per_page=100&sort=published
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

from feed_io import write_json
from normalize import NormalisationTally

API_URL = "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"
OUTPUT_PATH = "data/ghsa.json"
SCHEMA_VERSION = 2
MAX_ITEMS = 100


def fetch_json(url, *, attempts=4):
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    last_error = None
    for attempt in range(1, attempts + 1):
        headers = {
            "User-Agent": "threats-top-collector",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = 5 * (2 ** (attempt - 1))
            print(f"  fetch failed ({exc}); retry {attempt}/{attempts - 1} in {delay}s")
            time.sleep(delay)
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def first_ecosystem(advisory):
    for vulnerability in advisory.get("vulnerabilities") or []:
        package = vulnerability.get("package") or {}
        ecosystem = package.get("ecosystem")
        if ecosystem:
            return ecosystem
    return None


def build_items(raw, tally):
    items = []
    for advisory in raw[:MAX_ITEMS]:
        ghsa_id = advisory.get("ghsa_id")
        if not ghsa_id:
            continue
        items.append({
            "id": ghsa_id,
            "title": (advisory.get("summary") or "").strip(),
            "published": tally.iso(advisory.get("published_at"), field="items[].published"),
            "ecosystem": first_ecosystem(advisory),
            "summary": (advisory.get("description") or "").strip()[:300],
            "link": advisory.get("html_url") or "",
        })
    items.sort(key=lambda item: item["published"] or "", reverse=True)
    return items


def main() -> int:
    raw = fetch_json(API_URL)
    if not isinstance(raw, list):
        print("::error::GitHub advisories API returned a non-list payload", file=sys.stderr)
        return 1

    tally = NormalisationTally("ghsa")
    items = build_items(raw, tally)
    tally.raise_if_exceeded()

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "GitHub Security Advisories",
        "source_url": "https://api.github.com/advisories",
        "total": len(items),
        "normalisation_failures": tally.failures,
        "items": items,
    }
    write_json(OUTPUT_PATH, output)

    print(f"Wrote {len(items)} GitHub Security Advisories.")
    if not items:
        print("::error::GHSA feed parsed to zero items -- refusing to publish an empty feed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
