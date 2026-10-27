#!/usr/bin/env python3
"""
Recent ransomware victim claims from ransomware.live (free, no key).

Published records are headline-level intelligence: victim, group, sector,
country, claim date and a link to the public claim page. Attacker-supplied
descriptions are truncated and stripped of markup. The feed is a claim feed,
not confirmation that an attack succeeded; the UI labels it that way.

Source: https://api.ransomware.live/v2/recentvictims (v2, JSON array)
"""
import json
import sys
import urllib.error
import urllib.request

from feed_io import DATA_DIR, envelope, is_http_url, stable_id, strip_html, truncate, write_json
from normalize import NormalisationTally

API_URL = "https://api.ransomware.live/v2/recentvictims"
OUTPUT_PATH = DATA_DIR / "ransomware.json"
MAX_ITEMS = 100


def fetch_json(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "threats-top-collector", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def clean_url(value):
    return value.strip() if is_http_url(value) else None


def build_items(raw, tally):
    items = []
    seen = set()
    for entry in raw[:MAX_ITEMS]:
        if not isinstance(entry, dict):
            continue
        victim = truncate(strip_html(entry.get("victim") or entry.get("domain") or ""), 200)
        group = truncate(strip_html(entry.get("group") or ""), 100)
        if not victim:
            continue
        attackdate = entry.get("attackdate")
        discovered = entry.get("discovered")
        published = tally.iso(discovered or attackdate, field="items[].published")
        item_id = stable_id("rw", group, victim, attackdate)
        if item_id in seen:
            continue
        seen.add(item_id)
        items.append({
            "id": item_id,
            "victim": victim,
            "domain": truncate(strip_html(entry.get("domain") or ""), 255).lower() or None,
            "group": group or None,
            "activity": truncate(strip_html(entry.get("activity") or ""), 120) or None,
            "country": truncate(strip_html(entry.get("country") or ""), 80) or None,
            "published": published,
            "discovered": tally.iso(discovered, field="items[].discovered") if discovered else None,
            "description": truncate(strip_html(entry.get("description") or ""), 400),
            "claim_url": clean_url(entry.get("claim_url")),
            "link": clean_url(entry.get("url")),
            "screenshot": clean_url(entry.get("screenshot")),
        })
    items.sort(key=lambda item: item["published"] or "", reverse=True)
    return items


def main():
    raw = fetch_json(API_URL)
    if not isinstance(raw, list):
        print("::error::ransomware.live returned a non-list payload", file=sys.stderr)
        return 1

    tally = NormalisationTally("ransomware")
    items = build_items(raw, tally)
    tally.raise_if_exceeded()

    document = envelope(
        "ransomware.live",
        API_URL,
        note="Victim claims published by ransomware leak sites. A claim is not confirmation of a successful attack.",
        total=len(items),
        normalisation_failures=tally.failures,
        items=items,
    )
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(items)} ransomware claims.")
    if not items:
        print("::error::no ransomware claims parsed; refusing to publish an empty feed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
