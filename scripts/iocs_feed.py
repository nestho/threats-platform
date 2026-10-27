#!/usr/bin/env python3
"""
Derived IOC feed: one flat list of indicators the other feeds already published.

This replaces the old `sensors.json`, which mixed three different upstreams
(Feodo, SANS DShield, URLhaus) behind one timestamp. Two of those sources had
started returning errors, and the collector papered over it by re-stamping the
old payload with a fresh `updated_at` -- the file looked current while its
content was days old. Here every indicator points back at the feed it came
from, and that feed's own timestamp is the freshness evidence.

Included:
  * OpenPhish URLs, defanged, active at collection time
  * ransomware.live victim domains (labels, not attacker infrastructure)

Not included: Feodo C2 / ThreatFox / URLhaus, which require an abuse.ch
Auth-Key and are disabled in v1.
"""
import json
import re
import sys

from feed_io import DATA_DIR, envelope, now_iso, stable_id, write_json

PHISHING_PATH = DATA_DIR / "phishing.json"
RANSOMWARE_PATH = DATA_DIR / "ransomware.json"
OUTPUT_PATH = DATA_DIR / "iocs.json"
MAX_ITEMS = 500
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def load(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::warning::{path.name} unreadable: {exc}", file=sys.stderr)
        return None
    return document


def main():
    phishing = load(PHISHING_PATH)
    ransomware = load(RANSOMWARE_PATH)
    if phishing is None and ransomware is None:
        print("::error::no upstream feed available to derive iocs.json", file=sys.stderr)
        return 1

    items = []
    seen = set()

    for row in (phishing or {}).get("items", []):
        value = row.get("url_defanged")
        if not value or ("url", value) in seen:
            continue
        seen.add(("url", value))
        collected = row.get("collected_at") or (phishing or {}).get("updated_at")
        items.append({
            "id": stable_id("ioc", "url", value),
            "type": "url",
            "value": value,
            "source": "OpenPhish",
            "context": "active phishing URL",
            "severity": "HIGH",
            "first_seen": collected,
            "last_seen": collected,
            "link": "https://openphish.com/",
        })

    for row in (ransomware or {}).get("items", []):
        domain = (row.get("domain") or "").strip().lower().rstrip(".")
        if not HOSTNAME.match(domain) or ("domain", domain) in seen:
            continue
        seen.add(("domain", domain))
        items.append({
            "id": stable_id("ioc", "domain", domain),
            "type": "domain",
            "value": domain,
            "source": "ransomware.live",
            "context": "victim domain named on a ransomware leak site",
            "severity": "MEDIUM",
            "first_seen": row.get("published"),
            "last_seen": row.get("published"),
            "link": row.get("link") or "https://www.ransomware.live/",
        })

    items.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
    items = items[:MAX_ITEMS]

    document = envelope(
        "Derived from OpenPhish and ransomware.live",
        [
            "https://openphish.com/feed.txt",
            "https://api.ransomware.live/v2/recentvictims",
        ],
        generated_at=now_iso(),
        total=len(items),
        items=items,
    )
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(items)} indicators.")
    if not items:
        print("::error::derived IOC feed is empty; refusing to publish", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
