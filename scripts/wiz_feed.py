#!/usr/bin/env python3
"""
Wiz Cloud Threat Landscape — cloud security incidents, campaigns and research.

Why this source exists
----------------------
Every other feed on this platform is a vulnerability or exploit feed: NVD, KEV,
Exploit-DB, CERT-EU, GHSA, URLhaus. Between them they cover what is *vulnerable*
and what is being *exploited in malware distribution*. None of them cover what
actually happened: which identity was abused, which CI/CD system was compromised,
which supply-chain package was hijacked. Wiz publishes exactly that, and it was
the largest content gap on the site.

Cadence warning
---------------
This is an *analysis* feed, not an alert feed. Measured over the 509-item feed:
0 items in the last 7 days, 3 in the last 30, 47 in 180, 83 in 365. Publishing
that volume on the same hourly cadence as the CVE feeds would imply a freshness
this source does not have, so it runs weekly and is labelled as analysis
everywhere it appears. See docs/DEEP-ANALYSIS.md.

Wiz was acquired by Google in 2025, so this is a single-vendor feed with a
single-vendor failure mode -- the same fragility class as the other RSS sources in
ARCHITECTURE.md 7.4. If it goes quiet, the weekly run will fail loudly rather
than silently emptying, which is the point of the empty-feed guard.

SCHEMA VERSION 1 (2026-09-27) — new feed.
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from normalize import NormalisationTally

FEED_URL = "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml"
OUTPUT_PATH = "data/wiz.json"
SCHEMA_VERSION = 1
MAX_ITEMS = 200

# Titles are suffixed with their classification, e.g.
#   "Coder Module Registry Compromise ... (Incident)"
#   "@scope/pkg Compromised in Supply Chain Attack (Campaign)"
# There are no <category> elements in this feed, so the suffix is the only
# classification available and it is worth keeping.
TITLE_TYPE = re.compile(r"\((Incident|Campaign|Research|Vulnerability|Malware|Threat Actor)\)\s*$", re.IGNORECASE)

VALID_TYPES = {"incident", "campaign", "research", "vulnerability", "malware", "threat actor"}


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "threats-top-collector",
                "Accept": "application/rss+xml, application/xml, text/xml",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = 5 * (2 ** (attempt - 1))
            print(f"  fetch failed ({exc}); retry {attempt}/{attempts - 1} in {delay}s")
            time.sleep(delay)
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def strip_html(text):
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def classify(title):
    """Pull the classification out of the title suffix and clean the title."""
    match = TITLE_TYPE.search(title or "")
    if not match:
        return (title or "").strip(), None
    return title[: match.start()].strip(), match.group(1).lower()


def main() -> int:
    tally = NormalisationTally("wiz")
    raw = fetch_text(FEED_URL)
    root = ET.fromstring(raw)

    items = []
    for entry in root.findall(".//item")[:MAX_ITEMS]:
        raw_title = (entry.findtext("title") or "").strip()
        title, kind = classify(raw_title)
        guid = (entry.findtext("guid") or "").strip()
        link = (entry.findtext("link") or "").strip()
        description = (entry.findtext("description") or "").strip()
        pub_date = (entry.findtext("pubDate") or "").strip()
        author = (entry.findtext("author") or "").strip()

        if kind is not None and kind not in VALID_TYPES:
            kind = None

        items.append({
            # guid is a stable UUID; the title is not (titles get edited), and a
            # content-addressed id is what makes this feed diffable over time.
            "id": guid or link or title,
            "title": title,
            "type": kind,
            "published": tally.iso(pub_date, field="items[].published"),
            "summary": strip_html(description)[:400],
            "author": author or None,
            "link": link,
        })

    tally.raise_if_exceeded()

    # Newest first, with undated items last rather than first.
    items.sort(key=lambda x: x["published"] or "", reverse=True)

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "Wiz Research — Cloud Threat Landscape",
        "cadence": "weekly",
        "note": "Analysis feed, not an alert feed. Wiz publishes roughly monthly.",
        "total": len(items),
        "normalisation_failures": tally.failures,
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    kinds = {}
    for item in items:
        kinds[item["type"] or "unclassified"] = kinds.get(item["type"] or "unclassified", 0) + 1
    print(f"Wrote {len(items)} Wiz items ({kinds}).")
    if not items:
        print("::error::Wiz feed parsed to zero items -- refusing to publish an empty feed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
