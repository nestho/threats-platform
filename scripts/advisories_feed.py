#!/usr/bin/env python3
"""
Vendor security advisories from two official, free, no-key feeds:

  * Microsoft Security Update Guide (MSRC) RSS
  * Ubuntu Security Notices

CISA's advisory RSS is the third source we wanted, but www.cisa.gov was not
reachable from the build environment, so it is deliberately not listed as a
source rather than being a feed that can never publish. CISA KEV still reaches
the site through the CVE feed via its official GitHub mirror.

Source sizes are asymmetrical (MSRC publishes thousands of CVE update rows,
Ubuntu dozens of notices), so each is capped separately. A single global cap
would let MSRC crowd Ubuntu out of every snapshot.
"""
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from feed_io import DATA_DIR, envelope, stable_id, strip_html, truncate, write_json
from normalize import NormalisationTally

SOURCES = [
    {
        "vendor": "Microsoft",
        "url": "https://api.msrc.microsoft.com/update-guide/rss",
        "cap": 60,
    },
    {
        "vendor": "Ubuntu",
        "url": "https://ubuntu.com/security/notices/rss.xml",
        "cap": 40,
    },
]
OUTPUT_PATH = DATA_DIR / "advisories.json"
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
USN_ID = re.compile(r"USN-\d+-\d+", re.IGNORECASE)


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "threats-top-collector", "Accept": "application/rss+xml, application/xml"},
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def advisory_id(vendor, title, link):
    match = USN_ID.search(title or "") or USN_ID.search(link or "")
    if match:
        return match.group(0).upper()
    match = CVE_ID.search(title or "") or CVE_ID.search(link or "")
    if match:
        return match.group(0).upper()
    return stable_id("adv", vendor, link or title)


def parse_feed(vendor, raw, cap, tally):
    root = ET.fromstring(raw)
    items = []
    for entry in root.findall(".//item")[:cap]:
        title = truncate(strip_html(entry.findtext("title") or ""), 300)
        link = (entry.findtext("link") or "").strip()
        summary = truncate(strip_html(entry.findtext("description") or ""), 300)
        published = tally.iso(entry.findtext("pubDate") or "", field="items[].published")
        if not title:
            continue
        items.append({
            "id": advisory_id(vendor, title, link),
            "vendor": vendor,
            "title": title,
            "published": published,
            "summary": summary or title,
            "link": link,
        })
    return items


def main():
    tally = NormalisationTally("advisories")
    items = []
    failures = []
    for source in SOURCES:
        try:
            raw = fetch_text(source["url"])
            parsed = parse_feed(source["vendor"], raw, source["cap"], tally)
        except (RuntimeError, ET.ParseError) as exc:
            failures.append(f"{source['vendor']}: {exc}")
            print(f"::warning::advisory source {source['vendor']} failed: {exc}", file=sys.stderr)
            continue
        print(f"  {source['vendor']}: {len(parsed)} advisories")
        items.extend(parsed)

    if not items:
        print(f"::error::no advisory source produced data ({'; '.join(failures)})", file=sys.stderr)
        return 1

    tally.raise_if_exceeded()

    deduped = {}
    for item in items:
        deduped.setdefault(item["id"], item)
    items = list(deduped.values())
    items.sort(key=lambda item: item["published"] or "", reverse=True)

    document = envelope(
        "Microsoft MSRC + Ubuntu Security Notices",
        [source["url"] for source in SOURCES],
        total=len(items),
        normalisation_failures=tally.failures,
        partial=failures or None,
        items=items,
    )
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(items)} advisories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
