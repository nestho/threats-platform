#!/usr/bin/env python3
"""
Active phishing URLs from the OpenPhish public feed (free, no key).

OpenPhish publishes a plain-text snapshot of URLs that are live right now; it
carries no timestamps, so the feed records `collected_at` rather than inventing
a first-seen date. Every URL is defanged before publication: the site is a
threat feed, not a link shortener for credential harvesters.

Source: https://openphish.com/feed.txt (302 -> GitHub raw)
"""
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

from feed_io import DATA_DIR, defang, envelope, is_http_url, now_iso, refang, stable_id, write_json

FEED_URL = "https://openphish.com/feed.txt"
OUTPUT_PATH = DATA_DIR / "phishing.json"
MAX_ITEMS = 300


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "threats-top-collector", "Accept": "text/plain"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def build_items(text, collected_at):
    items = []
    seen = set()
    for line in text.splitlines():
        url = line.strip()
        if not is_http_url(url) or url in seen:
            continue
        seen.add(url)
        host = (urlparse(url).hostname or "").lower()
        items.append({
            "id": stable_id("ph", url),
            "url_defanged": defang(url),
            "host": host,
            "collected_at": collected_at,
        })
        if len(items) >= MAX_ITEMS:
            break
    return items


def main():
    collected_at = now_iso()
    text = fetch_text(FEED_URL)
    items = build_items(text, collected_at)

    document = envelope(
        "OpenPhish",
        FEED_URL,
        note="Snapshot of URLs OpenPhish listed as active phishing at collection time. URLs are defanged.",
        total=len(items),
        items=items,
    )
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(items)} defanged phishing URLs.")
    if not items:
        print("::error::OpenPhish returned no usable URLs; refusing to publish an empty feed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
