#!/usr/bin/env python3
"""
Pulls recently added malicious URLs from URLhaus (abuse.ch) — a
well-established, official threat-intel source tracking active malware
distribution URLs. Free CSV export, no API key required.

SECURITY: every URL here is defanged (http -> hxxp, . -> [.]) before
being written out. These are live malware-distribution links; showing
them as clickable, non-defanged URLs on a public web page would be
irresponsible and could lead to accidental infections. Defanging is
standard practice in threat-intel reporting for exactly this reason.
"""
import csv
import io
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from normalize import NormalisationTally

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OUTPUT_PATH = "data/urlhaus.json"
SCHEMA_VERSION = 2
MAX_ITEMS = 200


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
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


def defang(url):
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def main() -> int:
    raw = fetch_text(FEED_URL)
    # The feed has '#'-prefixed comment lines before the real CSV header/rows
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    reader = csv.reader(lines)

    tally = NormalisationTally("urlhaus")
    items = []
    for row in reader:
        if len(row) < 6:
            continue
        # columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        entry_id, date_added, url, url_status, _, threat = row[:6]
        tags = row[6] if len(row) > 6 else ""
        items.append({
            "id": entry_id.strip('"'),
            # abuse.ch publishes "YYYY-MM-DD HH:MM:SS" in UTC without saying so.
            "date_added": tally.iso(date_added, field="items[].date_added"),
            "url_defanged": defang(url.strip('"')),
            "status": url_status.strip('"'),
            "threat": threat.strip('"'),
            "tags": tags.strip('"'),
        })
        if len(items) >= MAX_ITEMS:
            break

    tally.raise_if_exceeded()

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(items),
        "normalisation_failures": tally.failures,
        "note": "URLs are defanged (hxxp, [.]) — this is intentional, not a formatting error.",
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} URLhaus entries.")
    if not items:
        print("::error::URLhaus feed parsed to zero items -- refusing to publish an empty feed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
