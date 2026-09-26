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
import urllib.request
from datetime import datetime, timezone

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OUTPUT_PATH = "data/urlhaus.json"
MAX_ITEMS = 200


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def defang(url):
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def main():
    raw = fetch_text(FEED_URL)
    # The feed has '#'-prefixed comment lines before the real CSV header/rows
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    reader = csv.reader(lines)

    items = []
    for row in reader:
        if len(row) < 6:
            continue
        # columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        entry_id, date_added, url, url_status, _, threat = row[:6]
        tags = row[6] if len(row) > 6 else ""
        items.append({
            "id": entry_id.strip('"'),
            "date_added": date_added.strip('"'),
            "url_defanged": defang(url.strip('"')),
            "status": url_status.strip('"'),
            "threat": threat.strip('"'),
            "tags": tags.strip('"'),
        })
        if len(items) >= MAX_ITEMS:
            break

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "note": "URLs are defanged (hxxp, [.]) — this is intentional, not a formatting error.",
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} URLhaus entries.")


if __name__ == "__main__":
    main()
