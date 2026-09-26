#!/usr/bin/env python3
"""
Pulls the latest releases (exploits, advisories, tools, papers) from
PacketStorm Security's official RSS feed. This is a separate feed from
the CVE/KEV/Exploit-DB data — PacketStorm entries aren't reliably
tagged with clean CVE IDs in their titles, so this is kept as its own
"latest security releases" list rather than cross-referenced by CVE.
"""
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

FEED_URL = "https://rss.packetstormsecurity.com/files/"
OUTPUT_PATH = "data/packetstorm.json"
MAX_ITEMS = 100


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def guess_category(title):
    t = title.lower()
    if "advisory" in t:
        return "advisory"
    if any(k in t for k in ("exploit", "poc", "rce", "overflow", "injection")):
        return "exploit"
    if "whitepaper" in t or "paper" in t:
        return "paper"
    return "tool"


def main():
    xml_text = fetch_text(FEED_URL)
    root = ET.fromstring(xml_text)

    items = []
    for item in root.findall(".//item")[:MAX_ITEMS]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date_raw = item.findtext("pubDate") or ""
        try:
            pub_date = parsedate_to_datetime(pub_date_raw).isoformat()
        except Exception:
            pub_date = None

        # opportunistic CVE extraction, only shown if present — not guaranteed
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title, re.IGNORECASE)

        items.append({
            "title": title,
            "link": link,
            "published": pub_date,
            "category": guess_category(title),
            "cve_ref": cve_match.group(0).upper() if cve_match else None,
        })

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} PacketStorm items.")


if __name__ == "__main__":
    main()
