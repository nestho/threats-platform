#!/usr/bin/env python3
"""
Pulls the latest GitHub Security Advisories (GHSA) — official, free,
no-key Atom feed covering vulnerabilities in open-source packages
(npm, PyPI, RubyGems, Go modules, etc). Complements NVD/KEV, which
skew toward enterprise/OS-level CVEs, with the software-supply-chain
angle.
"""
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

FEED_URL = "https://github.com/security-advisories.atom"
OUTPUT_PATH = "data/ghsa.json"
MAX_ITEMS = 100

ATOM_NS = "{http://www.w3.org/2005/Atom}"


def fetch_text(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "threats-top-collector",
            "Accept": "application/atom+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def strip_html(text):
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def main():
    xml_text = fetch_text(FEED_URL)
    root = ET.fromstring(xml_text)

    items = []
    for entry in root.findall(f"{ATOM_NS}entry")[:MAX_ITEMS]:
        entry_id = entry.findtext(f"{ATOM_NS}id") or ""
        ghsa_match = re.search(r"GHSA-[a-z0-9\-]+", entry_id)
        title = (entry.findtext(f"{ATOM_NS}title") or "").strip()
        published = entry.findtext(f"{ATOM_NS}published") or ""
        content = strip_html(entry.findtext(f"{ATOM_NS}content") or "")[:300]

        link_el = entry.find(f"{ATOM_NS}link")
        link = link_el.get("href") if link_el is not None else ""

        category_el = entry.find(f"{ATOM_NS}category")
        ecosystem = category_el.get("term") if category_el is not None else None

        items.append({
            "id": ghsa_match.group(0) if ghsa_match else entry_id,
            "title": title,
            "published": published,
            "ecosystem": ecosystem,
            "summary": content,
            "link": link,
        })

    items.sort(key=lambda x: x["published"] or "", reverse=True)

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} GitHub Security Advisories.")


if __name__ == "__main__":
    main()
