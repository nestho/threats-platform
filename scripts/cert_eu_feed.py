#!/usr/bin/env python3
"""
Pulls the latest Security Advisories from CERT-EU (official EU institutions CERT).
Free RSS, no key required. High-signal, actionable advisories.
"""
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

FEED_URL = "https://cert.europa.eu/publications/security-advisories-rss"
OUTPUT_PATH = "data/cert_eu.json"
MAX_ITEMS = 50


def fetch_text(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "threats-top-collector",
            "Accept": "application/rss+xml, application/xml, text/xml, text/html",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main():
    raw = fetch_text(FEED_URL)

    # CERT-EU sometimes returns a minimal HTML-ish page or a real RSS.
    # Try parsing as XML first; fall back to simple regex extraction if needed.
    items = []

    try:
        root = ET.fromstring(raw)
        for item in root.findall(".//item")[:MAX_ITEMS]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            description = (item.findtext("description") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            guid = (item.findtext("guid") or link).strip()

            # CERT-EU titles look like "2026-013: Critical Vulnerability in F5 BIG-IP APM"
            advisory_id = None
            m = re.match(r"(\d{4}-\d{3})\s*:\s*(.*)", title)
            if m:
                advisory_id = m.group(1)
                title_clean = m.group(2).strip()
            else:
                title_clean = title

            items.append({
                "id": advisory_id or guid,
                "title": title_clean,
                "published": pub_date,
                "summary": description[:400] if description else title_clean,
                "link": link or f"https://cert.europa.eu/publications/security-advisories/{advisory_id}/" if advisory_id else "",
            })
    except ET.ParseError:
        # Fallback: page is not pure RSS (sometimes returns a plain list).
        # Extract titles that match CERT-EU advisory pattern.
        pattern = re.compile(
            r"(\d{4}-\d{3}):\s*([^\n<]+?)(?:\s{2,}|$)",
            re.MULTILINE,
        )
        for match in pattern.finditer(raw):
            if len(items) >= MAX_ITEMS:
                break
            advisory_id = match.group(1)
            title_clean = match.group(2).strip()
            items.append({
                "id": advisory_id,
                "title": title_clean,
                "published": "",
                "summary": title_clean,
                "link": f"https://cert.europa.eu/publications/security-advisories/{advisory_id}/",
            })

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} CERT-EU advisories.")


if __name__ == "__main__":
    main()
