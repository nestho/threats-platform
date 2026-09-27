#!/usr/bin/env python3
"""
Pulls the latest Security Advisories from CERT-EU (official EU institutions CERT).
Free RSS, no key required. High-signal, actionable advisories.
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

FEED_URL = "https://cert.europa.eu/publications/security-advisories-rss"
OUTPUT_PATH = "data/cert_eu.json"
SCHEMA_VERSION = 2
MAX_ITEMS = 50
ADVISORY_BASE = "https://cert.europa.eu/publications/security-advisories"


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "threats-top-collector",
                "Accept": "application/rss+xml, application/xml, text/xml, text/html",
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


def build_item(advisory_id, title_clean, link, description, pub_date, tally):
    """One shape for both the XML path and the regex fallback."""
    return {
        "id": advisory_id,
        "title": title_clean,
        # CERT-EU publishes RFC-2822 with a CEST offset, which a JavaScript Date
        # constructor cannot parse -- every item rendered as an em-dash and the
        # homepage's recent-activity sort comparator returned NaN. Normalised here
        # so the browser never sees a format it has to guess at.
        "published": tally.iso(pub_date, field="items[].published") if pub_date else None,
        "summary": strip_html(description)[:400] if description else title_clean,
        "link": link or (f"{ADVISORY_BASE}/{advisory_id}/" if advisory_id else ""),
    }


def strip_html(text):
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def main() -> int:
    raw = fetch_text(FEED_URL)

    # CERT-EU sometimes returns a minimal HTML-ish page or a real RSS.
    # Try parsing as XML first; fall back to simple regex extraction if needed.
    tally = NormalisationTally("cert_eu")
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

            items.append(build_item(advisory_id or guid, title_clean, link, description, pub_date, tally))
    except ET.ParseError:
        # Fallback: page is not pure RSS (sometimes returns a plain list).
        # Extract titles that match CERT-EU advisory pattern.
        #
        # This path cannot distinguish "upstream changed shape" from "upstream
        # served us an error page", and both produce zero matches. The empty-feed
        # guard in main() is what stops the second case being published.
        print("  CERT-EU response was not valid XML; using regex fallback")
        pattern = re.compile(
            r"(\d{4}-\d{3}):\s*([^\n<]+?)(?:\s{2,}|$)",
            re.MULTILINE,
        )
        for match in pattern.finditer(raw):
            if len(items) >= MAX_ITEMS:
                break
            advisory_id = match.group(1)
            title_clean = match.group(2).strip()
            items.append(build_item(advisory_id, title_clean, "", "", "", tally))

    tally.raise_if_exceeded()

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(items),
        "normalisation_failures": tally.failures,
        "items": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} CERT-EU advisories.")
    if not items:
        print(
            "::error::CERT-EU feed parsed to zero items. Upstream may have served an "
            "error page or changed shape. Refusing to publish an empty feed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
