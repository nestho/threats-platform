#!/usr/bin/env python3
"""
EPSS exploitation-probability scores for the CVEs this site already publishes.

FIRST's API is free and keyless, but accepts a bounded number of CVE IDs per
request. We rank the recent NVD window and KEV entries first (KEV, then CVSS
score, then recency) and ask for the top 100, which is the slice a reader can
act on. The full EPSS dataset is deliberately not mirrored.

Source: https://api.first.org/data/v1/epss
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from feed_io import DATA_DIR, envelope, write_json

CVES_PATH = DATA_DIR / "cves.json"
OUTPUT_PATH = DATA_DIR / "epss.json"
API_URL = "https://api.first.org/data/v1/epss"
MAX_CVES = 100


def fetch_json(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "threats-top-collector", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def candidate_cves():
    try:
        document = json.loads(CVES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {CVES_PATH.name}: {exc}") from exc

    recent = ((document.get("recent") or {}).get("items")) or []
    kev = ((document.get("actively_exploited") or {}).get("items")) or []
    ranked = sorted(
        (item for item in recent if item.get("id")),
        key=lambda item: (
            bool(item.get("kev")),
            item.get("score") or 0,
            item.get("published") or "",
        ),
        reverse=True,
    )
    ordered = [item["id"] for item in ranked]
    for item in kev:
        if item.get("id") and item["id"] not in ordered:
            ordered.append(item["id"])
    return ordered[:MAX_CVES]


def main():
    cves = candidate_cves()
    if not cves:
        print("::error::data/cves.json has no CVEs to score; run the CVE collector first", file=sys.stderr)
        return 1

    query = urllib.parse.urlencode({"cve": ",".join(cves), "limit": len(cves)})
    payload = fetch_json(f"{API_URL}?{query}")
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        print("::error::FIRST EPSS returned an unexpected payload", file=sys.stderr)
        return 1

    items = []
    for row in rows:
        try:
            score = float(row.get("epss"))
            percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            continue
        cve_id = row.get("cve")
        date = row.get("date")
        if not cve_id or not date:
            continue
        items.append({
            "cve": cve_id,
            "epss": round(score, 5),
            "percentile": round(percentile, 5),
            "date": date,
        })
    items.sort(key=lambda item: item["epss"], reverse=True)

    document = envelope(
        "FIRST EPSS",
        API_URL,
        note=f"EPSS scores for the top {len(cves)} prioritised CVEs in data/cves.json.",
        total=len(items),
        items=items,
    )
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(items)} EPSS scores.")
    if not items:
        print("::error::EPSS returned no scores; refusing to publish an empty feed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
