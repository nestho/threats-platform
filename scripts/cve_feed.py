#!/usr/bin/env python3
"""
Fetches recently published CVEs from NVD (official, free, no API key needed
for this volume) and writes a clean snapshot for the site.
"""
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

OUTPUT_PATH = "data/cves.json"
LOOKBACK_DAYS = 3


def fetch_recent_cves():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return {
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity", metrics[key][0].get("baseSeverity")),
            }
    return {"score": None, "severity": None}


def main():
    raw = fetch_recent_cves()
    items = []

    for entry in raw.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        severity = extract_severity(cve.get("metrics", {}))

        items.append({
            "id": cve_id,
            "published": cve.get("published"),
            "description": description[:300],
            "severity": severity["severity"],
            "score": severity["score"],
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    # newest first
    items.sort(key=lambda x: x["published"] or "", reverse=True)

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_days": LOOKBACK_DAYS,
        "total": len(items),
        "cves": items,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(items)} recent CVEs.")


if __name__ == "__main__":
    main()
