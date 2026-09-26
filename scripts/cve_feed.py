#!/usr/bin/env python3
"""
Builds a combined vulnerability feed from two official, free, no-key sources:

1. NVD (nvd.nist.gov) — recently published CVEs (last N days).
2. CISA KEV catalog — vulnerabilities confirmed to be actively exploited
   in the wild. This is the higher-signal list: CVSS score alone doesn't
   tell you what's actually being used in attacks right now, KEV does.

Recently published CVEs that also appear in KEV are flagged accordingly,
so the site can highlight "this is new AND it's already being exploited"
as the highest-priority signal.
"""
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

OUTPUT_PATH = "data/cves.json"
NVD_LOOKBACK_DAYS = 3
KEV_LOOKBACK_DAYS = 90  # keep the KEV list to recent additions, not the full 1000+ archive


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_nvd_recent():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=NVD_LOOKBACK_DAYS)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    return fetch_json(url)


def extract_severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return {
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity", metrics[key][0].get("baseSeverity")),
            }
    return {"score": None, "severity": None}


def fetch_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    return fetch_json(url)


def main():
    # --- Recently published CVEs (NVD) ---
    nvd_raw = fetch_nvd_recent()
    recent = []
    for entry in nvd_raw.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        severity = extract_severity(cve.get("metrics", {}))
        recent.append({
            "id": cve_id,
            "published": cve.get("published"),
            "description": description[:300],
            "severity": severity["severity"],
            "score": severity["score"],
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "kev": False,  # filled in below
        })

    # --- Actively exploited (CISA KEV) ---
    kev_raw = fetch_kev()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEV_LOOKBACK_DAYS)).date()
    kev_all = kev_raw.get("vulnerabilities", [])
    kev_ids = {v.get("cveID") for v in kev_all if v.get("cveID")}

    kev_recent = []
    for v in kev_all:
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < cutoff:
            continue
        kev_recent.append({
            "id": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "description": (v.get("shortDescription") or "")[:300],
            "link": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
        })

    # Cross-flag: mark recently-published CVEs that are also in the full KEV set
    for item in recent:
        if item["id"] in kev_ids:
            item["kev"] = True

    recent.sort(key=lambda x: x["published"] or "", reverse=True)
    kev_recent.sort(key=lambda x: x["date_added"] or "", reverse=True)

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "recent": {
            "lookback_days": NVD_LOOKBACK_DAYS,
            "total": len(recent),
            "items": recent,
        },
        "actively_exploited": {
            "lookback_days": KEV_LOOKBACK_DAYS,
            "total": len(kev_recent),
            "items": kev_recent,
        },
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(recent)} recent CVEs, {len(kev_recent)} recent KEV entries.")


if __name__ == "__main__":
    main()
