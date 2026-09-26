#!/usr/bin/env python3
"""
Collects bug bounty program domains from ProjectDiscovery's public list,
detects the bounty platform from each program's URL, merges in any
manually-added entries from data/manual.json (which you maintain by hand
and which this script never overwrites), and writes a clean JSON snapshot.
"""
import json
import os
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

SOURCE_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
OUTPUT_PATH = "data/domains.json"
MANUAL_PATH = "data/manual.json"

PLATFORM_MAP = {
    "hackerone.com": "HackerOne",
    "bugcrowd.com": "Bugcrowd",
    "intigriti.com": "Intigriti",
    "yeswehack.com": "YesWeHack",
    "hackenproof.com": "HackenProof",
    "immunefi.com": "Immunefi",
}


def fetch_source():
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def normalize_entries(raw):
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("programs", "data", "entries"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        values = list(raw.values())
        if values and isinstance(values[0], dict):
            return values
    raise ValueError(f"Unrecognized data shape: {type(raw)}")


def detect_platform(url):
    if not url:
        return "Self-hosted / Other"
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return "Self-hosted / Other"
    for key, label in PLATFORM_MAP.items():
        if key in host:
            return label
    return "Self-hosted / Other"


def load_manual():
    """
    Reads data/manual.json if present. Expected shape:
    { "programs": [ { "name": ..., "url": ..., "domains": [...] }, ... ] }
    This file is yours to hand-edit. The collector merges it in on every
    run but never writes to it, so your manual entries always survive.
    """
    if not os.path.exists(MANUAL_PATH):
        return []
    with open(MANUAL_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("programs", [])


def main():
    raw = fetch_source()
    entries = normalize_entries(raw)
    manual_entries = load_manual()

    by_name = {}

    for program in entries:
        if not isinstance(program, dict) or not program.get("bounty"):
            continue
        name = program.get("name", "unknown")
        url = program.get("url", "")
        domains = program.get("domains", [])
        by_name[name] = {
            "name": name,
            "url": url,
            "platform": detect_platform(url),
            "domains": set(domains),
            "manual": False,
        }

    # Merge manual entries: extend domains if the program already exists,
    # otherwise add it as a new manual-only program.
    for program in manual_entries:
        name = program.get("name", "unknown")
        domains = set(program.get("domains", []))
        if name in by_name:
            by_name[name]["domains"] |= domains
            by_name[name]["manual"] = True
        else:
            by_name[name] = {
                "name": name,
                "url": program.get("url", ""),
                "platform": program.get("platform") or detect_platform(program.get("url", "")),
                "domains": domains,
                "manual": True,
            }

    programs_out = []
    all_domains = set()
    for p in by_name.values():
        domains_list = sorted(p["domains"])
        all_domains.update(domains_list)
        programs_out.append({
            "name": p["name"],
            "url": p["url"],
            "platform": p["platform"],
            "domain_count": len(domains_list),
            "domains": domains_list,
            "manual": p["manual"],
        })

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_programs": len(programs_out),
        "total_unique_domains": len(all_domains),
        "programs": programs_out,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(programs_out)} programs ({len(manual_entries)} manual), {len(all_domains)} unique domains.")


if __name__ == "__main__":
    main()
