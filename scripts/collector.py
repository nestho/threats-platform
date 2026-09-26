#!/usr/bin/env python3
"""
Collects bug bounty program domains from ProjectDiscovery's public list
and writes a clean JSON snapshot for the site.
"""
import json
import urllib.request
from datetime import datetime, timezone

SOURCE_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
OUTPUT_PATH = "data/domains.json"


def fetch_source():
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "threats-top-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def normalize_entries(raw):
    """Handle whatever shape the source JSON turns out to be."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("programs", "data", "entries"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        # fallback: maybe it's {name: {...}} style
        values = list(raw.values())
        if values and isinstance(values[0], dict):
            return values
    raise ValueError(f"Unrecognized data shape: {type(raw)}")


def main():
    raw = fetch_source()
    entries = normalize_entries(raw)

    programs_out = []
    all_domains = set()

    for program in entries:
        if not isinstance(program, dict):
            continue
        if not program.get("bounty"):
            continue
        domains = program.get("domains", [])
        programs_out.append({
            "name": program.get("name", "unknown"),
            "domain_count": len(domains),
            "domains": domains,
        })
        all_domains.update(domains)

    output = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_programs": len(programs_out),
        "total_unique_domains": len(all_domains),
        "programs": programs_out,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(programs_out)} programs, {len(all_domains)} unique domains.")


if __name__ == "__main__":
    main()
