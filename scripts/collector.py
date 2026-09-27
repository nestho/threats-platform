#!/usr/bin/env python3
"""
Collects bug bounty program domains from ProjectDiscovery's public list,
detects the bounty platform from each program's URL, merges in any
manually-added entries from data/manual.json (which you maintain by hand
and which this script never overwrites), and writes a clean JSON snapshot.

SCHEMA VERSION 2 (2026-09-27)
-----------------------------
* `platform` is now a closed enum. It was free text, and a single hand-edit in
  manual.json ("BugCrowd" vs the canonical "Bugcrowd") split the published data
  into two separate groups on the site's "By platform" tab. Manual values are
  now matched case-insensitively against PLATFORM_MAP; anything unrecognised is
  preserved but recorded in `platform_warnings` so validate_feeds.py fails on it
  rather than it shipping quietly.
* `updated_at` is explicit-UTC ISO-8601 rather than a bare isoformat() with a
  +00:00 offset.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

SOURCE_URL = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
OUTPUT_PATH = "data/domains.json"
MANUAL_PATH = "data/manual.json"
SCHEMA_VERSION = 2

PLATFORM_MAP = {
    "hackerone.com": "HackerOne",
    "bugcrowd.com": "Bugcrowd",
    "intigriti.com": "Intigriti",
    "yeswehack.com": "YesWeHack",
    "hackenproof.com": "HackenProof",
    "immunefi.com": "Immunefi",
}

UNKNOWN_PLATFORM = "Self-hosted / Other"
CANONICAL_PLATFORMS = frozenset(PLATFORM_MAP.values()) | {UNKNOWN_PLATFORM}


def fetch_source(*, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "threats-top-collector"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = 5 * (2 ** (attempt - 1))
            print(f"  fetch failed ({exc}); retry {attempt}/{attempts - 1} in {delay}s")
            time.sleep(delay)
    raise RuntimeError(f"GET failed after {attempts} attempts: {SOURCE_URL}") from last_error


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
        return UNKNOWN_PLATFORM
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return UNKNOWN_PLATFORM
    for key, label in PLATFORM_MAP.items():
        if key in host:
            return label
    return UNKNOWN_PLATFORM


def canonical_platform(value):
    """
    Map a hand-written platform string onto the canonical enum.

    The bug this fixes: manual.json said "BugCrowd" while PLATFORM_MAP says
    "Bugcrowd". Nothing normalised the two, and programs.html groups on the raw
    string, so Bugcrowd rendered as two separate groups on the public site.

    Returns (canonical_value, is_recognised). Unrecognised values are passed
    through unchanged rather than being silently rewritten -- a hand-written
    "Hackerone Enterprise" should not quietly become "HackerOne" -- but they are
    reported so the validator can fail on them.
    """
    if not value:
        return UNKNOWN_PLATFORM, True
    text = str(value).strip()
    for canonical in CANONICAL_PLATFORMS:
        if text.lower() == canonical.lower():
            return canonical, True
    return text, False


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


def main() -> int:
    raw = fetch_source()
    entries = normalize_entries(raw)
    manual_entries = load_manual()
    warnings = []

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
        platform, recognised = canonical_platform(
            program.get("platform") or detect_platform(program.get("url", ""))
        )
        if not recognised:
            warnings.append(
                f"manual.json: program {name!r} has platform {program.get('platform')!r}, "
                f"which is not one of {sorted(CANONICAL_PLATFORMS)}"
            )
        if name in by_name:
            by_name[name]["domains"] |= domains
            by_name[name]["manual"] = True
            if platform != UNKNOWN_PLATFORM:
                by_name[name]["platform"] = platform
        else:
            by_name[name] = {
                "name": name,
                "url": program.get("url", ""),
                "platform": platform,
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

    programs_out.sort(key=lambda p: p["name"].lower())
    empty_scope = sum(1 for p in programs_out if not p["domains"])

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_programs": len(programs_out),
        "total_unique_domains": len(all_domains),
        # Surfaced rather than acted on: dropping these is a judgement call about
        # whether a program with undisclosed scope belongs on a scope page. See
        # docs/DEEP-ANALYSIS.md open question 6.
        "programs_without_domains": empty_scope,
        "platform_warnings": warnings,
        "platforms": sorted(CANONICAL_PLATFORMS),
        "programs": programs_out,
    }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(
        f"Wrote {len(programs_out)} programs ({len(manual_entries)} manual), "
        f"{len(all_domains)} unique domains. "
        f"{empty_scope} programs have no published domains."
    )
    for warning in warnings:
        print(f"::warning::{warning}", file=sys.stderr)

    if not programs_out:
        print("::error::collector produced zero programs -- refusing to publish an empty feed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
