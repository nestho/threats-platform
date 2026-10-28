#!/usr/bin/env python3
"""
Source registry and status bookkeeping for the collector orchestrator.

`data/status.json` is the public freshness contract: every source says when it
was last attempted, when it last succeeded, how many records that success
published, and why the last attempt failed. The site renders outages from this
file instead of pretending a stale feed is current.

Cadence is data, not schedule arithmetic. The workflow runs hourly and asks
`is_due()` which sources have outlived their cadence, so a missed run is caught
up on the next one and a weekly source cannot silently never run because its
cron minute did not match.
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from feed_io import DATA_DIR, now_iso, parse_iso, write_json

STATUS_PATH = DATA_DIR / "status.json"

# Order matters: iocs derives from phishing and ransomware, epss reads cves.json.
SOURCES = {
    "cve": {
        "label": "NVD + CISA KEV",
        "url": [
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        ],
        "cadence_minutes": 120,
        "critical": True,
        "script": "cve_feed.py",
        "feeds": ["cves.json", "cves_headline.json"],
        "primary_feed": "cves.json",
    },
    "ghsa": {
        "label": "GitHub Security Advisories",
        "url": "https://github.com/security-advisories.atom",
        "cadence_minutes": 180,
        "critical": False,
        "script": "ghsa_feed.py",
        "feeds": ["ghsa.json"],
        "primary_feed": "ghsa.json",
    },
    "exploitdb": {
        "label": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "cadence_minutes": 240,
        "critical": False,
        "script": "exploitdb_feed.py",
        "feeds": ["exploitdb.json"],
        "primary_feed": "exploitdb.json",
    },
    "cert_eu": {
        "label": "CERT-EU",
        "url": "https://cert.europa.eu/publications/security-advisories-rss",
        "cadence_minutes": 240,
        "critical": False,
        "script": "cert_eu_feed.py",
        "feeds": ["cert_eu.json"],
        "primary_feed": "cert_eu.json",
    },
    "wiz": {
        "label": "Wiz Cloud Threat Landscape",
        "url": "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
        "cadence_minutes": 43200,
        "critical": False,
        "script": "wiz_feed.py",
        "feeds": ["wiz.json"],
        "primary_feed": "wiz.json",
    },
    "domains": {
        "label": "ProjectDiscovery + curated programs",
        "url": "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json",
        "cadence_minutes": 360,
        "critical": False,
        "script": "collector.py",
        "feeds": ["domains.json"],
        "primary_feed": "domains.json",
    },
    "ransomware": {
        "label": "ransomware.live",
        "url": "https://api.ransomware.live/v2/recentvictims",
        "cadence_minutes": 60,
        "critical": False,
        "script": "ransomware_feed.py",
        "feeds": ["ransomware.json"],
        "primary_feed": "ransomware.json",
    },
    "phishing": {
        "label": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "cadence_minutes": 60,
        "critical": False,
        "script": "phishing_feed.py",
        "feeds": ["phishing.json"],
        "primary_feed": "phishing.json",
    },
    "advisories": {
        "label": "Microsoft MSRC + Ubuntu Security Notices",
        "url": [
            "https://api.msrc.microsoft.com/update-guide/rss",
            "https://ubuntu.com/security/notices/rss.xml",
        ],
        "cadence_minutes": 240,
        "critical": False,
        "script": "advisories_feed.py",
        "feeds": ["advisories.json"],
        "primary_feed": "advisories.json",
    },
    "epss": {
        "label": "FIRST EPSS",
        "url": "https://api.first.org/data/v1/epss",
        "cadence_minutes": 360,
        "critical": False,
        "script": "epss_feed.py",
        "feeds": ["epss.json"],
        "primary_feed": "epss.json",
    },
    "iocs": {
        "label": "Derived IOC feed",
        "url": ["https://openphish.com/feed.txt", "https://api.ransomware.live/v2/recentvictims"],
        "cadence_minutes": 60,
        "critical": False,
        "script": "iocs_feed.py",
        "feeds": ["iocs.json"],
        "primary_feed": "iocs.json",
    },
    # Derived from phishing and ransomware, so it runs after both. The country
    # database it needs is an input, not a source: live_feed.py downloads it and
    # publishes claims only if that download fails.
    "live": {
        "label": "Live map (claims + phishing hosting)",
        "url": ["https://api.ransomware.live/v2/recentvictims", "https://openphish.com/feed.txt"],
        "cadence_minutes": 60,
        "critical": False,
        "script": "live_feed.py",
        "feeds": ["live.json"],
        "primary_feed": "live.json",
    },
}


def load_status():
    try:
        document = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    sources = document.get("sources")
    if not isinstance(sources, list):
        return {}
    return {
        entry["id"]: entry
        for entry in sources
        if isinstance(entry, dict) and entry.get("id") in SOURCES
    }


def feed_totals():
    """Map feed file -> item count, read from the current files on disk."""
    totals = {}
    for feed in DATA_DIR.glob("*.json"):
        if feed.name in ("status.json", "manual.json"):
            continue
        try:
            document = json.loads(feed.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        total = 0
        if isinstance(document.get("items"), list):
            total += len(document["items"])
        if isinstance(document.get("programs"), list):
            total += len(document["programs"])
        if isinstance(document.get("events"), list):
            total += len(document["events"])
        for section in ("recent", "actively_exploited"):
            value = document.get(section)
            if isinstance(value, dict) and isinstance(value.get("items"), list):
                total += len(value["items"])
        totals[feed.name] = total
    return totals


def primary_timestamp(feed_name):
    try:
        document = json.loads((DATA_DIR / feed_name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document.get("updated_at")


def is_due(source_id, previous, *, now=None):
    now = now or datetime.now(timezone.utc)
    source = SOURCES[source_id]
    last_success = parse_iso((previous or {}).get("last_success"))
    if last_success is None:
        return True
    due_at = last_success + timedelta(minutes=source["cadence_minutes"])
    # Five minutes of grace keeps an hourly source from being forced to wait a
    # full extra hour when the previous run finished a few seconds after the hour.
    return now >= due_at - timedelta(minutes=5)


def enrich_entry(source_id, previous, *, attempted, succeeded, error, duration_ms, http_status=None):
    source = SOURCES[source_id]
    entry = {
        "id": source_id,
        "label": source["label"],
        "url": source["url"],
        "cadence_minutes": source["cadence_minutes"],
        "critical": source["critical"],
        "feeds": source["feeds"],
        "last_attempt": attempted,
        "last_success": (previous or {}).get("last_success"),
        "http_status": http_status,
        "items": (previous or {}).get("items", 0),
        "error": None if succeeded else error,
        "duration_ms": duration_ms,
    }
    if succeeded:
        feed = source["primary_feed"]
        timestamp = primary_timestamp(feed)
        entry["last_success"] = timestamp or attempted
        entry["items"] = feed_totals().get(feed, 0)
        entry["http_status"] = http_status
    return entry


def mark_stale(entry, *, now=None):
    now = now or datetime.now(timezone.utc)
    last_success = parse_iso(entry.get("last_success"))
    cadence = entry.get("cadence_minutes") or 1440
    if last_success is None:
        entry["stale"] = True
        entry["age_minutes"] = None
        return entry
    age = int((now - last_success).total_seconds() // 60)
    entry["age_minutes"] = age
    entry["stale"] = age > cadence * 2
    return entry


def overall(entries, *, now=None):
    now = now or datetime.now(timezone.utc)
    if any(entry.get("stale") for entry in entries):
        for entry in entries:
            if entry.get("critical") and entry.get("stale"):
                return "outage"
        return "degraded"
    if any(entry.get("error") for entry in entries):
        return "degraded"
    return "ok"


def write_status(entries):
    ordered = []
    for source_id in SOURCES:
        entry = entries.get(source_id)
        if entry is None:
            entry = enrich_entry(
                source_id,
                {},
                attempted=None,
                succeeded=False,
                error="not attempted yet",
                duration_ms=0,
            )
        ordered.append(mark_stale(entry))
    document = {
        "schema_version": 1,
        "generated_at": now_iso(),
        "overall": overall(ordered),
        "sources": ordered,
    }
    write_json(STATUS_PATH, document)
    return document
