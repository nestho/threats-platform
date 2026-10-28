#!/usr/bin/env python3
"""
Builds data/live.json: the events the live map animates.

WHAT "LIVE" MEANS HERE
----------------------
Vendor attack maps animate their own sensor grids; that telemetry is not for
sale or licence-clean. This feed is honest about its inputs:

  * claim       a ransomware leak-site claim published in the last 72 hours,
                plotted in the victim's country.
  * host        a phishing hostname from the current OpenPhish snapshot,
                resolved to an IP at collection time and plotted in the
                country that IP is registered in.

There are no source -> destination arcs, because no upstream we may publish
records an attacker's origin. Both kinds carry the timestamp of observation, so
the map can replay the last 72 hours and show that claims arrive in bursts
rather than pretending a quiet hour was a quiet attack.

Records that cannot be placed -- no ISO country, no resolvable host, no
country database -- are counted in `coverage`, not guessed.
"""
import ipaddress
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ip_country
from feed_io import (
    DATA_DIR,
    envelope,
    now_iso,
    parse_iso,
    read_json,
    stable_id,
    strip_html,
    truncate,
    write_json,
)

OUTPUT_PATH = DATA_DIR / "live.json"
RANSOMWARE_PATH = DATA_DIR / "ransomware.json"
PHISHING_PATH = DATA_DIR / "phishing.json"

WINDOW_HOURS = 72
MAX_EVENTS = 600
MAX_HOSTS = 300
RESOLVE_WORKERS = 16
RESOLVE_BUDGET_SECONDS = 90

SOURCE_URLS = [
    "https://api.ransomware.live/v2/recentvictims",
    "https://openphish.com/feed.txt",
]

ISO2 = re.compile(r"[A-Z]{2}")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

NOTE = (
    "Claims are ransomware leak-site victims published in the last "
    f"{WINDOW_HOURS} hours, shown in the country the claim names. Hosts are "
    "phishing hostnames from the current OpenPhish snapshot, resolved and "
    "geolocated at collection time. Neither layer is an attacker's origin: "
    "there is no source-to-destination telemetry in any publishable feed."
)


def claim_events(items, *, now, window_hours=WINDOW_HOURS, limit=MAX_EVENTS):
    """Claims inside the window with a usable country -> (events, coverage)."""
    cutoff = now - timedelta(hours=window_hours)
    total = 0
    in_window = 0
    seen = set()
    events = []

    for item in items or []:
        if not isinstance(item, dict):
            continue
        total += 1
        timestamp = parse_iso(item.get("published")) or parse_iso(item.get("discovered"))
        if timestamp is None or timestamp < cutoff or timestamp > now:
            continue
        in_window += 1

        country = str(item.get("country") or "").strip().upper()
        if not ISO2.fullmatch(country):
            continue

        identifier = str(item.get("id") or "").strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)

        events.append({
            "id": identifier,
            "kind": "claim",
            "ts": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country": country,
            "group": truncate(strip_html(item.get("group")), 60) or "Unattributed",
            "sector": truncate(strip_html(item.get("activity")), 60) or None,
            "host": None,
        })

    mapped = len(events)
    events = sorted(events, key=lambda event: (event["ts"], event["id"]), reverse=True)[:limit]
    coverage = {
        "claims_total": total,
        "claims_in_window": in_window,
        "claims_mapped": mapped,
    }
    return events, coverage


def host_events(hosts, addresses, lookup, *, collected_at, limit=MAX_EVENTS):
    """Phishing hosts with a resolved, geolocatable IP -> (events, coverage)."""
    unique = []
    seen = set()
    for raw in hosts or []:
        host = str(raw or "").strip().lower()
        if not HOSTNAME.fullmatch(host) or host in seen:
            continue
        seen.add(host)
        unique.append(host)

    resolved = 0
    events = []
    for host in unique:
        address = addresses.get(host)
        if not address:
            continue
        resolved += 1
        country = lookup(address)
        if not country:
            continue
        events.append({
            "id": stable_id("live-host", host),
            "kind": "host",
            "ts": collected_at,
            "country": country,
            "group": None,
            "sector": None,
            "host": host,
        })

    mapped = len(events)
    events = sorted(events, key=lambda event: (event["ts"], event["id"]), reverse=True)[:limit]
    coverage = {
        "hosts_total": len(unique),
        "hosts_resolved": resolved,
        "hosts_mapped": mapped,
    }
    return events, coverage


def default_resolver(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return infos[0][4][0]


def resolve_hosts(hosts, *, resolver=None, workers=RESOLVE_WORKERS,
                  budget_seconds=RESOLVE_BUDGET_SECONDS):
    """hostname -> IP for the hosts that answer inside the time budget."""
    resolver = resolver or default_resolver
    unique = []
    seen = set()
    for raw in hosts or []:
        host = str(raw or "").strip().lower()
        if HOSTNAME.fullmatch(host) and host not in seen:
            seen.add(host)
            unique.append(host)
    if not unique:
        return {}

    addresses = {}
    executor = ThreadPoolExecutor(max_workers=max(1, min(workers, len(unique))))
    try:
        futures = {executor.submit(resolver, host): host for host in unique}
        done, _pending = wait(futures, timeout=budget_seconds)
        for future in done:
            host = futures[future]
            try:
                address = future.result()
            except (OSError, UnicodeError):
                continue
            try:
                ipaddress.ip_address(address)
            except (ValueError, TypeError):
                continue
            addresses[host] = address
    finally:
        # A resolver call that outlives the budget must not hold the run open.
        executor.shutdown(wait=False, cancel_futures=True)
    return addresses


def build_document(*, claims, hosts, addresses, lookup, collected_at,
                   geo_available=True, now=None):
    now = now or parse_iso(collected_at) or datetime.now(timezone.utc)
    lookup = lookup or (lambda address: None)

    claim_list, claim_coverage = claim_events(claims, now=now)
    host_list, host_coverage = host_events(
        hosts, addresses, lookup, collected_at=collected_at
    )
    events = sorted(
        claim_list + host_list,
        key=lambda event: (event["ts"], event["id"]),
        reverse=True,
    )[:MAX_EVENTS]

    coverage = {
        **claim_coverage,
        **host_coverage,
        "geo_available": bool(geo_available),
    }
    return envelope(
        "ransomware.live claims + OpenPhish hosts, geolocated with DB-IP Lite",
        SOURCE_URLS,
        updated_at=collected_at,
        note=NOTE,
        window_hours=WINDOW_HOURS,
        attribution={
            "ip_geolocation": ip_country.DB_ATTRIBUTION,
            "license_url": ip_country.DB_LICENSE_URL,
        },
        coverage=coverage,
        events=events,
    )


def main():
    collected_at = now_iso()
    now = parse_iso(collected_at) or datetime.now(timezone.utc)

    ransomware = read_json(RANSOMWARE_PATH, {}) or {}
    phishing = read_json(PHISHING_PATH, {}) or {}
    claims = ransomware.get("items") if isinstance(ransomware.get("items"), list) else []
    hosts = [
        item.get("host")
        for item in phishing.get("items") or []
        if isinstance(item, dict)
    ][:MAX_HOSTS]

    lookup = None
    geo_available = False
    try:
        database = ip_country.load_database(ip_country.ensure_database(now=now))
        lookup = database.country
        geo_available = True
        print(f"  country database: {len(database)} ranges")
    except (ip_country.DatabaseUnavailable, OSError) as exc:
        print(f"::warning::live map without a country database: {exc}", file=sys.stderr)

    addresses = resolve_hosts(hosts) if geo_available else {}
    if geo_available:
        print(f"  resolved {len(addresses)} of {len(hosts)} phishing hosts")
    document = build_document(
        claims=claims,
        hosts=hosts,
        addresses=addresses,
        lookup=lookup,
        collected_at=collected_at,
        geo_available=geo_available,
        now=now,
    )
    write_json(OUTPUT_PATH, document)

    coverage = document["coverage"]
    print(
        f"Wrote {len(document['events'])} live events "
        f"({coverage['claims_mapped']}/{coverage['claims_total']} claims, "
        f"{coverage['hosts_mapped']}/{coverage['hosts_resolved']} resolved hosts "
        f"of {coverage['hosts_total']})."
    )
    if not document["events"]:
        print("::error::live feed would be empty; refusing to publish", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
