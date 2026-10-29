# Live Attack Map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the static-looking homepage counters honest and upgrade `map.html` into a five-layer interactive live attack map (claims, incidents, phishing hosts, ISC source IPs, blocklist.de attacker IPs) fed by three new keyless collectors.

**Architecture:** Three new stdlib-only Python collectors (`incidents_feed.py`, `isc_feed.py`, `attackers_feed.py`) publish `data/incidents.json`, `data/isc.json`, `data/attackers.json` through the existing `feed_io.envelope()` + `write_json` atomic pattern. `live_feed.py` gains three new event builders that merge with the existing claim/host events into `data/live.json` under one uniform event shape with five kinds. The validator and `status.py` registry gain the three feeds. `assets/live-map.js` generalizes from a claim/host binary to per-kind counts, and `map.html` gets layer chips, a 15-item ticker, per-kind 24h counters, and a per-kind sparkline. Homepage counters are recomputed client-side from real feed timestamps.

**Tech Stack:** Python 3 stdlib collectors (urllib, unittest), vanilla ES modules (`assets/live-map.js`), static HTML/JS pages, `validate_feeds.py` contract gate, GitHub Actions PR flow.

**Spec:** [docs/superpowers/specs/2026-10-29-live-attack-map-design.md](../specs/2026-10-29-live-attack-map-design.md)

## Global Constraints

- No fake source→destination arcs, ever. Every map layer is labelled with exactly what it is ("no publishable feed records attacker origin" stays in the copy).
- Licence-clean keyless sources only. Cloudflare Radar (CC BY-NC) and abuse.ch ThreatFox (for-profit clause) stay excluded — do not reintroduce them.
- `live.json` window stays 72 hours; live event kinds become `claim`, `host`, `incident`, `source`, `attacker`.
- New feed cadences: `incidents` 180 min, `isc` 60 min, `attackers` 60 min. They must be registered in `status.py` BEFORE `iocs` and `live` (order matters: derived feeds run after their inputs).
- New feeds start at `schema_version` 1 in `EXPECTED_SCHEMA_VERSION`. `ALLOW_EMPTY` stays empty — every collector refuses to publish an empty feed.
- `main` branch is protected: work happens on `feat/live-attack-map`, shipped via one reviewed PR.
- No demo markers anywhere (`default-pro`, `community-free`, `demo-tenant`, `example-tenant`); the validator rejects them.
- Design tokens and WCAG AA contrast are preserved; the impeccable design detector gates CI.
- Verification commands (run from repo root):
  - `python3 -m unittest discover -s scripts/tests -t scripts -v`
  - `node --test assets worker scheduler`
  - `python3 scripts/validate_feeds.py --against HEAD`

## Key existing code to reuse (read before starting)

- `scripts/feed_io.py` — `envelope(source, source_url, **extra)` (sets `updated_at=now_iso()`, extra keys merged), `now_iso()`, `parse_iso()`, `stable_id(prefix, *parts)` (16-hex sha256), `write_json()` (atomic), `read_json(path, default)`, `is_http_url()`, `strip_html()`, `truncate()`.
- `scripts/ip_country.py` — `ensure_database(now=)`, `load_database(path)` → object with `.country(ip)` and `len(db)`, `DB_ATTRIBUTION`, `DB_LICENSE_URL`, `DatabaseUnavailable`.
- `scripts/phishing_feed.py` — the collector pattern to mirror: `fetch_text` with retry, pure `build_items`, envelope + refuse-empty `main`.
- `scripts/live_feed.py` — `claim_events`/`host_events` event vocabulary and coverage reporting.
- `assets/live-map.js` + `assets/live-map.test.mjs` — the pure helpers and test conventions to generalize.

---

### Task 1: `incidents_feed.py` — ransomware.live recent cyber incidents

**Files:**
- Create: `scripts/incidents_feed.py`
- Create: `scripts/tests/fixtures/recentcyberattacks.json`
- Modify: `scripts/tests/test_collectors.py` (add `IncidentFeedTests`)
- Generates: `data/incidents.json` (real data, collected locally in Step 4)

**Interfaces:**
- Consumes: `feed_io.envelope`, `feed_io.stable_id`, `feed_io.strip_html`, `feed_io.truncate`, `feed_io.is_http_url`, `feed_io.write_json`, `feed_io.now_iso`
- Produces: `parse_items(payload, *, limit=200) -> list[dict]` and `build_document(items) -> dict` used by tests; `data/incidents.json` item shape consumed by Task 4's `incident_events`:
  `{id, victim, domain, country, added, date, title, summary, link, claim_gang, infostealer_compromised_users}`

Upstream: `https://api.ransomware.live/v2/recentcyberattacks` — a JSON list. Verified record keys: `added` (ISO **date**, no time), `date` (ISO date or empty), `victim`, `domain`, `country` (ISO2 or empty), `title` (may be empty), `summary` + `description` (prose), `link` (url), `claim_gang` (bool), `has_infostealer_info` (bool), `infostealer_data` (dict with `employees` int, or empty). Upstream caps the list at 100; keep up to 200 for headroom.

- [ ] **Step 1: Write the fixture**

Create `scripts/tests/fixtures/recentcyberattacks.json` — a JSON list of 3 records exercising the edge cases:

```json
[
  {
    "added": "2026-10-28",
    "date": "2026-10-20",
    "victim": "Acme Manufacturing Ltd",
    "domain": "acme-mfg.example",
    "country": "DE",
    "title": "Ransomware claim: Acme Manufacturing",
    "summary": "<p>LockBit lists Acme Manufacturing.</p>",
    "description": "LockBit lists Acme Manufacturing.",
    "link": "https://www.ransomware.live/id/acme",
    "claim_gang": true,
    "has_infostealer_info": true,
    "infostealer_data": {"employees": 42, "infostealer_stats": {"Acreed": 1}}
  },
  {
    "added": "2026-10-27",
    "date": "",
    "victim": "",
    "domain": "",
    "country": "fr",
    "title": "",
    "summary": "A stealer log exposed credentials.",
    "description": "",
    "link": "https://www.ransomware.live/id/stealer",
    "claim_gang": false,
    "has_infostealer_info": false,
    "infostealer_data": {}
  },
  {
    "added": "not-a-date",
    "date": "2026-10-01",
    "victim": "Broken record",
    "domain": "broken.example",
    "country": "US",
    "title": "Has no usable added date",
    "summary": "Must be dropped.",
    "description": "",
    "link": "https://www.ransomware.live/id/broken",
    "claim_gang": false,
    "has_infostealer_info": false,
    "infostealer_data": {}
  }
]
```

- [ ] **Step 2: Write the failing tests**

Add to `scripts/tests/test_collectors.py` (after the imports; reuse `read_fixture`):

```python
import incidents_feed


class IncidentFeedTests(unittest.TestCase):
    def test_records_are_normalised_and_sorted_by_added(self):
        payload = json.loads(read_fixture("recentcyberattacks.json"))
        items = incidents_feed.parse_items(payload)

        self.assertEqual(len(items), 2, "the record without a usable added date is dropped")
        self.assertEqual(items[0]["added"], "2026-10-28")
        self.assertEqual(items[0]["date"], "2026-10-20")
        self.assertEqual(items[0]["country"], "DE")
        self.assertEqual(items[0]["summary"], "LockBit lists Acme Manufacturing.")
        self.assertTrue(items[0]["claim_gang"])
        self.assertEqual(items[0]["infostealer_compromised_users"], 42)

    def test_empty_and_missing_fields_become_null_not_strings(self):
        payload = json.loads(read_fixture("recentcyberattacks.json"))
        second = incidents_feed.parse_items(payload)[1]

        self.assertIsNone(second["victim"])
        self.assertIsNone(second["domain"])
        self.assertEqual(second["country"], "FR", "country is uppercased")
        self.assertIsNone(second["title"])
        self.assertIsNone(second["date"])
        self.assertFalse(second["claim_gang"])
        self.assertIsNone(second["infostealer_compromised_users"])

    def test_ids_are_stable_and_deduplicated_by_link(self):
        payload = json.loads(read_fixture("recentcyberattacks.json"))
        items = incidents_feed.parse_items(payload + [payload[0]])

        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["id"], incidents_feed.parse_items([payload[0]])[0]["id"])

    def test_document_carries_provenance_and_a_honest_note(self):
        payload = json.loads(read_fixture("recentcyberattacks.json"))
        document = incidents_feed.build_document(incidents_feed.parse_items(payload))

        self.assertEqual(document["schema_version"], 1)
        self.assertIn("ransomware.live", document["source"])
        self.assertEqual(document["total"], 2)
        self.assertEqual(len(document["items"]), 2)
        self.assertIn("not confirmation", document["note"])
        self.assertTrue(document["items"][0]["link"].startswith("https://"))
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'incidents_feed'`.

- [ ] **Step 4: Implement the collector**

Create `scripts/incidents_feed.py`:

```python
#!/usr/bin/env python3
"""
Public claims of recent cyber incidents from ransomware.live (free, no key).

recentcyberattacks covers breaches, infostealer exposures and hacktivist
claims that ransomware.live tracks beyond its ransomware victim list. Every
record carries an `added` date -- the day the claim was recorded, with no time
component -- so that date (at 00:00 UTC) is the published timestamp; no times
are invented.

A claim is not confirmation of a successful attack: the note says so, and the
summary keeps its attribution to the claimant.

Source: https://api.ransomware.live/v2/recentcyberattacks
"""
import json
import re
import sys
import urllib.error
import urllib.request

from feed_io import (
    DATA_DIR, envelope, is_http_url, stable_id, strip_html,
    truncate, write_json,
)

FEED_URL = "https://api.ransomware.live/v2/recentcyberattacks"
OUTPUT_PATH = DATA_DIR / "incidents.json"
MAX_ITEMS = 200

ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def fetch_json(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": "threats-top-collector", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def parse_items(payload, *, limit=MAX_ITEMS):
    items = []
    seen = set()
    for raw in payload or []:
        if not isinstance(raw, dict):
            continue
        added = str(raw.get("added") or "").strip()
        if not ISO_DATE.match(added):
            continue
        link = str(raw.get("link") or "").strip()
        if not is_http_url(link):
            continue
        identifier = stable_id("inc", link)
        if identifier in seen:
            continue
        seen.add(identifier)

        country = str(raw.get("country") or "").strip().upper() or None
        date = str(raw.get("date") or "").strip()
        infostealer = raw.get("infostealer_data")
        compromised = None
        if isinstance(infostealer, dict):
            employees = infostealer.get("employees")
            if isinstance(employees, int) and not isinstance(employees, bool) and employees > 0:
                compromised = employees

        items.append({
            "id": identifier,
            "victim": truncate(strip_html(raw.get("victim")), 120) or None,
            "domain": str(raw.get("domain") or "").strip().lower() or None,
            "country": country,
            "added": added,
            "date": date if ISO_DATE.match(date) else None,
            "title": truncate(strip_html(raw.get("title")), 140) or None,
            "summary": truncate(strip_html(raw.get("summary") or raw.get("description")), 300),
            "link": link,
            "claim_gang": bool(raw.get("claim_gang")),
            "infostealer_compromised_users": compromised,
        })

    items.sort(key=lambda item: (item["added"], item["id"]), reverse=True)
    return items[:limit]


def build_document(items):
    return envelope(
        "ransomware.live recent cyber incidents",
        FEED_URL,
        note=("Public claims of cyber incidents -- breaches, infostealer exposures, "
              "hacktivist and ransomware claims -- as recorded by ransomware.live. "
              "A claim is not confirmation of a successful attack; `added` is the "
              "day the claim was recorded and carries no time component."),
        total=len(items),
        items=items,
    )


def main():
    items = parse_items(fetch_json(FEED_URL))
    write_json(OUTPUT_PATH, build_document(items))

    print(f"Wrote {len(items)} incident claims.")
    if not items:
        print("::error::recentcyberattacks returned no usable records; refusing to publish an empty feed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run tests to verify they pass, then collect real data**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: PASS (all suites).

Run: `python3 scripts/incidents_feed.py`
Expected: prints `Wrote N incident claims.` with N > 0 and writes `data/incidents.json`.

- [ ] **Step 6: Commit**

```bash
git add scripts/incidents_feed.py scripts/tests/test_collectors.py scripts/tests/fixtures/recentcyberattacks.json data/incidents.json
git commit -m "feat(feeds): collect ransomware.live recent cyber incidents"
```

---

### Task 2: `isc_feed.py` — SANS ISC top attacker IPs and ports

**Files:**
- Create: `scripts/isc_feed.py`
- Create: `scripts/tests/fixtures/isc_topips.json`
- Create: `scripts/tests/fixtures/isc_topports.json`
- Modify: `scripts/tests/test_collectors.py` (add `IscFeedTests`)
- Generates: `data/isc.json`

**Interfaces:**
- Consumes: `feed_io` helpers (as Task 1), `ip_country` (as `live_feed.py` does)
- Produces: `parse_top_ips(payload) -> list`, `parse_top_ports(payload) -> list`, `build_document(top_ips, top_ports, *, collected_at) -> dict`; `data/isc.json` shape:
  envelope with `top_ips: {total, items: [{ip, reports_24h, targets, country}]}`, `top_ports: {total, items: [{port, records_24h, targets, sources}]}`, `attribution: {sensor_grid, ip_geolocation, license_url}`.
  `top_ips.items` is consumed by Task 4's `source_events`.

Upstream (verified live): `https://isc.sans.edu/api/topips/records/25` → list of `{ip, rank, source, reports, targets}`; `https://isc.sans.edu/api/topports/records/10` → list of `{rank, targetport, records, targets, sources}`. `dshield sources/attacks` and `topcountries` are Cloudflare-bot-blocked — do not use them. Licence: commercial use with attribution allowed, no resale; the attribution string is required in the envelope.

- [ ] **Step 1: Write the fixtures**

`scripts/tests/fixtures/isc_topips.json`:

```json
[
  {"rank": 1, "ip": "45.155.91.123", "source": "DShield", "reports": 2218, "targets": 412},
  {"rank": 2, "ip": "not-an-ip", "source": "DShield", "reports": 1800, "targets": 300},
  {"rank": 3, "ip": "45.155.91.123", "source": "DShield", "reports": 900, "targets": 100},
  {"rank": 4, "ip": "185.220.101.4", "source": "DShield", "reports": 700, "targets": 250}
]
```

`scripts/tests/fixtures/isc_topports.json`:

```json
[
  {"rank": 1, "targetport": 23, "records": 152000, "targets": 88000, "sources": 1200},
  {"rank": 2, "targetport": 0, "records": 90000, "targets": 50000, "sources": 800},
  {"rank": 3, "targetport": 3389, "records": 70000, "targets": 40000, "sources": 600},
  {"rank": 4, "targetport": "ssh", "records": 10, "targets": 5, "sources": 2}
]
```

- [ ] **Step 2: Write the failing tests**

```python
import isc_feed


class IscFeedTests(unittest.TestCase):
    def test_top_ips_are_validated_and_deduplicated(self):
        payload = json.loads(read_fixture("isc_topips.json"))
        items = isc_feed.parse_top_ips(payload)

        self.assertEqual([item["ip"] for item in items], ["45.155.91.123", "185.220.101.4"])
        self.assertEqual(items[0]["reports_24h"], 2218)
        self.assertIsNone(items[0]["country"], "country is filled at collection time")

    def test_top_ports_are_validated(self):
        payload = json.loads(read_fixture("isc_topports.json"))
        items = isc_feed.parse_top_ports(payload)

        self.assertEqual([item["port"] for item in items], [23, 3389])
        self.assertEqual(items[0]["records_24h"], 152000)
        self.assertEqual(items[0]["sources"], 1200)

    def test_document_has_two_sections_and_required_attribution(self):
        payload_ips = json.loads(read_fixture("isc_topips.json"))
        payload_ports = json.loads(read_fixture("isc_topports.json"))
        document = isc_feed.build_document(
            isc_feed.parse_top_ips(payload_ips),
            isc_feed.parse_top_ports(payload_ports),
            collected_at="2026-10-29T09:00:00Z",
        )

        self.assertEqual(document["top_ips"]["total"], 2)
        self.assertEqual(document["top_ports"]["total"], 2)
        self.assertIn("SANS Internet Storm Center", document["attribution"]["sensor_grid"])
        self.assertIn("DB-IP", document["attribution"]["ip_geolocation"])
        self.assertIn("24 hours", document["note"])
        self.assertEqual(document["updated_at"], "2026-10-29T09:00:00Z")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'isc_feed'`.

- [ ] **Step 4: Implement the collector**

Create `scripts/isc_feed.py`:

```python
#!/usr/bin/env python3
"""
Top attacker IPs and targeted ports from the SANS Internet Storm Center grid.

The ISC/DShield API aggregates reports from its volunteer sensor grid over
roughly the last 24 hours. That window is the grid's own aggregation, not a
timeline of individual attacks -- the note says so. Countries are filled with
the DB-IP Lite lookup at collection time; when the database is unavailable the
feed still publishes with country=null rather than skipping the source.

Licence: commercial use with attribution allowed, no resale. The attribution
string is required and lives in the envelope.

Sources: https://isc.sans.edu/api/topips/records/25, .../topports/records/10
"""
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import ip_country
from feed_io import DATA_DIR, envelope, now_iso, write_json

TOPIPS_URL = "https://isc.sans.edu/api/topips/records/25"
TOPPORTS_URL = "https://isc.sans.edu/api/topports/records/10"
TOP_IPS = 25
TOP_PORTS = 10

OUTPUT_PATH = DATA_DIR / "isc.json"


def fetch_json(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": "threats-top-collector", "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def non_negative_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def parse_top_ips(payload, *, limit=TOP_IPS):
    items = []
    seen = set()
    for raw in payload or []:
        if not isinstance(raw, dict):
            continue
        ip = str(raw.get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        items.append({
            "ip": ip,
            "reports_24h": non_negative_int(raw.get("reports")),
            "targets": non_negative_int(raw.get("targets")),
            "country": None,  # filled by main() with the DB-IP lookup
        })
        if len(items) >= limit:
            break
    return items


def parse_top_ports(payload, *, limit=TOP_PORTS):
    items = []
    for raw in payload or []:
        if not isinstance(raw, dict):
            continue
        port = raw.get("targetport")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            continue
        items.append({
            "port": port,
            "records_24h": non_negative_int(raw.get("records")),
            "targets": non_negative_int(raw.get("targets")),
            "sources": non_negative_int(raw.get("sources")),
        })
        if len(items) >= limit:
            break
    return items


def build_document(top_ips, top_ports, *, collected_at):
    return envelope(
        "SANS Internet Storm Center sensor grid",
        [TOPIPS_URL, TOPPORTS_URL],
        updated_at=collected_at,
        note=("Attacker IPs and targeted ports observed by the ISC/DShield volunteer "
              "sensor grid over roughly the last 24 hours. The window is the grid's "
              "own aggregation, not a timeline of individual attacks."),
        attribution={
            "sensor_grid": "Data courtesy of SANS Internet Storm Center (https://isc.sans.edu)",
            "ip_geolocation": ip_country.DB_ATTRIBUTION,
            "license_url": ip_country.DB_LICENSE_URL,
        },
        top_ips={"total": len(top_ips), "items": top_ips},
        top_ports={"total": len(top_ports), "items": top_ports},
    )


def main():
    collected_at = now_iso()
    failed = []
    top_ips, top_ports = [], []

    try:
        top_ips = parse_top_ips(fetch_json(TOPIPS_URL))
    except RuntimeError as exc:
        failed.append("topips")
        print(f"::warning::topips fetch failed: {exc}", file=sys.stderr)
    try:
        top_ports = parse_top_ports(fetch_json(TOPPORTS_URL))
    except RuntimeError as exc:
        failed.append("topports")
        print(f"::warning::topports fetch failed: {exc}", file=sys.stderr)

    if not top_ips and not top_ports:
        print("::error::ISC returned no usable data for either section; refusing to publish", file=sys.stderr)
        return 1

    if top_ips:
        try:
            database = ip_country.load_database(
                ip_country.ensure_database(now=datetime.now(timezone.utc))
            )
            for item in top_ips:
                item["country"] = database.country(item["ip"])
            print(f"  geolocated {sum(1 for item in top_ips if item['country'])} of {len(top_ips)} IPs")
        except (ip_country.DatabaseUnavailable, OSError) as exc:
            print(f"::warning::ISC feed without a country database: {exc}", file=sys.stderr)

    document = build_document(top_ips, top_ports, collected_at=collected_at)
    if failed:
        document["partial"] = failed
    write_json(OUTPUT_PATH, document)

    print(f"Wrote {len(top_ips)} top IPs and {len(top_ports)} top ports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run tests to verify they pass, then collect real data**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: PASS.

Run: `python3 scripts/isc_feed.py`
Expected: prints `Wrote 25 top IPs and 10 top ports.` (or a partial warning, never empty).

- [ ] **Step 6: Commit**

```bash
git add scripts/isc_feed.py scripts/tests/test_collectors.py scripts/tests/fixtures/isc_topips.json scripts/tests/fixtures/isc_topports.json data/isc.json
git commit -m "feat(feeds): collect SANS ISC top attacker IPs and ports"
```

---

### Task 3: `attackers_feed.py` — blocklist.de last-hour attacker IPs

**Files:**
- Create: `scripts/attackers_feed.py`
- Create: `scripts/tests/fixtures/blocklist_getlast.txt`
- Modify: `scripts/tests/test_collectors.py` (add `AttackerFeedTests`)
- Generates: `data/attackers.json`

**Interfaces:**
- Consumes: `feed_io` helpers, `ip_country`
- Produces: `parse_ips(text, *, limit=500) -> list[str]`, `build_document(ips, *, lookup, collected_at) -> dict`; `data/attackers.json` items `{ip, seen, country}` (consumed by Task 4's `attacker_events`).

Upstream: `https://www.blocklist.de/getlast.php?time=3600` — plain text, one attacker IP per line. Community fail2ban reports; the API has no per-report timestamp, so `seen` is the collection time. Plotted at the attacking IP's geolocation.

- [ ] **Step 1: Write the fixture**

`scripts/tests/fixtures/blocklist_getlast.txt`:

```
45.155.91.123
45.155.91.123
not-an-ip
185.220.101.4 extra-columns-are-ignored

103.99.0.27
```

- [ ] **Step 2: Write the failing tests**

```python
import attackers_feed


class AttackerFeedTests(unittest.TestCase):
    def test_ips_are_validated_deduplicated_and_capped(self):
        ips = attackers_feed.parse_ips(read_fixture("blocklist_getlast.txt"))

        self.assertEqual(ips, ["45.155.91.123", "185.220.101.4", "103.99.0.27"])

    def test_document_records_collection_time_as_seen(self):
        document = attackers_feed.build_document(
            ["45.155.91.123"],
            lookup=lambda ip: "NL",
            collected_at="2026-10-29T09:00:00Z",
        )

        self.assertEqual(document["items"], [{
            "ip": "45.155.91.123",
            "seen": "2026-10-29T09:00:00Z",
            "country": "NL",
        }])
        self.assertEqual(document["updated_at"], "2026-10-29T09:00:00Z")
        self.assertIn("fail2ban", document["note"])

    def test_a_missing_lookup_leaves_country_null(self):
        document = attackers_feed.build_document(
            ["45.155.91.123"], lookup=None, collected_at="2026-10-29T09:00:00Z"
        )
        self.assertIsNone(document["items"][0]["country"])
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'attackers_feed'`.

- [ ] **Step 4: Implement the collector**

Create `scripts/attackers_feed.py`:

```python
#!/usr/bin/env python3
"""
Attacker IPs reported to blocklist.de in the last hour (free, no key).

blocklist.de aggregates fail2ban reports from its community of reporters.
These are community reports of IPs that triggered intrusion-prevention bans,
not confirmed attacks, and the API carries no per-report timestamp -- `seen`
is the collection time and the note says both things. Countries come from the
DB-IP Lite lookup; when it is unavailable the feed publishes with
country=null.

Source: https://www.blocklist.de/getlast.php?time=3600
"""
import ipaddress
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import ip_country
from feed_io import DATA_DIR, envelope, now_iso, write_json

FEED_URL = "https://www.blocklist.de/getlast.php?time=3600"
OUTPUT_PATH = DATA_DIR / "attackers.json"
MAX_ITEMS = 500


def fetch_text(url, *, attempts=4):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": "threats-top-collector", "Accept": "text/plain"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  fetch failed ({exc}); retrying")
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def parse_ips(text, *, limit=MAX_ITEMS):
    ips = []
    seen = set()
    for line in (text or "").splitlines():
        candidate = line.strip().split()[0] if line.strip() else ""
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        ips.append(candidate)
        if len(ips) >= limit:
            break
    return ips


def build_document(ips, *, lookup, collected_at):
    items = [
        {"ip": ip, "seen": collected_at, "country": lookup(ip) if lookup else None}
        for ip in ips
    ]
    return envelope(
        "blocklist.de fail2ban reports (last hour)",
        FEED_URL,
        updated_at=collected_at,
        note=("Attacker IPs reported by fail2ban users to blocklist.de in the hour "
              "before collection. Community reports of intrusion attempts, not "
              "confirmed attacks; `seen` is the collection time because the API "
              "carries no per-report timestamp."),
        total=len(items),
        items=items,
    )


def main():
    collected_at = now_iso()
    ips = parse_ips(fetch_text(FEED_URL))

    lookup = None
    try:
        database = ip_country.load_database(
            ip_country.ensure_database(now=datetime.now(timezone.utc))
        )
        lookup = database.country
        print(f"  country database: {len(database)} ranges")
    except (ip_country.DatabaseUnavailable, OSError) as exc:
        print(f"::warning::attackers feed without a country database: {exc}", file=sys.stderr)

    write_json(OUTPUT_PATH, build_document(ips, lookup=lookup, collected_at=collected_at))

    print(f"Wrote {len(ips)} attacker IPs.")
    if not ips:
        print("::error::blocklist.de returned no usable IPs; refusing to publish an empty feed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run tests to verify they pass, then collect real data**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: PASS.

Run: `python3 scripts/attackers_feed.py`
Expected: prints `Wrote N attacker IPs.` with N > 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/attackers_feed.py scripts/tests/test_collectors.py scripts/tests/fixtures/blocklist_getlast.txt data/attackers.json
git commit -m "feat(feeds): collect blocklist.de last-hour attacker IPs"
```

---

### Task 4: `live_feed.py` — three new event kinds

**Files:**
- Modify: `scripts/live_feed.py`
- Modify: `scripts/tests/test_live_feed.py`
- Modifies: `data/live.json`

**Interfaces:**
- Consumes: `data/incidents.json` (Task 1), `data/isc.json` `top_ips.items` (Task 2), `data/attackers.json` (Task 3)
- Produces: **every** live event now carries exactly these keys — `id, kind, ts, country, group, sector, host, title, ip, reports_24h` — with `null` for fields the kind does not use. Task 6's helpers and Task 5's validator rely on this uniform shape.
  - `claim` — `group` str, `sector` nullable str (existing, gains `title/ip/reports_24h: null`)
  - `host` — `host` str (existing, gains `title/ip/reports_24h: null`)
  - `incident` — `title` nullable str; `ts` is `added` at 00:00 UTC (upstream has no time component)
  - `source` — `ip` str, `reports_24h` int; `ts` is the snapshot time (ISC is a 24h aggregation)
  - `attacker` — `ip` str; `ts` is `seen`
  - New coverage keys: `incidents_total/incidents_in_window/incidents_mapped`, `sources_total/sources_mapped`, `attackers_total/attackers_in_window/attackers_mapped`.

- [ ] **Step 1: Write the failing tests**

Add to `scripts/tests/test_live_feed.py` (update the import line to include the new builders):

```python
from live_feed import (
    attacker_events, build_document, claim_events, host_events,
    incident_events, resolve_hosts, source_events,
)
```

```python
class IncidentEventTests(unittest.TestCase):
    def incident(self, **overrides):
        item = {
            "id": "inc-1",
            "country": "DE",
            "added": "2026-10-28",
            "title": "Ransomware claim: Acme",
            "link": "https://www.ransomware.live/id/acme",
        }
        item.update(overrides)
        return item

    def test_emits_an_incident_with_a_midnight_utc_timestamp(self):
        events, coverage = incident_events([self.incident()], now=NOW)

        self.assertEqual(events, [{
            "id": "inc-1",
            "kind": "incident",
            "ts": "2026-10-28T00:00:00Z",
            "country": "DE",
            "group": None,
            "sector": None,
            "host": None,
            "title": "Ransomware claim: Acme",
            "ip": None,
            "reports_24h": None,
        }])
        self.assertEqual(coverage["incidents_mapped"], 1)

    def test_an_empty_title_becomes_null(self):
        events, _ = incident_events([self.incident(title="")], now=NOW)
        self.assertIsNone(events[0]["title"])

    def test_incidents_outside_the_window_or_without_country_are_dropped(self):
        events, coverage = incident_events(
            [self.incident(added="2026-10-01"), self.incident(country="")],
            now=NOW,
        )
        self.assertEqual(events, [])
        self.assertEqual(coverage["incidents_total"], 2)
        self.assertEqual(coverage["incidents_in_window"], 1)
        self.assertEqual(coverage["incidents_mapped"], 0)


class SourceEventTests(unittest.TestCase):
    @staticmethod
    def lookup(ip):
        return "NL" if ip == "45.155.91.123" else None

    def test_emits_a_source_sized_by_reports(self):
        events, coverage = source_events(
            [{"ip": "45.155.91.123", "reports_24h": 2218, "targets": 412}],
            lookup=self.lookup,
            collected_at=COLLECTED,
        )

        self.assertEqual(events[0]["kind"], "source")
        self.assertEqual(events[0]["ip"], "45.155.91.123")
        self.assertEqual(events[0]["reports_24h"], 2218)
        self.assertEqual(events[0]["ts"], COLLECTED, "the snapshot time, not an attack time")
        self.assertEqual(coverage["sources_mapped"], 1)

    def test_an_ungeolocatable_ip_is_counted_not_plotted(self):
        events, coverage = source_events(
            [{"ip": "10.0.0.1", "reports_24h": 5}],
            lookup=self.lookup,
            collected_at=COLLECTED,
        )
        self.assertEqual(events, [])
        self.assertEqual(coverage["sources_total"], 1)
        self.assertEqual(coverage["sources_mapped"], 0)

    def test_ids_are_stable_across_collections(self):
        first, _ = source_events(
            [{"ip": "45.155.91.123", "reports_24h": 1}],
            lookup=self.lookup, collected_at="2026-10-28T11:00:00Z",
        )
        second, _ = source_events(
            [{"ip": "45.155.91.123", "reports_24h": 9}],
            lookup=self.lookup, collected_at=COLLECTED,
        )
        self.assertEqual(first[0]["id"], second[0]["id"])


class AttackerEventTests(unittest.TestCase):
    @staticmethod
    def lookup(ip):
        return "RU" if ip == "185.220.101.4" else None

    def test_emits_an_attacker_with_its_seen_timestamp(self):
        events, coverage = attacker_events(
            [{"ip": "185.220.101.4", "seen": "2026-10-28T08:30:00Z"}],
            lookup=self.lookup,
            now=NOW,
        )

        self.assertEqual(events[0]["kind"], "attacker")
        self.assertEqual(events[0]["ts"], "2026-10-28T08:30:00Z")
        self.assertEqual(events[0]["ip"], "185.220.101.4")
        self.assertIsNone(events[0]["reports_24h"])
        self.assertEqual(coverage["attackers_mapped"], 1)

    def test_ips_seen_before_the_window_are_dropped(self):
        events, coverage = attacker_events(
            [{"ip": "185.220.101.4", "seen": "2026-10-01T00:00:00Z"}],
            lookup=self.lookup,
            now=NOW,
        )
        self.assertEqual(events, [])
        self.assertEqual(coverage["attackers_in_window"], 0)
```

In `BuildDocumentTests`, update `build()` to pass the new inputs, update the existing envelope test (`len(document["source_url"])` is now **5**, not 2), and add:

```python
    def build(self, *, lookup=None, geo_available=True):
        return build_document(
            claims=[claim(), claim(id="rw-2", country=None)],
            hosts=["a.example", "b.example"],
            addresses=HostEventTests.ADDRESSES,
            lookup=lookup or HostEventTests.lookup,
            incidents=[{
                "id": "inc-1", "country": "DE", "added": "2026-10-28",
                "title": "Claim", "link": "https://www.ransomware.live/id/x",
            }],
            sources=[{"ip": "8.8.8.8", "reports_24h": 10, "targets": 5, "country": None}],
            attackers=[{"ip": "1.1.1.1", "seen": COLLECTED, "country": None}],
            collected_at=COLLECTED,
            geo_available=geo_available,
        )

    def test_all_five_kinds_publish_newest_first_with_uniform_keys(self):
        document = self.build()
        kinds = {event["kind"] for event in document["events"]}

        self.assertEqual(kinds, {"claim", "host", "incident", "source", "attacker"})
        keys = {"id", "kind", "ts", "country", "group", "sector", "host",
                "title", "ip", "reports_24h"}
        for event in document["events"]:
            self.assertEqual(set(event.keys()), keys)
        timestamps = [event["ts"] for event in document["events"]]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))

    def test_ip_based_layers_need_a_country_database(self):
        document = self.build(lookup=lambda address: None, geo_available=False)
        kinds = {event["kind"] for event in document["events"]}

        self.assertEqual(kinds, {"claim", "incident"})
        self.assertFalse(document["coverage"]["geo_available"])
```

Also extend the existing `test_coverage_is_reported_not_implied` with the new keys (the existing per-key `assertEqual`s keep passing unchanged):

```python
        self.assertEqual(coverage["incidents_total"], 1)
        self.assertEqual(coverage["incidents_mapped"], 1)
        self.assertEqual(coverage["sources_total"], 1)
        self.assertEqual(coverage["sources_mapped"], 1)
        self.assertEqual(coverage["attackers_total"], 1)
        self.assertEqual(coverage["attackers_mapped"], 0)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest scripts.tests.test_live_feed -v`
Expected: FAIL — `ImportError: cannot import name 'incident_events'`.

- [ ] **Step 3: Implement the new builders**

In `scripts/live_feed.py`:

1. Add constants and paths near the top:

```python
OUTPUT_PATH = DATA_DIR / "live.json"
RANSOMWARE_PATH = DATA_DIR / "ransomware.json"
PHISHING_PATH = DATA_DIR / "phishing.json"
INCIDENTS_PATH = DATA_DIR / "incidents.json"
ISC_PATH = DATA_DIR / "isc.json"
ATTACKERS_PATH = DATA_DIR / "attackers.json"

WINDOW_HOURS = 72
MAX_EVENTS = 600
MAX_HOSTS = 300
MAX_INCIDENTS = 200
MAX_SOURCES = 50
MAX_ATTACKERS = 300
RESOLVE_WORKERS = 16
RESOLVE_BUDGET_SECONDS = 90

SOURCE_URLS = [
    "https://api.ransomware.live/v2/recentvictims",
    "https://openphish.com/feed.txt",
    "https://api.ransomware.live/v2/recentcyberattacks",
    "https://isc.sans.edu/api/topips/records/25",
    "https://www.blocklist.de/getlast.php?time=3600",
]
```

2. Replace `NOTE` with:

```python
NOTE = (
    f"Claims are ransomware leak-site victims and incidents are public "
    f"cyber-incident claims, both recorded in the last {WINDOW_HOURS} hours and "
    "shown in the country the record names. Hosts are phishing hostnames from "
    "the current OpenPhish snapshot, resolved and geolocated at collection "
    "time. Sources are attacker IPs on the SANS ISC top list and attackers are "
    "IPs reported to blocklist.de in the last hour, both plotted at the "
    "attacking IP's geolocation. Source markers carry the snapshot time, not "
    "an attack time. None of these layers is an attack in progress, and none "
    "shows a victim: there is no source-to-destination telemetry in any "
    "publishable feed."
)
```

3. In `claim_events`, add `"title": None, "ip": None, "reports_24h": None,` to the event dict. In `host_events`, same three keys set to `None`.

4. Add the three builders after `host_events`:

```python
def incident_events(items, *, now, window_hours=WINDOW_HOURS, limit=MAX_INCIDENTS):
    """Incident claims inside the window -> (events, coverage).

    incidents.json carries `added` as an ISO date with no time component, so
    the event timestamp is that date at 00:00 UTC -- honest and stable, never
    a fabricated time of day.
    """
    cutoff = now - timedelta(hours=window_hours)
    total = 0
    in_window = 0
    seen = set()
    events = []

    for item in items or []:
        if not isinstance(item, dict):
            continue
        total += 1
        try:
            day = datetime.strptime(str(item.get("added") or "").strip(),
                                    "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if day < cutoff or day > now:
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
            "kind": "incident",
            "ts": day.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country": country,
            "group": None,
            "sector": None,
            "host": None,
            "title": truncate(strip_html(item.get("title")), 140) or None,
            "ip": None,
            "reports_24h": None,
        })

    mapped = len(events)
    events = sorted(events, key=lambda event: (event["ts"], event["id"]), reverse=True)[:limit]
    coverage = {
        "incidents_total": total,
        "incidents_in_window": in_window,
        "incidents_mapped": mapped,
    }
    return events, coverage


def source_events(items, *, lookup, collected_at, limit=MAX_SOURCES):
    """ISC top attacker IPs -> (events, coverage). ts is the snapshot time."""
    total = 0
    events = []

    for item in items or []:
        if not isinstance(item, dict):
            continue
        total += 1
        ip = str(item.get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        country = lookup(ip) if lookup else None
        if not country:
            continue
        reports = item.get("reports_24h")
        events.append({
            "id": stable_id("live-src", ip),
            "kind": "source",
            "ts": collected_at,
            "country": country,
            "group": None,
            "sector": None,
            "host": None,
            "title": None,
            "ip": ip,
            "reports_24h": reports if isinstance(reports, int) and not isinstance(reports, bool) and reports >= 0 else None,
        })

    mapped = len(events)
    events = sorted(events, key=lambda event: (event["ts"], event["id"]), reverse=True)[:limit]
    coverage = {"sources_total": total, "sources_mapped": mapped}
    return events, coverage


def attacker_events(items, *, lookup, now, window_hours=WINDOW_HOURS, limit=MAX_ATTACKERS):
    """blocklist.de IPs inside the window -> (events, coverage)."""
    cutoff = now - timedelta(hours=window_hours)
    total = 0
    in_window = 0
    seen = set()
    events = []

    for item in items or []:
        if not isinstance(item, dict):
            continue
        total += 1
        timestamp = parse_iso(item.get("seen"))
        if timestamp is None or timestamp < cutoff or timestamp > now:
            continue
        in_window += 1

        ip = str(item.get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip in seen:
            continue
        seen.add(ip)

        country = lookup(ip) if lookup else None
        if not country:
            continue
        events.append({
            "id": stable_id("live-att", ip),
            "kind": "attacker",
            "ts": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "country": country,
            "group": None,
            "sector": None,
            "host": None,
            "title": None,
            "ip": ip,
            "reports_24h": None,
        })

    mapped = len(events)
    events = sorted(events, key=lambda event: (event["ts"], event["id"]), reverse=True)[:limit]
    coverage = {
        "attackers_total": total,
        "attackers_in_window": in_window,
        "attackers_mapped": mapped,
    }
    return events, coverage
```

5. Replace `build_document` with:

```python
def build_document(*, claims, hosts, addresses, lookup, incidents=(), sources=(),
                   attackers=(), collected_at, geo_available=True, now=None):
    now = now or parse_iso(collected_at) or datetime.now(timezone.utc)
    lookup = lookup or (lambda address: None)

    claim_list, claim_coverage = claim_events(claims, now=now)
    host_list, host_coverage = host_events(
        hosts, addresses, lookup, collected_at=collected_at
    )
    incident_list, incident_coverage = incident_events(incidents, now=now)
    source_list, source_coverage = source_events(
        sources, lookup=lookup, collected_at=collected_at
    )
    attacker_list, attacker_coverage = attacker_events(
        attackers, lookup=lookup, now=now
    )
    events = sorted(
        claim_list + host_list + incident_list + source_list + attacker_list,
        key=lambda event: (event["ts"], event["id"]),
        reverse=True,
    )[:MAX_EVENTS]

    coverage = {
        **claim_coverage,
        **host_coverage,
        **incident_coverage,
        **source_coverage,
        **attacker_coverage,
        "geo_available": bool(geo_available),
    }
    return envelope(
        "ransomware.live claims and incidents, OpenPhish hosts, SANS ISC "
        "sources and blocklist.de attackers, geolocated with DB-IP Lite",
        SOURCE_URLS,
        updated_at=collected_at,
        note=NOTE,
        window_hours=WINDOW_HOURS,
        attribution={
            "ip_geolocation": ip_country.DB_ATTRIBUTION,
            "license_url": ip_country.DB_LICENSE_URL,
            "sensor_grid": "Data courtesy of SANS Internet Storm Center (https://isc.sans.edu)",
        },
        coverage=coverage,
        events=events,
    )
```

6. In `main()`, load the three new feeds and pass them through:

```python
    incidents_doc = read_json(INCIDENTS_PATH, {}) or {}
    isc_doc = read_json(ISC_PATH, {}) or {}
    attackers_doc = read_json(ATTACKERS_PATH, {}) or {}
    incidents = incidents_doc.get("items") if isinstance(incidents_doc.get("items"), list) else []
    sources = (isc_doc.get("top_ips") or {}).get("items") or []
    attackers = attackers_doc.get("items") if isinstance(attackers_doc.get("items"), list) else []
```

and extend the `build_document(...)` call and the final print:

```python
    document = build_document(
        claims=claims,
        hosts=hosts,
        addresses=addresses,
        lookup=lookup,
        incidents=incidents,
        sources=sources,
        attackers=attackers,
        collected_at=collected_at,
        geo_available=geo_available,
        now=now,
    )
```

```python
    coverage = document["coverage"]
    print(
        f"Wrote {len(document['events'])} live events "
        f"({coverage['claims_mapped']}/{coverage['claims_total']} claims, "
        f"{coverage['incidents_mapped']}/{coverage['incidents_total']} incidents, "
        f"{coverage['hosts_mapped']}/{coverage['hosts_resolved']} resolved hosts "
        f"of {coverage['hosts_total']}, "
        f"{coverage['sources_mapped']}/{coverage['sources_total']} sources, "
        f"{coverage['attackers_mapped']}/{coverage['attackers_total']} attackers)."
    )
```

- [ ] **Step 4: Run tests to verify they pass, then rebuild live.json**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: PASS.

Run: `python3 scripts/live_feed.py`
Expected: prints a five-kind breakdown; `data/live.json` now contains `incident`, `source` and `attacker` events.

- [ ] **Step 5: Commit**

```bash
git add scripts/live_feed.py scripts/tests/test_live_feed.py data/live.json
git commit -m "feat(live): add incident, source and attacker event kinds"
```

---

### Task 5: Register the feeds in the validator and status registry

**Files:**
- Modify: `scripts/validate_feeds.py`
- Modify: `scripts/status.py`
- Modify: `data/status.json` (regenerated)

**Interfaces:**
- Consumes: the three feed shapes from Tasks 1–3, the live event shape from Task 4
- Produces: validation + health coverage for `incidents.json`, `isc.json`, `attackers.json`; registration is what lets the automation collect them (`run_collectors.py --feeds auto` is registry-driven — no orchestrator changes needed).

Note on layout: `isc.json` uses the same section layout as `cves.json` (`top_ips: {total, items}` / `top_ports: {total, items}`), so it registers as `"nested"` and gets per-section sort checks.

- [ ] **Step 1: Write the failing registry/contract tests first (validator tests)**

In `scripts/tests/test_validate_feeds.py`:

1. Extend the `live()` factory to the uniform event shape from Task 4 (add `"title": None, "ip": None, "reports_24h": None` after `"host": None`).

2. Add these factories next to the existing ones:

```python
def incident_item(**overrides):
    record = {
        "id": "inc-1",
        "victim": "Acme Corp",
        "domain": "acme.example",
        "country": "DE",
        "added": "2026-10-28",
        "date": "2026-10-20",
        "title": "Ransomware claim: Acme",
        "summary": "LockBit lists Acme.",
        "link": "https://www.ransomware.live/id/acme",
        "claim_gang": True,
        "infostealer_compromised_users": 42,
    }
    record.update(overrides)
    return record


def isc_top_ip(**overrides):
    record = {
        "ip": "45.155.91.123",
        "reports_24h": 2218,
        "targets": 412,
        "country": "NL",
    }
    record.update(overrides)
    return record


def isc_top_port(**overrides):
    record = {
        "port": 23,
        "records_24h": 152000,
        "targets": 88000,
        "sources": 1200,
    }
    record.update(overrides)
    return record


def attacker_ip(**overrides):
    record = {
        "ip": "45.155.91.123",
        "seen": NOW,
        "country": "NL",
    }
    record.update(overrides)
    return record
```

3. Add these test classes (after `LiveEventTests`):

```python
class NewFeedRecordTests(unittest.TestCase):
    def check(self, record, record_type):
        report = validate_feeds.Report()
        validate_feeds.check_record(record, record_type, "test", report)
        return report

    def test_a_valid_incident_item_passes(self):
        self.assertEqual(self.check(incident_item(), "incident_item").errors, [])

    def test_an_incident_item_needs_a_real_added_date(self):
        report = self.check(incident_item(added="28/10/2026"), "incident_item")
        self.assertTrue(any("added" in error for error in report.errors))

    def test_a_valid_isc_top_ip_passes(self):
        self.assertEqual(self.check(isc_top_ip(), "isc_top_ip").errors, [])

    def test_an_isc_top_ip_with_a_bad_ip_is_rejected(self):
        report = self.check(isc_top_ip(ip="999.1.1.1"), "isc_top_ip")
        self.assertTrue(any("not an IP" in error for error in report.errors))

    def test_a_valid_isc_top_port_passes(self):
        self.assertEqual(self.check(isc_top_port(), "isc_top_port").errors, [])

    def test_port_zero_is_rejected(self):
        report = self.check(isc_top_port(port=0), "isc_top_port")
        self.assertTrue(any("port" in error for error in report.errors))

    def test_a_valid_attacker_ip_passes(self):
        self.assertEqual(self.check(attacker_ip(), "attacker_ip").errors, [])


class NewLiveKindTests(unittest.TestCase):
    def check(self, record):
        report = validate_feeds.Report()
        validate_feeds.check_record(record, "live_event", "test", report)
        return report

    def test_a_valid_incident_event_passes(self):
        record = live(kind="incident", group=None, sector=None, title="Acme breach")
        self.assertEqual(self.check(record).errors, [])

    def test_a_valid_source_event_passes(self):
        record = live(kind="source", group=None, sector=None,
                      ip="45.155.91.123", reports_24h=2218)
        self.assertEqual(self.check(record).errors, [])

    def test_a_valid_attacker_event_passes(self):
        record = live(kind="attacker", group=None, sector=None, ip="45.155.91.123")
        self.assertEqual(self.check(record).errors, [])

    def test_a_source_event_without_reports_is_rejected(self):
        record = live(kind="source", group=None, sector=None,
                      ip="45.155.91.123", reports_24h=None)
        self.assertTrue(any("reports_24h" in error for error in self.check(record).errors))

    def test_an_incident_event_carrying_an_ip_is_rejected(self):
        record = live(kind="incident", group=None, sector=None,
                      title="x", ip="45.155.91.123")
        self.assertTrue(any("incident event must not carry" in error
                            for error in self.check(record).errors))


class NewFeedValidationTests(unittest.TestCase):
    def validate(self, name, document):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(json.dumps(document), encoding="utf-8")
            report = validate_feeds.Report()
            validate_feeds.validate_feed(path, report, check_regression=False, ref=None)
        return report

    def test_incidents_json_validates_end_to_end(self):
        report = self.validate("incidents.json", {
            "schema_version": 1, "updated_at": NOW,
            "source": "ransomware.live recent cyber incidents",
            "source_url": "https://api.ransomware.live/v2/recentcyberattacks",
            "total": 1, "items": [incident_item()],
        })
        self.assertEqual(report.errors, [])

    def test_isc_json_validates_with_both_sections(self):
        report = self.validate("isc.json", {
            "schema_version": 1, "updated_at": NOW,
            "source": "SANS Internet Storm Center sensor grid",
            "source_url": ["https://isc.sans.edu/api/topips/records/25",
                           "https://isc.sans.edu/api/topports/records/10"],
            "top_ips": {"total": 1, "items": [isc_top_ip()]},
            "top_ports": {"total": 1, "items": [isc_top_port()]},
        })
        self.assertEqual(report.errors, [])

    def test_attackers_json_validates_end_to_end(self):
        report = self.validate("attackers.json", {
            "schema_version": 1, "updated_at": NOW,
            "source": "blocklist.de fail2ban reports (last hour)",
            "source_url": "https://www.blocklist.de/getlast.php?time=3600",
            "total": 1, "items": [attacker_ip()],
        })
        self.assertEqual(report.errors, [])
```

Run: `python3 -m unittest scripts.tests.test_validate_feeds -v`
Expected: FAIL. The rejection tests fail first (unknown record types are checked vacuously, and `kind: "source"` is not in `LIVE_EVENT_KINDS` yet). The "valid ... passes" and end-to-end tests are vacuous until Step 2 registers the types — they become real assertions from then on.

- [ ] **Step 2: Register the feeds in `validate_feeds.py`**

1. `EXPECTED_SCHEMA_VERSION` (after the `"live.json": 1` line):

```python
    "incidents.json": 1,
    "isc.json": 1,
    "attackers.json": 1,
```

2. `LIVE_EVENT_KINDS`:

```python
LIVE_EVENT_KINDS = {"claim", "host", "incident", "source", "attacker"}
```

3. `CONTRACT` — replace the `live_event` block and add four new record blocks after it:

```python
    "live_event": {
        "id": "str -- stable event ID",
        "kind": f"enum -- one of {sorted(LIVE_EVENT_KINDS)}",
        "ts": ("iso_datetime -- claim=published, incident=added (00:00 UTC), "
               "host/source=snapshot time, attacker=seen"),
        "country": "str -- ISO 3166-1 alpha-2; the country the event is plotted in",
        "group": "nullable_str -- ransomware group, claim events only",
        "sector": "nullable_str -- claimed victim sector, claim events only",
        "host": "nullable_str -- phishing hostname, host events only",
        "title": "nullable_str -- incident headline, incident events only",
        "ip": "nullable_str -- observed attacking IP, source/attacker events only",
        "reports_24h": "nullable_int -- sensor-grid reports, source events only",
    },
    "incident_item": {
        "id": "str",
        "victim": "nullable_str",
        "domain": "nullable_str -- victim domain, lowercased",
        "country": "nullable_str -- ISO 3166-1 alpha-2",
        "added": "iso_date -- the day ransomware.live recorded the claim",
        "date": "nullable_iso_date -- incident date claimed by the source",
        "title": "nullable_str",
        "summary": "str -- markup stripped, truncated to 300 chars",
        "link": "url",
        "claim_gang": "bool -- ransom demand vs disclosure-only",
        "infostealer_compromised_users": "nullable_int",
    },
    "isc_top_ip": {
        "ip": "str",
        "reports_24h": "int -- reports seen by the sensor grid in its own ~24h window",
        "targets": "int",
        "country": "nullable_str -- DB-IP Lite lookup at collection time",
    },
    "isc_top_port": {
        "port": "int -- 1..65535",
        "records_24h": "int",
        "targets": "int",
        "sources": "int",
    },
    "attacker_ip": {
        "ip": "str",
        "seen": "iso_datetime -- collection time; the API has no per-report timestamp",
        "country": "nullable_str -- DB-IP Lite lookup at collection time",
    },
```

4. `FEED_SPECS` (after the `"live.json"` line):

```python
    "incidents.json": ("flat", [(("items",), "incident_item", None)]),
    "isc.json": ("nested", [(("top_ips", "items"), "isc_top_ip", "top_ips"),
                            (("top_ports", "items"), "isc_top_port", "top_ports")]),
    "attackers.json": ("flat", [(("items",), "attacker_ip", None)]),
```

5. `SORTED_FEEDS` — note the key must match what `validate_feed` computes for nested sections (`f"{feed}:{'.'.join(list_path)}"`, i.e. the section path *including* the trailing `items`):

```python
    "incidents.json": ("added", True),
    "isc.json:top_ips.items": ("reports_24h", True),
    "isc.json:top_ports.items": ("records_24h", True),
```

6. In `validate_feed`, the duplicate-key line — replace:

```python
        check_duplicates(items, "name" if record_type == "program" else "id", where_list, report)
```

with:

```python
        if record_type == "program":
            dup_key = "name"
        elif record_type in ("isc_top_ip", "attacker_ip"):
            dup_key = "ip"
        elif record_type == "isc_top_port":
            dup_key = "port"
        else:
            dup_key = "id"
        check_duplicates(items, dup_key, where_list, report)
```

and teach `check_duplicates` to accept int keys (ports) — change:

```python
        value = item.get(key)
        if not isinstance(value, str):
            continue
        identity = value.lower() if key == "name" else value
```

to:

```python
        value = item.get(key)
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            continue
        identity = value.lower() if key == "name" else value
```

7. In `check_record`, extend the `live_event` block and add the new record checks. Replace the existing `if record_type == "live_event":` block with:

```python
    if record_type == "live_event":
        kind = item.get("kind")
        if kind not in LIVE_EVENT_KINDS:
            report.fail(f"{where}.kind", f"{kind!r} is not one of {sorted(LIVE_EVENT_KINDS)}")
        check_timestamp(item.get("ts"), allow_null=False,
                        where=f"{where}.ts", report=report)
        country = item.get("country")
        if not isinstance(country, str) or not COUNTRY_CODE.fullmatch(country):
            report.fail(f"{where}.country",
                        f"{country!r} is not an ISO 3166-1 alpha-2 code")
        group = item.get("group")
        sector = item.get("sector")
        host = item.get("host")
        title = item.get("title")
        ip = item.get("ip")
        reports = item.get("reports_24h")
        if kind == "claim":
            if host is not None or title is not None or ip is not None or reports is not None:
                report.fail(where, "a claim event must not carry host/title/ip/reports fields")
            if not isinstance(group, str) or not group.strip():
                report.fail(f"{where}.group", "a claim event needs a group (or 'Unattributed')")
        elif kind == "host":
            if group is not None or sector is not None or title is not None \
                    or ip is not None or reports is not None:
                report.fail(where, "a host event must not carry claim/title/ip/reports fields")
            if not isinstance(host, str) or not HOSTNAME.match(host.lower()):
                report.fail(f"{where}.host", f"{host!r} is not a hostname")
        elif kind == "incident":
            if group is not None or sector is not None or host is not None \
                    or ip is not None or reports is not None:
                report.fail(where, "an incident event must not carry claim/host/ip/reports fields")
            if title is not None and not isinstance(title, str):
                report.fail(f"{where}.title", "must be a string or null")
        elif kind == "source":
            if group is not None or sector is not None or host is not None \
                    or title is not None:
                report.fail(where, "a source event must not carry claim/host/title fields")
            check_ip_field(item, "ip", where, report, required=True)
            if not isinstance(reports, int) or isinstance(reports, bool) or reports < 0:
                report.fail(f"{where}.reports_24h", "a source event needs a non-negative int")
        elif kind == "attacker":
            if group is not None or sector is not None or host is not None \
                    or title is not None or reports is not None:
                report.fail(where, "an attacker event must not carry claim/host/title/reports fields")
            check_ip_field(item, "ip", where, report, required=True)
```

Add the helper and record checks (place the helper above `check_record`):

```python
def check_ip_field(item, field, where, report, *, required):
    value = item.get(field)
    if value is None:
        if required:
            report.fail(f"{where}.{field}", "must not be null")
        return
    try:
        ipaddress.ip_address(value)
    except ValueError:
        report.fail(f"{where}.{field}", f"{value!r} is not an IP address")
```

(also add `import ipaddress` to the imports at the top of `validate_feeds.py`)

```python
    if record_type == "incident_item":
        check_timestamp(item.get("added"), allow_null=False, date_only=True,
                        where=f"{where}.added", report=report)
        check_timestamp(item.get("date"), allow_null=True, date_only=True,
                        where=f"{where}.date", report=report)
        if not isinstance(item.get("claim_gang"), bool):
            report.fail(f"{where}.claim_gang", "must be a bool")
        compromised = item.get("infostealer_compromised_users")
        if compromised is not None and (
                not isinstance(compromised, int) or isinstance(compromised, bool) or compromised < 0):
            report.fail(f"{where}.infostealer_compromised_users",
                        "must be a non-negative int or null")
        country = item.get("country")
        if country is not None and (not isinstance(country, str) or not COUNTRY_CODE.fullmatch(country)):
            report.fail(f"{where}.country", f"{country!r} is not an ISO 3166-1 alpha-2 code")
        domain = item.get("domain")
        if domain is not None and (not isinstance(domain, str) or not HOSTNAME.match(domain.lower())):
            report.fail(f"{where}.domain", f"{domain!r} is not a hostname")
        check_url(item.get("link"), allow_null=False, where=f"{where}.link", report=report)

    if record_type in ("isc_top_ip", "attacker_ip"):
        check_ip_field(item, "ip", where, report, required=True)
        country = item.get("country")
        if country is not None and (not isinstance(country, str) or not COUNTRY_CODE.fullmatch(country)):
            report.fail(f"{where}.country", f"{country!r} is not an ISO 3166-1 alpha-2 code")
        if record_type == "isc_top_ip":
            for field in ("reports_24h", "targets"):
                value = item.get(field)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    report.fail(f"{where}.{field}", "must be a non-negative int")
        else:
            check_timestamp(item.get("seen"), allow_null=False,
                            where=f"{where}.seen", report=report)

    if record_type == "isc_top_port":
        port = item.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            report.fail(f"{where}.port", f"{port!r} is not a TCP/UDP port number")
        for field in ("records_24h", "targets", "sources"):
            value = item.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                report.fail(f"{where}.{field}", "must be a non-negative int")
```

- [ ] **Step 3: Run validator tests**

Run: `python3 -m unittest discover -s scripts/tests -t scripts -v`
Expected: PASS.

- [ ] **Step 4: Register the sources in `status.py`**

1. Insert three entries in `SOURCES` **between the `"phishing"` and `"advisories"` entries** (so they run before the derived `iocs` and `live` sources):

```python
    "incidents": {
        "label": "ransomware.live recent cyber incidents",
        "url": "https://api.ransomware.live/v2/recentcyberattacks",
        "cadence_minutes": 180,
        "critical": False,
        "script": "incidents_feed.py",
        "feeds": ["incidents.json"],
        "primary_feed": "incidents.json",
    },
    "isc": {
        "label": "SANS Internet Storm Center",
        "url": [
            "https://isc.sans.edu/api/topips/records/25",
            "https://isc.sans.edu/api/topports/records/10",
        ],
        "cadence_minutes": 60,
        "critical": False,
        "script": "isc_feed.py",
        "feeds": ["isc.json"],
        "primary_feed": "isc.json",
    },
    "attackers": {
        "label": "blocklist.de last-hour attacker IPs",
        "url": "https://www.blocklist.de/getlast.php?time=3600",
        "cadence_minutes": 60,
        "critical": False,
        "script": "attackers_feed.py",
        "feeds": ["attackers.json"],
        "primary_feed": "attackers.json",
    },
```

2. In the `"live"` source, replace `url` with:

```python
        "url": [
            "https://api.ransomware.live/v2/recentvictims",
            "https://openphish.com/feed.txt",
            "https://api.ransomware.live/v2/recentcyberattacks",
            "https://isc.sans.edu/api/topips/records/25",
            "https://www.blocklist.de/getlast.php?time=3600",
        ],
```

3. In `feed_totals`, extend the section loop so `isc.json` counts both sections (the validator cross-checks `status.items` against these totals):

```python
        for section in ("recent", "actively_exploited", "top_ips", "top_ports"):
            value = document.get(section)
            if isinstance(value, dict) and isinstance(value.get("items"), list):
                total += len(value["items"])
```

- [ ] **Step 5: Regenerate status.json and validate everything**

Run: `python3 scripts/run_collectors.py --feeds incidents,isc,attackers,live`
Expected: four sources run; `data/status.json` lists the three new sources plus live.

Run: `python3 scripts/validate_feeds.py --against HEAD`
Expected: exit 0, no errors (the three new feeds are registered and covered by status.json).

- [ ] **Step 6: Commit**

```bash
git add scripts/validate_feeds.py scripts/status.py scripts/tests/test_validate_feeds.py data/status.json data/incidents.json data/isc.json data/attackers.json data/live.json
git commit -m "feat(feeds): register incidents, isc and attackers in validator and status"
```

---

### Task 6: Generalize `assets/live-map.js` to five kinds

**Files:**
- Modify: `assets/live-map.js`
- Modify: `assets/live-map.test.mjs`

**Interfaces:**
- Consumes: the uniform live event shape from Task 4
- Produces (Task 7 depends on these exact names):
  - `EVENT_KINDS` — frozen array `['claim', 'incident', 'host', 'source', 'attacker']`
  - `KIND_LABELS` — frozen map kind → display plural (`Claims`, `Incidents`, `Phishing hosts`, `ISC sources`, `Attacker IPs`)
  - `KIND_SHORT` — frozen map kind → ticker noun (`claim`, `incident`, `hosting`, `ISC source`, `attacker IP`)
  - `hourlyBuckets(events, {end, hours})` → `[{start, total, byKind: {claim, incident, host, source, attacker}}]`
  - `aggregateEvents(events, {end, head, hours})` → `{total, unmapped, max, countries: [{code, total, byKind, latest, groups}]}` — `groups` stays claims-only
  - `eventLabel(event)` extended for the new kinds
  - `eventsInWindow`, `eventTime`, `cumulative`, `newEventIds`, `ingestState`, `pulseRadius`, `pulseCount` — unchanged

- [ ] **Step 1: Update the tests**

In `assets/live-map.test.mjs`:

1. Update the shared `event()` factory to the uniform shape:

```js
const event = (overrides = {}) => ({
  id: 'rw-1',
  kind: 'claim',
  ts: '2026-10-28T06:00:00Z',
  country: 'US',
  group: 'LockBit',
  sector: 'Manufacturing',
  host: null,
  title: null,
  ip: null,
  reports_24h: null,
  ...overrides,
});
```

2. Replace the `hourlyBuckets` placement test's deepEqual expectations with the `byKind` shape:

```js
test('hourlyBuckets: places events in the right hour and counts kinds apart', () => {
  const buckets = hourlyBuckets([
    event({ kind: 'claim', ts: hoursAgo(0) }),
    event({ kind: 'host', ts: hoursAgo(0) }),
    event({ kind: 'claim', ts: hoursAgo(1.5) }),
    event({ kind: 'incident', ts: hoursAgo(71.5) }),
    event({ kind: 'claim', ts: hoursAgo(80) }),
  ], { end: NOW, hours: 72 });

  assert.deepEqual(buckets[71], {
    start: NOW - HOUR,
    total: 2,
    byKind: { claim: 1, incident: 0, host: 1, source: 0, attacker: 0 },
  });
  assert.deepEqual(buckets[70].byKind.claim, 1);
  assert.deepEqual(buckets[0].byKind.incident, 1);
  assert.equal(buckets.reduce((sum, bucket) => sum + bucket.total, 0), 4);
});
```

3. Replace the `aggregateEvents` expectations:

```js
test('aggregateEvents: reports per-kind counts per country, busiest first', () => {
  const aggregate = aggregateEvents([
    event({ id: 'a', country: 'US' }),
    event({ id: 'b', country: 'US', group: 'Qilin' }),
    event({ id: 'c', country: 'US', kind: 'incident', group: null }),
    event({ id: 'd', country: 'DE' }),
    event({ id: 'e', country: 'DE', kind: 'host', group: null, host: 'x.example' }),
    event({ id: 'f', country: 'CA', kind: 'source', group: null, ip: '1.2.3.4', reports_24h: 9 }),
    event({ id: 'g', country: 'CA', kind: 'attacker', group: null, ip: '5.6.7.8' }),
  ], { end: NOW });

  assert.equal(aggregate.total, 7);
  assert.equal(aggregate.max, 3);
  const us = aggregate.countries.find((entry) => entry.code === 'US');
  assert.deepEqual(us.byKind,
    { claim: 2, incident: 1, host: 0, source: 0, attacker: 0 });
  const ca = aggregate.countries.find((entry) => entry.code === 'CA');
  assert.equal(ca.byKind.source, 1);
  assert.equal(ca.byKind.attacker, 1);
});

test('aggregateEvents: degrades to an empty result', () => {
  const aggregate = aggregateEvents(undefined, { end: NOW });
  assert.deepEqual(aggregate,
    { total: 0, unmapped: 0, max: 0, countries: [] });
});
```

(Delete the old tests that assert `claims`/`hosts` fields — those fields no longer exist.)

4. Extend the `eventLabel` test:

```js
test('eventLabel: every kind speaks in the feed\'s own vocabulary', () => {
  assert.equal(eventLabel(event()), 'LockBit claim · Manufacturing');
  assert.equal(eventLabel(event({ sector: null })), 'LockBit claim');
  assert.equal(eventLabel(event({ kind: 'host', group: null, host: 'x.example' })), 'Phishing host · x.example');
  assert.equal(eventLabel(event({ kind: 'incident', group: null, title: 'Acme breach' })), 'Incident · Acme breach');
  assert.equal(eventLabel(event({ kind: 'incident', group: null, title: null })), 'Incident');
  assert.equal(eventLabel(event({ kind: 'source', group: null, ip: '1.2.3.4', reports_24h: 2218 })),
    'Observed source 1.2.3.4 · 2218 reports/24h');
  assert.equal(eventLabel(event({ kind: 'attacker', group: null, ip: '5.6.7.8' })), 'Attacker IP 5.6.7.8');
});

test('kind label maps cover every kind', () => {
  for (const kind of EVENT_KINDS) {
    assert.ok(KIND_LABELS[kind], kind);
    assert.ok(KIND_SHORT[kind], kind);
  }
});
```

(update the import list to include `EVENT_KINDS`, `KIND_LABELS`, `KIND_SHORT`)

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test assets`
Expected: FAIL — `EVENT_KINDS` is not exported / old assertions fail.

- [ ] **Step 3: Implement the generalization**

In `assets/live-map.js`:

1. Add after `WINDOW_HOURS`:

```js
export const EVENT_KINDS = Object.freeze(['claim', 'incident', 'host', 'source', 'attacker']);

export const KIND_LABELS = Object.freeze({
  claim: 'Claims',
  incident: 'Incidents',
  host: 'Phishing hosts',
  source: 'ISC sources',
  attacker: 'Attacker IPs',
});

export const KIND_SHORT = Object.freeze({
  claim: 'claim',
  incident: 'incident',
  host: 'hosting',
  source: 'ISC source',
  attacker: 'attacker IP',
});
```

2. Replace `hourlyBuckets`:

```js
export function hourlyBuckets(events, { end = Date.now(), hours = WINDOW_HOURS } = {}) {
  const buckets = Array.from({ length: hours }, (_, index) => ({
    start: end - (hours - index) * HOUR_MS,
    total: 0,
    byKind: Object.fromEntries(EVENT_KINDS.map((kind) => [kind, 0])),
  }));

  for (const event of eventsInWindow(events, { end, hours })) {
    const offset = Math.floor((end - eventTime(event)) / HOUR_MS);
    if (offset < 0 || offset >= hours) continue;
    const bucket = buckets[hours - 1 - offset];
    if (EVENT_KINDS.includes(event.kind)) bucket.byKind[event.kind] += 1;
    bucket.total += 1;
  }
  return buckets;
}
```

3. Replace `aggregateEvents`:

```js
export function aggregateEvents(events, { end = Date.now(), head = end, hours = WINDOW_HOURS } = {}) {
  const byCode = new Map();
  let total = 0;
  let unmapped = 0;

  for (const event of eventsInWindow(events, { end, head, hours })) {
    total += 1;
    const code = String(event.country ?? '').trim().toUpperCase();
    if (!ISO2.test(code)) {
      unmapped += 1;
      continue;
    }

    let entry = byCode.get(code);
    if (!entry) {
      entry = {
        code,
        total: 0,
        byKind: Object.fromEntries(EVENT_KINDS.map((kind) => [kind, 0])),
        latest: null,
        latestTime: -Infinity,
        groups: new Map(),
      };
      byCode.set(code, entry);
    }
    entry.total += 1;
    if (EVENT_KINDS.includes(event.kind)) entry.byKind[event.kind] += 1;

    if (event.kind === 'claim') {
      const group = String(event.group ?? '').trim() || 'Unattributed';
      entry.groups.set(group, (entry.groups.get(group) || 0) + 1);
    }

    const time = eventTime(event);
    if (time !== null && time > entry.latestTime) {
      entry.latestTime = time;
      entry.latest = event.ts;
    }
  }

  const countries = [...byCode.values()]
    .map((entry) => ({
      code: entry.code,
      total: entry.total,
      byKind: entry.byKind,
      latest: entry.latest,
      groups: [...entry.groups]
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => b.total - a.total || a.code.localeCompare(b.code));

  return {
    total,
    unmapped,
    max: countries.length ? countries[0].total : 0,
    countries,
  };
}
```

4. Replace `eventLabel`:

```js
export function eventLabel(event) {
  if (!event) return '';
  switch (event.kind) {
    case 'host':
      return event.host ? `Phishing host · ${event.host}` : 'Phishing host';
    case 'incident':
      return event.title ? `Incident · ${event.title}` : 'Incident';
    case 'source':
      return event.ip
        ? `Observed source ${event.ip} · ${event.reports_24h ?? '—'} reports/24h`
        : 'Observed source';
    case 'attacker':
      return event.ip ? `Attacker IP ${event.ip}` : 'Attacker IP';
    default: {
      const group = String(event.group ?? '').trim() || 'Unattributed';
      return event.sector ? `${group} claim · ${event.sector}` : `${group} claim`;
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test assets`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add assets/live-map.js assets/live-map.test.mjs
git commit -m "feat(map): generalize live-map helpers to five event kinds"
```

---

### Task 7: Upgrade `map.html` — layer chips, 15-item ticker, per-kind counters

**Files:**
- Modify: `map.html`

**Interfaces:**
- Consumes: `EVENT_KINDS`, `KIND_LABELS`, `KIND_SHORT`, `byKind`-shaped aggregates from Task 6; coverage keys from Task 4
- Produces: the shipped map page. No module exports (inline page script).

- [ ] **Step 1: Markup — counters, chips, table, legend, provenance**

1. Replace the stat grid (the `<div class="stat-grid">` with `stat-claims`/`stat-hosts`/`stat-countries`/`stat-latest`) with:

```html
  <div class="stat-grid">
    <div class="stat-card"><div class="num" id="stat-events">—</div><div class="lbl">events · 24h</div></div>
    <div class="stat-card"><div class="num" id="stat-claims">—</div><div class="lbl">victim claims · 24h</div></div>
    <div class="stat-card"><div class="num" id="stat-incidents">—</div><div class="lbl">incident claims · 24h</div></div>
    <div class="stat-card"><div class="num" id="stat-ips">—</div><div class="lbl">observed attacker IPs · 24h</div></div>
    <div class="stat-card"><div class="num" id="stat-latest">—</div><div class="lbl">newest event</div></div>
  </div>
```

2. Replace the layer `seg-group` (three buttons with `data-layer`) with five kind chips:

```html
      <div class="seg-group" role="group" aria-label="Map layers" id="layer-chips">
        <button type="button" class="seg" data-kind="claim" aria-pressed="true">Claims</button>
        <button type="button" class="seg" data-kind="incident" aria-pressed="true">Incidents</button>
        <button type="button" class="seg" data-kind="host" aria-pressed="true">Phishing hosts</button>
        <button type="button" class="seg" data-kind="source" aria-pressed="true">ISC sources</button>
        <button type="button" class="seg" data-kind="attacker" aria-pressed="true">Attacker IPs</button>
      </div>
```

3. Update the table header (add Incidents and IPs columns):

```html
        <tr>
          <th scope="col">Country</th>
          <th scope="col">Claims</th>
          <th scope="col">Incidents</th>
          <th scope="col">Phishing hosts</th>
          <th scope="col">Attacker IPs</th>
          <th scope="col">Total</th>
          <th scope="col">Top group</th>
          <th scope="col">Latest event</th>
        </tr>
```

4. Replace the provenance list with five honest layers:

```html
      <ul class="provenance">
        <li><strong>Victim claims</strong> — ransomware leak-site victims published in the last 72 hours, shown in the country the claim names (ransomware.live).</li>
        <li><strong>Incident claims</strong> — public claims of breaches, infostealer exposures and hacktivist activity recorded in the last 72 hours, shown in the country the record names (ransomware.live). A claim is not confirmation of an attack.</li>
        <li><strong>Phishing hosting</strong> — hostnames in the current OpenPhish snapshot, resolved at collection time; the country is where the IP is registered, not where the attacker sits.</li>
        <li><strong>ISC sources / Attacker IPs</strong> — attacker IPs observed by the SANS Internet Storm Center sensor grid (~24h window) and reported to blocklist.de in the last hour, plotted at the attacking IP's geolocation. A marker is an observed IP, not an attack in progress.</li>
        <li><strong>No source-to-destination arcs.</strong> No publishable feed records attacker origin, so the map shows where events are recorded rather than inventing a path.</li>
        <li>Sources: <a href="https://isc.sans.edu" target="_blank" rel="noopener">SANS Internet Storm Center</a> (attribution required), <a href="https://www.blocklist.de" target="_blank" rel="noopener">blocklist.de</a>, OpenPhish. IP geolocation: <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a>, <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener">CC BY 4.0</a>.</li>
      </ul>
```

5. Update `<title>`/description and the `<h1>` sub to mention all layers:

```html
<meta name="description" content="Ransomware claims, incident claims, phishing hosting and observed attacker IPs plotted from live feeds, with a 72-hour replay and an explicit freshness banner.">
```

```html
  <p class="sub">Ransomware victim claims, public incident claims, phishing hosting and observed attacker IPs, plotted from the feeds as the collectors publish them. Every ring is a record with a timestamp: a quiet hour is a quiet feed, not a quiet internet. No layer claims to be an attack in progress — no publishable feed records that.</p>
```

- [ ] **Step 2: CSS — kind colors, scrollable ticker, legend dots**

In the page-local `<style>`:

```css
  .kind.incident { color: var(--crit); }
  .kind.source { color: var(--ok); }
  .kind.attacker { color: var(--med); }

  .spark .k-claim { background: rgba(249, 115, 22, 0.55); border-radius: 1px 1px 0 0; }
  .spark .k-incident { background: rgba(255, 92, 92, 0.55); border-radius: 1px 1px 0 0; }
  .spark .k-host { background: rgba(92, 200, 255, 0.45); border-radius: 1px 1px 0 0; }
  .spark .k-source { background: rgba(61, 220, 151, 0.5); border-radius: 1px 1px 0 0; }
  .spark .k-attacker { background: rgba(224, 180, 84, 0.5); border-radius: 1px 1px 0 0; }

  .ticker { max-height: 430px; overflow-y: auto; padding-right: 4px; }

  .kind-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin: 0 5px 0 12px;
  }
  .kind-dot.k-claim { background: rgba(249, 115, 22, 0.8); }
  .kind-dot.k-incident { background: rgba(255, 92, 92, 0.8); }
  .kind-dot.k-host { background: rgba(92, 200, 255, 0.8); }
  .kind-dot.k-source { background: rgba(61, 220, 151, 0.8); }
  .kind-dot.k-attacker { background: rgba(224, 180, 84, 0.8); }
```

and delete the old `.spark .claims` / `.spark .hosts` rules (replaced by `.k-*`).

- [ ] **Step 3: Script — layer state and filtering**

1. Update the import to include the new exports:

```js
import {
  EVENT_KINDS,
  KIND_LABELS,
  KIND_SHORT,
  WINDOW_HOURS,
  aggregateEvents,
  eventLabel,
  eventTime,
  eventsInWindow,
  hourlyBuckets,
  ingestState,
  newEventIds,
  pulseCount,
  pulseRadius,
} from '/assets/live-map.js';
```

2. Replace `let layer = 'claims';` with:

```js
const layers = new Set(EVENT_KINDS);
/* Kinds with real per-event timestamps worth ringing on arrival. Hosts and
   sources all share one snapshot timestamp, so ringing them every poll is
   noise; their countries still flash. */
const PULSE_KINDS = new Set(['claim', 'incident', 'attacker']);
```

3. Replace `currentEvents()`:

```js
function currentEvents() {
  const group = groupSelect.value;
  return events.filter((event) => {
    if (!layers.has(event.kind)) return false;
    if (group) return event.kind === 'claim' && event.group === group;
    return true;
  });
}
```

4. Replace `metric(country)` with:

```js
function countByLayers(country) {
  let count = 0;
  for (const kind of EVENT_KINDS) {
    if (layers.has(kind)) count += country.byKind[kind] || 0;
  }
  return count;
}
```

5. In `paintMap`, replace the `painted`/`max` computation and `describe`:

```js
  const painted = countries
    .map((country) => ({ ...country, count: countByLayers(country) }))
    .filter((country) => country.count > 0);
  const max = aggregate.countries.reduce((peak, country) => Math.max(peak, countByLayers(country)), 0);
  const describe = (code, country) => {
    const parts = [];
    for (const kind of EVENT_KINDS) {
      const count = country.byKind[kind] || 0;
      if (!count || !layers.has(kind)) continue;
      parts.push(`${count} ${KIND_LABELS[kind].toLowerCase()}`);
    }
    return `${countryName(code)} · ${parts.join(', ') || 'no events in the selected layers'}`;
  };
```

- [ ] **Step 4: Script — ticker, table, sparkline, counters**

1. Replace `renderTicker` (drop the host-capping special case — kind chips make hosts distinguishable; show the newest 15):

```js
function renderTicker(visible) {
  const items = visible.slice(0, 15);
  document.getElementById('ticker').innerHTML = items.length
    ? items.map((event) => `<li>
        <time datetime="${esc(event.ts)}">${esc(timeAgo(event.ts))}</time>
        <span class="kind ${esc(event.kind)}">${esc(KIND_SHORT[event.kind] || event.kind)}</span>
        <button type="button" class="country-button" data-code="${esc(event.country)}">${esc(countryName(event.country))}</button>
        <span class="ticker-label">${esc(eventLabel(event))}</span>
      </li>`).join('')
    : '<li><span class="ticker-label">No event in the selected window.</span></li>';
}
```

2. Replace `row(country)` and the empty-row colspan (6 → 8):

```js
function row(country) {
  const top = country.groups[0];
  const topLabel = top ? `${top.name} (${top.count})` : '—';
  const ips = (country.byKind.source || 0) + (country.byKind.attacker || 0);
  return `<tr${country.code === selected ? ' class="sel"' : ''}>
    <td><button type="button" class="country-button" data-code="${esc(country.code)}">${esc(countryName(country.code))}</button> <span class="code">${esc(country.code)}</span></td>
    <td class="num">${country.byKind.claim}</td>
    <td class="num">${country.byKind.incident}</td>
    <td class="num">${country.byKind.host}</td>
    <td class="num">${ips}</td>
    <td class="num">${country.total}</td>
    <td class="top-group">${esc(topLabel)}</td>
    <td class="top-group">${esc(timeAgo(country.latest))}</td>
  </tr>`;
}
```

```js
    : '<tr><td colspan="8" class="empty">No country has an event in this window and filter.</td></tr>';
```

3. Replace `renderSpark` (stack only the enabled kinds; the last present segment absorbs rounding):

```js
function renderSpark() {
  const buckets = hourlyBuckets(currentEvents(), { end: now });
  const active = EVENT_KINDS.filter((kind) => layers.has(kind));
  const peak = Math.max(1, ...buckets.map((bucket) => bucket.total));
  spark.innerHTML = buckets
    .map((bucket) => {
      const total = Math.max(2, Math.round((bucket.total / peak) * 42));
      const present = active.filter((kind) => (bucket.byKind[kind] || 0) > 0);
      let used = 0;
      const parts = present.map((kind, index) => {
        const height = index === present.length - 1
          ? total - used
          : Math.round(((bucket.byKind[kind] || 0) / bucket.total) * total);
        used += height;
        return `<i class="k-${kind}" style="height:${height}px"></i>`;
      });
      return `<span class="bar">${parts.join('')}</span>`;
    })
    .join('');
  const marker = document.createElement('span');
  marker.className = 'spark-head';
  marker.id = 'spark-head';
  spark.append(marker);
}
```

4. In `render()`, replace the four `stat-*` updates with the five-card version:

```js
  const counts24 = Object.fromEntries(EVENT_KINDS.map((kind) => [kind, 0]));
  let total24 = 0;
  for (const event of visible) {
    const time = eventTime(event);
    if (time === null || time <= now - 24 * HOUR) continue;
    counts24[event.kind] = (counts24[event.kind] || 0) + 1;
    total24 += 1;
  }
  document.getElementById('stat-events').textContent = total24.toLocaleString('en-US');
  document.getElementById('stat-claims').textContent = counts24.claim.toLocaleString('en-US');
  document.getElementById('stat-incidents').textContent = counts24.incident.toLocaleString('en-US');
  document.getElementById('stat-ips').textContent = (counts24.source + counts24.attacker).toLocaleString('en-US');
  document.getElementById('stat-latest').textContent = visible.length ? timeAgo(visible[0].ts) : '—';
```

(`visible` is already layer-filtered via `currentEvents()`.)

- [ ] **Step 5: Script — pulses, legend, coverage, wiring**

1. In `spawnPulse`, replace the layer gate:

```js
function spawnPulse(code, count, peak) {
  if (reduceMotion || activePulses >= 48) return;
  if (![...PULSE_KINDS].some((kind) => layers.has(kind))) return;
```

2. Rename `pulseClaims` to `pulseEvents` and count every pulse-capable enabled kind:

```js
function pulseEvents(list) {
  const perCountry = new Map();
  for (const event of list) {
    if (!PULSE_KINDS.has(event.kind) || !layers.has(event.kind)) continue;
    perCountry.set(event.country, (perCountry.get(event.country) || 0) + 1);
  }
  const peak = Math.max(1, ...perCountry.values());
  for (const [code, count] of perCountry) spawnPulse(code, count, peak);
}
```

Update its two call sites: in `setHoursBack` (`pulseClaims(...)` → `pulseEvents(...)`) and in `poll()` (same rename; keep `flashCountries(freshEvents)` but drop the `.filter((event) => event.kind === 'claim')` so incidents and attacker IPs flash their countries too).

3. Replace `renderLegend` (the old one branches on `layer`, which no longer exists):

```js
function renderLegend() {
  document.getElementById('legend-title').textContent = 'Events vs busiest country';
  document.getElementById('legend-pulse').hidden = ![...PULSE_KINDS].some((kind) => layers.has(kind));
  document.getElementById('legend-kinds').innerHTML = EVENT_KINDS
    .filter((kind) => layers.has(kind))
    .map((kind) => `<i class="kind-dot k-${kind}"></i>${esc(KIND_LABELS[kind])}`)
    .join('');
}
```

and add `<span id="legend-kinds"></span>` to `.map-legend` after the pulse span:

```html
      <span id="legend-pulse"><i class="pulse-key"></i>new event</span>
      <span id="legend-kinds"></span>
```

4. Replace `renderCoverage` body:

```js
function renderCoverage() {
  const note = document.getElementById('coverage-note');
  if (!live) {
    note.textContent = 'The live feed is unavailable. The map stays blank rather than presenting old events as live.';
    return;
  }
  const coverage = live.coverage || {};
  const claims = `${coverage.claims_mapped ?? 0} of ${coverage.claims_in_window ?? 0}`;
  const incidents = `${coverage.incidents_mapped ?? 0} of ${coverage.incidents_in_window ?? 0}`;
  const hosts = `${coverage.hosts_mapped ?? 0} of ${coverage.hosts_resolved ?? 0}`;
  const sources = `${coverage.sources_mapped ?? 0} of ${coverage.sources_total ?? 0}`;
  const attackers = `${coverage.attackers_mapped ?? 0} of ${coverage.attackers_total ?? 0}`;
  note.innerHTML = `Placed at country level: <strong>${claims}</strong> claims and `
    + `<strong>${incidents}</strong> incident claims published in the window, `
    + `<strong>${hosts}</strong> resolved phishing hosts (${coverage.hosts_total ?? 0} in the snapshot), `
    + `<strong>${sources}</strong> ISC source IPs and <strong>${attackers}</strong> blocklist.de attacker IPs. `
    + 'Records without a country are counted, never guessed.'
    + (coverage.geo_available === false
      ? ' The country database was unavailable for this run, so the IP-based layers are not shown.'
      : '');
}
```

5. Replace the seg wiring and `syncSeg` (the old `.seg` selector and `data-layer` handler):

```js
function syncSeg() {
  for (const button of document.querySelectorAll('#layer-chips .seg')) {
    button.setAttribute('aria-pressed', String(layers.has(button.dataset.kind)));
  }
  renderLegend();
}
```

```js
for (const button of document.querySelectorAll('#layer-chips .seg')) {
  button.addEventListener('click', () => {
    const kind = button.dataset.kind;
    if (layers.has(kind)) layers.delete(kind);
    else layers.add(kind);
    /* A map with every layer off is a blank page; keep at least one on. */
    if (!layers.size) layers.add(kind);
    syncSeg();
    render();
  });
}
```

6. In the `groupSelect` change handler, remove the block that forced `layer = 'claims'` (the group filter now applies to claims inside `currentEvents()`):

```js
groupSelect.addEventListener('change', () => {
  selected = null;
  renderSpark();
  render();
});
```

- [ ] **Step 6: Serve locally and smoke-test**

Run: `python3 -m http.server 8000` from the repo root, open `http://localhost:8000/map.html`.
Verify: five chips all pressed; counters populate; ticker shows mixed kinds and scrolls; toggling a chip re-filters map, table, sparkline; replay still scrubs; no console errors.

- [ ] **Step 7: Commit**

```bash
git add map.html
git commit -m "feat(map): five-layer interactive attack map with live ticker"
```

---

### Task 8: Honest homepage counters

**Files:**
- Modify: `index.html`

**Interfaces:**
- Consumes: `cache.cves.kev_catalog_total` / `cache.cves.kev_total` — verified present in `data/cves_headline.json` (that is what the homepage loads as `cache.cves`, *not* `cves.json`), `cache.ransomware.items[].published`, `statusSource(id)` helper (already in the page)
- Produces: counters that say what they count and how fresh they are.

- [ ] **Step 1: Markup**

1. In the hero stats (the `.stats` block), update the four cards to carry a meta line each:

```html
      <div class="stat">
        <div class="stat-value" id="stat-programs">—</div>
        <div class="stat-label">programs tracked</div>
        <div class="stat-meta" id="prog-meta">—</div>
      </div>
      <div class="stat">
        <div class="stat-value" id="stat-cves">—</div>
        <div class="stat-label">CVEs in window</div>
        <div class="stat-meta" id="cves-meta">—</div>
      </div>
      <div class="stat">
        <div class="stat-value" id="stat-kev">—</div>
        <div class="stat-label">known exploited CVEs</div>
        <div class="stat-meta" id="kev-meta">—</div>
      </div>
      <div class="stat">
        <div class="stat-value" id="stat-ransomware">—</div>
        <div class="stat-label">ransomware claims · 24h</div>
        <div class="stat-meta" id="ransom-meta">—</div>
      </div>
```

(`prog-meta` and `ransom-meta` elements already exist elsewhere on the page as card metadata — check for duplicate IDs before adding; reuse the existing ones if present and add only `cves-meta`/`kev-meta`.)

2. Add the `.stat-meta` style next to the existing `.stat-label` CSS in `index.html`'s (or `app.css`'s) stat styles:

```css
.stat-meta { font-family: var(--mono); font-size: 10.5px; color: var(--text-secondary); margin-top: 4px; }
```

- [ ] **Step 2: Script — replace the stat block**

Replace the block at the current lines ~582–591 (`stat-cves` / `stat-kev` / `stat-ransomware` assignments and the `ransom-meta` line) with:

```js
const DAY_MS = 86_400_000;
const metaText = (sourceId) => {
  const last = statusSource(sourceId)?.last_success;
  const time = last ? Date.parse(last) : NaN;
  if (Number.isNaN(time)) return 'update time unknown';
  const minutes = Math.max(0, Math.round((Date.now() - time) / 60_000));
  return minutes < 1 ? 'updated just now' : `updated ${minutes} min ago`;
};

document.getElementById('stat-cves').textContent = cache.cves
  ? number(cache.cves.recent_total ?? cache.cves.items?.length)
  : '—';
document.getElementById('cves-meta').textContent = metaText('cve');

document.getElementById('stat-kev').textContent = cache.cves
  ? number(cache.cves.kev_catalog_total)
  : '—';
document.getElementById('kev-meta').textContent = cache.cves
  ? `catalog · added in 90d: ${number(cache.cves.kev_total)} · ${metaText('cve')}`
  : 'unavailable';

/* The snapshot holds the newest 100 claims, so a 24h count from its own
   timestamps is honest: "claims in the last 24h of the current snapshot". */
const ransomTimes = (cache.ransomware?.items || [])
  .map((item) => Date.parse(item.published || ''))
  .filter((value) => !Number.isNaN(value));
const recentClaims = ransomTimes.filter((time) => time > Date.now() - DAY_MS).length;
const newestClaim = ransomTimes.length ? Math.max(...ransomTimes) : NaN;
document.getElementById('stat-ransomware').textContent = cache.ransomware
  ? recentClaims.toLocaleString('en-US')
  : '—';
document.getElementById('ransom-meta').textContent = cache.ransomware
  ? `newest ${timeAgo(newestClaim)} · ${metaText('ransomware')}`
  : 'unavailable';
```

Also update the programs block's meta line to include freshness:

```js
  document.getElementById('prog-meta').textContent = `${programs} programs · ${domains} domains · ${metaText('domains')}`;
```

(`timeAgo` is already imported in this module; `number` and `statusSource` already exist above this block — place `metaText` next to them.)

- [ ] **Step 3: Verify locally**

Serve and open `http://localhost:8000/`:
- KEV shows the catalog size (≈1,762) with "added in 90d: N".
- Ransomware shows a 24h count (not 100) with "newest <ago>".
- Every hero counter has an "updated N min ago" freshness line.
- No console errors; cards degrade to "unavailable" if a feed is missing.

- [ ] **Step 4: Commit**

```bash
git add index.html
git commit -m "fix(home): honest KEV catalog, 24h ransomware and freshness counters"
```

---

### Task 9: Docs — contract, README, architecture, accessibility, attribution

**Files:**
- Modify: `docs/CONTRACT.md` (regenerated)
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `ACCESSIBILITY.md`

- [ ] **Step 1: Regenerate the contract**

`docs/CONTRACT.md` is generated, not edited by hand (its header says so). Regenerate after the Task 5 contract changes:

Run: `python3 scripts/validate_feeds.py --print-contract > docs/CONTRACT.md`
Then restore the header note if the printer does not emit it (compare with git diff — the file must keep its "Generated from scripts/validate_feeds.py. Do not edit by hand" preamble).

Verify: the new `incident_item`, `isc_top_ip`, `isc_top_port`, `attacker_ip` blocks and the extended `live_event` appear.

- [ ] **Step 2: README + ARCHITECTURE**

- `README.md`: add `incidents.json`, `isc.json`, `attackers.json` to the data feed table with source, cadence and one-line description; update the `live.json` row to mention the five event kinds.
- `ARCHITECTURE.md`: add the three collectors to the collector list; update the `live.json` event-kind list; mention that `isc.json` has two sections (`top_ips`/`top_ports`).

- [ ] **Step 3: ACCESSIBILITY**

- `ACCESSIBILITY.md`: note the map page now exposes five independently toggleable layers (chips with `aria-pressed`), the ticker is a scrollable list, and the per-kind counts are also available as text in the data table — the map has a text equivalent for every visual channel.

- [ ] **Step 4: Commit**

```bash
git add docs/CONTRACT.md README.md ARCHITECTURE.md ACCESSIBILITY.md
git commit -m "docs: contract and feed docs for the five-layer live map"
```

---

### Task 10: Full gates, browser QA, ship the PR

**Files:**
- All of the above; PR via `feat/live-attack-map` → `main`.

- [ ] **Step 1: Run every gate**

```bash
python3 -m unittest discover -s scripts/tests -t scripts -v
node --test assets worker scheduler
python3 scripts/validate_feeds.py --against HEAD
python3 scripts/normalize.py
```

Expected: all pass. Fix anything red before proceeding.

- [ ] **Step 2: Browser QA at desktop and mobile widths**

Serve locally (`python3 -m http.server 8000`) and check with a browser at 1440px and 390px:

- `/map.html`: five chips; toggling each re-filters map + table + sparkline; ticker scrolls with ~15 mixed-kind items; replay scrubs; counters show 24h splits; country deep link (`?country=DE`) still selects and filters the table; freshness banner reflects `live.json`.
- `/`: KEV counter shows catalog total with 90d subtext; ransomware counter shows a 24h number; all counters show "updated N min ago".
- No console errors at either width; contrast holds (impeccable scan runs in CI too).

- [ ] **Step 3: Open the PR**

```bash
git push -u origin feat/live-attack-map
gh pr create --title "feat(map): five-layer live attack map and honest homepage counters" --body "$(cat <<'EOF'
## Summary
- New collectors: ransomware.live recent cyber incidents (3h), SANS ISC top IPs/ports (1h), blocklist.de last-hour attacker IPs (1h) — all keyless and licence-clean, registered in the validator and status registry with tests and fixtures.
- data/live.json gains incident/source/attacker event kinds with a uniform event shape; live_feed.py coverage reports them all.
- map.html: five toggleable layer chips, 15-item scrollable ticker, per-kind 24h counters, per-kind sparkline, pulses for timestamped kinds, honest provenance copy.
- Homepage: KEV counter now shows the catalog total (1,762) with "added in 90d" subtext; ransomware counter shows claims in the last 24h; every counter shows freshness.

## Test plan
- [x] python3 -m unittest discover -s scripts/tests -t scripts -v
- [x] node --test assets worker scheduler
- [x] python3 scripts/validate_feeds.py --against HEAD
- [x] Browser QA at 1440/390 on /map.html and /
EOF
)"
```

- [ ] **Step 4: Watch CI, address review, merge after approval**

All checks must be green (including SonarCloud new-code ratings and the impeccable design detector). Merge only after review approval — `main` is protected.
