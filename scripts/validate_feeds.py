#!/usr/bin/env python3
"""
Validates everything under data/ before it is allowed to reach the public API.

WHY THIS EXISTS
---------------
Every collector used to exit 0 no matter what it managed to parse. An upstream
that served an HTML error page instead of RSS produced:

    {"schema_version": 2, "total": 0, "items": []}      exit 0

which the workflow happily committed, the site rendered as "No matches", and CI
reported success. The implicit contract was "exit 0 means the file is good", and
that contract was false.

This module is the gate that makes the contract true. It is deliberately
stdlib-only, like everything else in scripts/, so it can run in CI with no
install step and so adding it cannot introduce a supply chain.

USAGE
-----
    python3 scripts/validate_feeds.py                    # gate against HEAD
    python3 scripts/validate_feeds.py --against ORIG_SHA  # gate against any ref
    python3 scripts/validate_feeds.py --print-contract   # emit the field contract
    python3 scripts/validate_feeds.py --no-regression    # skip the baseline diff

Exit codes: 0 = all feeds valid, 1 = at least one check failed,
2 = a feed file is missing or unreadable.

The regression check compares the working tree against a committed ref (HEAD by
default), which in the workflow is the data as it was before this run. That is
what turns "the feed emptied out" from a silent data loss into a red build.
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DATA_DIR = Path("data")
MANUAL_PATH = DATA_DIR / "manual.json"
STATUS_PATH = DATA_DIR / "status.json"
ROOT = Path(__file__).resolve().parent.parent

# Expected schema_version per feed file.
#
# Per-file rather than one global set, because the versions legitimately differ:
# a brand-new feed starts at 1 (it has never had a breaking change) while the
# feeds touched by the 2026-09-27 normalisation work are at 2. A single global set
# would force a new feed to claim a version it has no history for.
#
# The check is still strict in the direction that matters: if a collector changes
# a published shape without bumping its line here, this fails. Update both in the
# same commit.
EXPECTED_SCHEMA_VERSION = {
    "cves.json": 2,
    "cves_headline.json": 2,
    "ghsa.json": 2,
    "exploitdb.json": 2,
    "cert_eu.json": 2,
    "domains.json": 2,
    "wiz.json": 1,
    "ransomware.json": 1,
    "phishing.json": 1,
    "advisories.json": 1,
    "epss.json": 1,
    "iocs.json": 1,
    "live.json": 1,
}

# Feeds that are allowed to be empty. Deliberately empty: a source that can
# legitimately have nothing to say should be listed here with a reason, not
# discovered by a red build at 3am. Anything not listed must never be empty.
ALLOW_EMPTY = {
    # (none currently -- every source we poll has continuous content)
}

# Markers that must never appear in published data or public UI. They identify
# the seeded console/tenant demo that used to ship as if it were real.
DEMO_MARKERS = ("default-pro", "community-free", "demo-tenant", "example-tenant")

# The canonical platform enum, mirroring collector.py. Duplicated on purpose:
# the validator must be able to fail when collector.py's enum drifts, so it
# cannot import it as the source of truth. validate_feeds.py is the checker, not
# the thing being checked.
CANONICAL_PLATFORMS = {
    "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack",
    "HackenProof", "Immunefi", "Self-hosted / Other",
}

THREAT_EVENT_TYPES = {"incident", "campaign", "research", "vulnerability", "malware", "threat actor"}
IOC_TYPES = {"url", "domain"}
LIVE_EVENT_KINDS = {"claim", "host"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
STATUS_OVERALL = {"ok", "degraded", "outage"}

ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COUNTRY_CODE = re.compile(r"[A-Z]{2}")
# Used only for the "field is entirely markup" shape check -- see check_record.
TAG_ONLY = re.compile(r"<[^>]*>")
DEFANGED = re.compile(r"^hxxps?://")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

PRIVATE_FIELDS = {"tenant_id", "plan", "email", "api_key", "assets", "watchlist", "secret"}

# The published contract, as data. `--print-contract` renders this so the docs
# cannot drift from what is actually enforced.
#   scope -> which logical record the field belongs to
#   type  -> str | int | float | bool | iso_datetime | iso_date | url | nullable_str
CONTRACT = {
    "envelope": {
        "schema_version": "int -- bumped on any breaking change to this file",
        "updated_at": "iso_datetime -- when this snapshot was generated, always UTC",
        "source": "str -- human-readable upstream name",
        "source_url": "str | list[str] -- the exact upstream URL(s)",
    },
    # Optional envelope fields: documented, and type-checked when present, but not
    # required. A feed that normalises per-record timestamps carries this; one
    # that has no per-record timestamps (domains.json) legitimately does not.
    "envelope_optional": {
        "normalisation_failures": "list[dict] -- records whose timestamp was unparseable",
        "note": "str -- provenance or interpretation caveat",
        "partial": "list[str] | null -- upstreams that failed while others succeeded",
    },
    "program": {
        "name": "str",
        "url": "str",
        "platform": f"enum -- one of {sorted(CANONICAL_PLATFORMS)}",
        "domain_count": "int",
        "domains": "list[str]",
        "manual": "bool -- true if the entry came from data/manual.json",
    },
    "cve": {
        "id": "str -- CVE-YYYY-NNNN",
        "published": "nullable_iso_datetime -- null only if the upstream date was unparseable",
        "description": "str -- truncated to 300 chars",
        "severity": "nullable_str -- null means NVD has not scored this yet",
        "score": "nullable_float",
        "cvss_version": "nullable_str -- 40/31/30/2, or null when unscored",
        "link": "url",
        "kev": "bool",
    },
    "kev": {
        "id": "str",
        "vendor": "nullable_str",
        "product": "nullable_str",
        "name": "nullable_str",
        "date_added": "iso_date -- CISA publishes no time component",
        "ransomware_use": "nullable_str -- null, not the string \"Unknown\"",
        "description": "str",
        "link": "url",
    },
    "advisory": {
        "id": "str",
        "title": "str",
        "published": "nullable_iso_datetime",
        "summary": "str",
        "link": "url",
    },
    "vendor_advisory": {
        "id": "str",
        "vendor": "str -- Microsoft | Ubuntu",
        "title": "str",
        "published": "nullable_iso_datetime",
        "summary": "str",
        "link": "url",
    },
    "exploit": {
        "id": "str -- EDB numeric id, else the bare guid",
        "title": "str",
        "type": "nullable_str",
        "published": "nullable_iso_datetime",
        "description": "str",
        "link": "url",
    },
    "threat_event": {
        "id": "str -- stable UUID guid from the feed",
        "title": "str -- classification suffix stripped",
        "type": "nullable_enum -- incident | campaign | research | null when unclassified",
        "published": "nullable_iso_datetime",
        "summary": "str",
        "author": "nullable_str",
        "link": "url",
    },
    "ransomware_claim": {
        "id": "str -- deterministic claim ID",
        "victim": "str",
        "domain": "nullable_str -- victim domain, when the leak site names one",
        "group": "nullable_str",
        "activity": "nullable_str -- claimed sector",
        "country": "nullable_str",
        "published": "nullable_iso_datetime",
        "discovered": "nullable_iso_datetime",
        "description": "str -- attacker-supplied, truncated",
        "claim_url": "nullable_url -- .onion claim page",
        "link": "nullable_url -- ransomware.live record",
        "screenshot": "nullable_url",
    },
    "phishing_url": {
        "id": "str -- derived from the live URL",
        "url_defanged": "str -- defanged; never a live hxxp/hxxps URL",
        "host": "str -- hostname extracted from the live URL",
        "collected_at": "iso_datetime -- the snapshot time, not a first-seen claim",
    },
    "epss_score": {
        "cve": "str",
        "epss": "float -- 0..1",
        "percentile": "float -- 0..1",
        "date": "iso_date",
    },
    "ioc": {
        "id": "str",
        "type": f"enum -- one of {sorted(IOC_TYPES)}",
        "value": "str -- defanged URL for type=url, hostname for type=domain",
        "source": "str",
        "context": "str -- what the indicator means",
        "severity": f"enum -- one of {sorted(SEVERITIES)}",
        "first_seen": "nullable_iso_datetime",
        "last_seen": "nullable_iso_datetime",
        "link": "url",
    },
    "live_event": {
        "id": "str -- stable event ID",
        "kind": f"enum -- one of {sorted(LIVE_EVENT_KINDS)}",
        "ts": "iso_datetime -- when the claim was published or the host observed",
        "country": "str -- ISO 3166-1 alpha-2; claim = victim country, host = hosting country",
        "group": "nullable_str -- ransomware group, claim events only",
        "sector": "nullable_str -- claimed victim sector, claim events only",
        "host": "nullable_str -- phishing hostname, host events only",
    },
    "status_source": {
        "id": "str",
        "label": "str",
        "url": "str | list[str]",
        "cadence_minutes": "int",
        "last_attempt": "nullable_iso_datetime",
        "last_success": "nullable_iso_datetime",
        "http_status": "nullable_int",
        "items": "int",
        "error": "nullable_str",
        "stale": "bool",
    },
}

# feed file -> (envelope kind, list of (item list path, record type, count key))
FEED_SPECS = {
    "cves.json": ("nested", [(("recent", "items"), "cve", "recent"),
                             (("actively_exploited", "items"), "kev", "actively_exploited")]),
    # Bounded slice of cves.json for the homepage. Same record shape, so it is
    # held to the same standard -- the point of the cap is payload size, not a
    # lower bar on quality.
    "cves_headline.json": ("flat", [(("items",), "cve", None)]),
    "ghsa.json": ("flat", [(("items",), "advisory", None)]),
    "exploitdb.json": ("flat", [(("items",), "exploit", None)]),
    "cert_eu.json": ("flat", [(("items",), "advisory", None)]),
    "wiz.json": ("flat", [(("items",), "threat_event", None)]),
    "ransomware.json": ("flat", [(("items",), "ransomware_claim", None)]),
    "phishing.json": ("flat", [(("items",), "phishing_url", None)]),
    "advisories.json": ("flat", [(("items",), "vendor_advisory", None)]),
    "epss.json": ("flat", [(("items",), "epss_score", None)]),
    "iocs.json": ("flat", [(("items",), "ioc", None)]),
    "live.json": ("flat", [(("events",), "live_event", None)]),
    "domains.json": ("programs", [(("programs",), "program", None)]),
}

# sort key -> direction, for feeds whose order the UI relies on.
SORTED_FEEDS = {
    "cves.json:recent": ("published", True),
    "cves.json:actively_exploited": ("date_added", True),
    "cves_headline.json": ("published", True),
    "ghsa.json": ("published", True),
    "exploitdb.json": ("published", True),
    "cert_eu.json": ("published", True),
    "wiz.json": ("published", True),
    "ransomware.json": ("published", True),
    "advisories.json": ("published", True),
    "epss.json": ("epss", True),
    "iocs.json": ("last_seen", True),
    "live.json": ("ts", True),
}


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def fail(self, where, message):
        self.errors.append(f"{where}: {message}")

    def warn(self, where, message):
        self.warnings.append(f"{where}: {message}")

    @property
    def ok(self):
        return not self.errors


def dig(obj, path):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def check_timestamp(value, *, allow_null, where, report, date_only=False):
    pattern = ISO_DATE if date_only else ISO_DATETIME
    if value is None:
        if allow_null:
            return
        report.fail(where, "timestamp is null")
        return
    if not isinstance(value, str):
        report.fail(where, f"expected a string timestamp, got {type(value).__name__}")
        return
    if not pattern.match(value):
        report.fail(where, f"{value!r} is not {pattern.pattern}")
        return
    try:
        datetime.strptime(value[:10], "%Y-%m-%d")
    except ValueError:
        report.fail(where, f"{value!r} is not a real date")


def check_url(value, *, allow_null, where, report, defanged=False):
    if value is None:
        if allow_null:
            return
        report.fail(where, "URL is null")
        return
    if not isinstance(value, str) or not value.strip():
        report.fail(where, "URL is empty")
        return
    if defanged:
        if not DEFANGED.match(value):
            report.fail(where, f"{value!r} is not defanged -- a live URL must never reach the public API")
        return
    try:
        parsed = urlparse(value)
    except ValueError:
        report.fail(where, f"{value!r} is not a URL")
        return
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        report.fail(where, f"{value!r} must be an absolute http(s) URL")


def check_record(item, record_type, where, report):
    """Type, timestamp, URL-scheme, and text-hygiene checks for one record."""
    for field in CONTRACT[record_type]:
        if field not in item:
            report.fail(where, f"missing required field {field!r}")
            return

    for field in PRIVATE_FIELDS:
        if field in item:
            report.fail(where, f"contains private field {field!r}; tenant data must never be published")

    if record_type in ("cve", "advisory", "exploit", "vendor_advisory"):
        check_timestamp(item.get("published"), allow_null=True,
                        where=f"{where}.published", report=report)

    if record_type == "kev":
        check_timestamp(item.get("date_added"), allow_null=False, date_only=True,
                        where=f"{where}.date_added", report=report)
        # CISA publishes the literal string "Unknown"; we normalise it to null so
        # consumers can test for absence instead of matching a sentinel.
        if item.get("ransomware_use") == "Unknown":
            report.fail(f"{where}.ransomware_use",
                        'is the string "Unknown"; must be null')

    if record_type == "cve":
        score = item.get("score")
        if score is not None and not isinstance(score, (int, float)):
            report.fail(f"{where}.score", f"expected number or null, got {type(score).__name__}")
        if item.get("severity") is None and score is None and item.get("cvss_version") is not None:
            report.fail(where, "has cvss_version but no score")
        if score is not None and item.get("cvss_version") is None:
            report.fail(where, "has a score but no cvss_version; cannot tell which CVSS it came from")

    if record_type == "program":
        if item.get("platform") not in CANONICAL_PLATFORMS:
            report.fail(f"{where}.platform",
                        f"{item.get('platform')!r} is not in the canonical enum "
                        f"{sorted(CANONICAL_PLATFORMS)}")
        domains = item.get("domains")
        if not isinstance(domains, list):
            report.fail(f"{where}.domains", f"expected a list, got {type(domains).__name__}")
        elif item.get("domain_count") != len(domains):
            report.fail(f"{where}.domain_count",
                        f"is {item.get('domain_count')} but domains has {len(domains)} entries")

    if record_type == "threat_event":
        if item.get("type") is not None and item["type"] not in THREAT_EVENT_TYPES:
            report.fail(f"{where}.type",
                        f"{item['type']!r} is not one of {sorted(THREAT_EVENT_TYPES)}")

    if record_type in ("advisory", "vendor_advisory", "exploit", "threat_event", "cve", "kev"):
        check_url(item.get("link"), allow_null=False, where=f"{where}.link", report=report)

    if record_type == "vendor_advisory" and not isinstance(item.get("vendor"), str):
        report.fail(f"{where}.vendor", "must be a string")

    if record_type == "ransomware_claim":
        if not isinstance(item.get("victim"), str) or not item["victim"].strip():
            report.fail(f"{where}.victim", "must be a non-empty string")
        check_timestamp(item.get("published"), allow_null=True,
                        where=f"{where}.published", report=report)
        check_timestamp(item.get("discovered"), allow_null=True,
                        where=f"{where}.discovered", report=report)
        for field in ("claim_url", "link", "screenshot"):
            check_url(item.get(field), allow_null=True, where=f"{where}.{field}", report=report)

    if record_type == "phishing_url":
        check_url(item.get("url_defanged"), allow_null=False,
                  where=f"{where}.url_defanged", report=report, defanged=True)
        host = item.get("host")
        if not isinstance(host, str) or not HOSTNAME.match(host.lower()):
            report.fail(f"{where}.host", f"{host!r} is not a hostname")
        check_timestamp(item.get("collected_at"), allow_null=False,
                        where=f"{where}.collected_at", report=report)

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
        if kind == "claim":
            if item.get("host") is not None:
                report.fail(f"{where}.host", "a claim event must not carry a hostname")
            group = item.get("group")
            if not isinstance(group, str) or not group.strip():
                report.fail(f"{where}.group", "a claim event needs a group (or 'Unattributed')")
        elif kind == "host":
            if item.get("group") is not None or item.get("sector") is not None:
                report.fail(where, "a host event must not carry claim fields")
            host = item.get("host")
            if not isinstance(host, str) or not HOSTNAME.match(host.lower()):
                report.fail(f"{where}.host", f"{host!r} is not a hostname")

    if record_type == "epss_score":
        for field in ("epss", "percentile"):
            value = item.get(field)
            if not isinstance(value, (int, float)) or not 0 <= value <= 1:
                report.fail(f"{where}.{field}", f"{value!r} is not a number in 0..1")
        check_timestamp(item.get("date"), allow_null=False, date_only=True,
                        where=f"{where}.date", report=report)

    if record_type == "ioc":
        if item.get("type") not in IOC_TYPES:
            report.fail(f"{where}.type", f"{item.get('type')!r} is not one of {sorted(IOC_TYPES)}")
        if item.get("severity") not in SEVERITIES:
            report.fail(f"{where}.severity", f"{item.get('severity')!r} is not one of {sorted(SEVERITIES)}")
        value = item.get("value")
        if item.get("type") == "url":
            check_url(value, allow_null=False, where=f"{where}.value", report=report, defanged=True)
        elif item.get("type") == "domain":
            if not isinstance(value, str) or not HOSTNAME.match(value.lower()):
                report.fail(f"{where}.value", f"{value!r} is not a hostname")
        check_timestamp(item.get("first_seen"), allow_null=True,
                        where=f"{where}.first_seen", report=report)
        check_timestamp(item.get("last_seen"), allow_null=True,
                        where=f"{where}.last_seen", report=report)
        check_url(item.get("link"), allow_null=False, where=f"{where}.link", report=report)

    # Shape check, not a security check: a text field must not consist *entirely*
    # of markup. This catches the real malformed case -- an upstream whose
    # "description" is really a fragment of an HTML page, e.g. a 503 challenge
    # body -- and has no false positives on prose that merely mentions a tag.
    for field in ("description", "summary", "title", "name", "url_defanged", "indicator"):
        value = item.get(field)
        if isinstance(value, str) and value.strip() and not TAG_ONLY.sub("", value).strip():
            report.fail(f"{where}.{field}",
                        "consists entirely of markup; the upstream field is probably "
                        "a fragment of an HTML page rather than content")


def check_envelope(doc, feed, report):
    where = f"data/{feed}"
    for field in CONTRACT["envelope"]:
        if field not in doc:
            report.fail(where, f"missing {field!r}")
            return
    source_url = doc["source_url"]
    if isinstance(source_url, str):
        check_url(source_url, allow_null=False, where=f"{where}.source_url", report=report)
    elif isinstance(source_url, list):
        if not source_url:
            report.fail(f"{where}.source_url", "is an empty list")
        for index, value in enumerate(source_url):
            check_url(value, allow_null=False, where=f"{where}.source_url[{index}]", report=report)
    else:
        report.fail(f"{where}.source_url",
                    f"expected a string or list, got {type(source_url).__name__}")

    for field, _spec in CONTRACT["envelope_optional"].items():
        if field in doc and field != "normalisation_failures" and field != "partial":
            if not isinstance(doc[field], str):
                report.fail(f"{where}.{field}", f"expected a string, got {type(doc[field]).__name__}")
        if field == "partial" and doc.get(field) is not None and not isinstance(doc[field], list):
            report.fail(f"{where}.partial", "expected a list or null")

    version = doc["schema_version"]
    expected = EXPECTED_SCHEMA_VERSION.get(feed)
    if expected is None:
        report.warn(f"{where}.schema_version",
                    "no EXPECTED_SCHEMA_VERSION entry; this file is not version-checked")
    elif version != expected:
        report.fail(f"{where}.schema_version",
                    f"is {version!r} but EXPECTED_SCHEMA_VERSION says {expected!r} -- "
                    f"if the shape changed, bump both in the same commit")
    check_timestamp(doc["updated_at"], allow_null=False,
                    where=f"{where}.updated_at", report=report)


# --against is operator input and reaches argv. Accept only plain ref names and
# object ids: no leading dash (git would read it as an option), no "..", no
# whitespace, no revision syntax such as "HEAD^{tree}".
GIT_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
FEED_NAME_RE = re.compile(r"[A-Za-z0-9._-]+\.json\Z")


def is_safe_ref(ref):
    return bool(GIT_REF_RE.fullmatch(ref)) and ".." not in ref and not ref.endswith("/")


def load_baseline(feed, ref):
    if not is_safe_ref(ref) or not FEED_NAME_RE.fullmatch(feed):
        return None
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:data/{feed}"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        return json.loads(out.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def item_count(doc, feed):
    spec = FEED_SPECS.get(feed)
    if not spec:
        return None
    total = 0
    for path, _record, _count_key in spec[1]:
        found = dig(doc, path)
        if isinstance(found, list):
            total += len(found)
    return total


def collect_strings(value, path="", found=None):
    found = found if found is not None else []
    if isinstance(value, str):
        found.append((path, value))
    elif isinstance(value, dict):
        for key, child in value.items():
            collect_strings(child, f"{path}.{key}" if path else key, found)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            collect_strings(child, f"{path}[{index}]", found)
    return found


def check_demo_markers(value, where, report):
    for path, text in collect_strings(value):
        lowered = text.lower()
        for marker in DEMO_MARKERS:
            if marker in lowered:
                report.fail(f"{where}:{path}", f"contains demo marker {marker!r}")


def check_duplicates(items, key, where, report):
    seen = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        if not isinstance(value, str):
            continue
        identity = value.lower() if key == "name" else value
        if identity in seen:
            report.fail(f"{where}[{index}]", f"duplicate {key} {value!r}")
        seen.add(identity)


def check_sorted(items, key, descending, where, report):
    values = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        values.append(value)
    clean = [value for value in values if isinstance(value, (str, int, float))]
    ordered = sorted(clean, reverse=descending)
    if clean != ordered:
        report.fail(where, f"items are not sorted by {key!r} ({'descending' if descending else 'ascending'})")


def validate_feed(path, report, *, check_regression, ref):
    feed = path.name
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.fail(f"data/{feed}", f"unreadable or invalid JSON: {exc}")
        return
    if not isinstance(doc, dict):
        report.fail(f"data/{feed}", "top level must be a JSON object")
        return

    check_envelope(doc, feed, report)
    check_demo_markers(doc, f"data/{feed}", report)
    if feed not in FEED_SPECS:
        return
    envelope_kind, lists = FEED_SPECS[feed]

    for list_path, record_type, section in lists:
        items = dig(doc, list_path)
        where_list = f"data/{feed}:{'.'.join(list_path)}"
        if not isinstance(items, list):
            report.fail(where_list, f"expected a list, got {type(items).__name__}")
            continue
        if section and isinstance(doc.get(section), dict):
            declared = doc[section].get("total")
            if declared != len(items):
                report.fail(f"data/{feed}:{section}.total",
                            f"declares {declared} but holds {len(items)} items")
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                report.fail(f"{where_list}[{index}]", "item is not an object")
                continue
            check_record(item, record_type, f"{where_list}[{index}]", report)

        check_duplicates(items, "name" if record_type == "program" else "id", where_list, report)
        sort_key = f"{feed}:{'.'.join(list_path)}" if envelope_kind == "nested" else feed
        if sort_key in SORTED_FEEDS and record_type not in ("program",):
            key, descending = SORTED_FEEDS[sort_key]
            check_sorted(items, key, descending, where_list, report)

    # Per-item normalisation failures are tolerated by the collectors (one odd
    # advisory should not cost us the other 99), but never silently: if any were
    # tolerated, the feed says so here and the count shows up in CI.
    tolerated = doc.get("normalisation_failures")
    if isinstance(tolerated, list) and tolerated:
        print(f"::warning::data/{feed}: {len(tolerated)} record(s) had an "
              f"unparseable timestamp and were published with a null date "
              f"(first: {tolerated[0].get('field')}={tolerated[0].get('value')!r})",
              file=sys.stderr)
    elif tolerated is not None and not isinstance(tolerated, list):
        report.fail(f"data/{feed}.normalisation_failures",
                    f"expected a list, got {type(tolerated).__name__}")

    # NVD completeness: the two counters exist precisely so truncation is visible.
    if feed == "cves.json":
        recent = doc.get("recent") or {}
        parsed, available = recent.get("items_parsed"), recent.get("items_available")
        if parsed is None or available is None:
            report.fail("data/cves.json:recent",
                        "missing items_parsed/items_available; NVD truncation cannot be detected")
        elif parsed != available:
            report.fail("data/cves.json:recent",
                        f"NVD truncation: parsed {parsed} of {available} available")

    # The original defect: a feed that empties out and still gets published.
    count = item_count(doc, feed)
    if count == 0 and feed not in ALLOW_EMPTY:
        report.fail(f"data/{feed}", "contains zero items -- refusing to publish an empty feed")
    elif check_regression and count is not None:
        baseline = load_baseline(feed, ref)
        if baseline is not None:
            before = item_count(baseline, feed)
            if before and count == 0:
                report.fail(f"data/{feed}", f"regressed from {before} items to 0")
            elif before and count < before * 0.5:
                report.warn(f"data/{feed}",
                            f"item count fell from {before} to {count} (>50% drop) -- check upstream")


def validate_manual(report):
    """
    manual.json is hand-edited and is the only human write path into published
    data. Check it directly rather than trusting the collector to normalise it.
    """
    if not MANUAL_PATH.exists():
        return
    try:
        doc = json.loads(MANUAL_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.fail("data/manual.json", f"unreadable or invalid JSON: {exc}")
        return
    programs = doc.get("programs")
    if not isinstance(programs, list):
        report.fail("data/manual.json", "expected a top-level 'programs' list")
        return
    for index, program in enumerate(programs):
        where = f"data/manual.json:programs[{index}]"
        if not isinstance(program, dict):
            report.fail(where, "entry is not an object")
            continue
        if not program.get("name"):
            report.fail(where, "missing 'name'")
        platform = program.get("platform")
        if platform and not any(platform.lower() == c.lower() for c in CANONICAL_PLATFORMS):
            report.warn(f"{where}.platform",
                        f"{platform!r} is not canonical (expected one of "
                        f"{sorted(CANONICAL_PLATFORMS)}); collector will normalise it "
                        f"but the canonical spelling is preferable here")
        domains = program.get("domains", [])
        if not isinstance(domains, list):
            report.fail(f"{where}.domains", f"expected a list, got {type(domains).__name__}")


def load_status(report):
    if not STATUS_PATH.exists():
        report.fail("data/status.json", "missing -- a run without freshness evidence is not publishable")
        return {}
    try:
        document = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.fail("data/status.json", f"unreadable or invalid JSON: {exc}")
        return {}
    if not isinstance(document, dict):
        report.fail("data/status.json", "top level must be an object")
        return {}
    if document.get("schema_version") != 1:
        report.fail("data/status.json:schema_version", f"expected 1, got {document.get('schema_version')!r}")
    check_timestamp(document.get("generated_at"), allow_null=False,
                    where="data/status.json:generated_at", report=report)
    if document.get("overall") not in STATUS_OVERALL:
        report.fail("data/status.json:overall", f"{document.get('overall')!r} is not one of {sorted(STATUS_OVERALL)}")
    sources = document.get("sources")
    if not isinstance(sources, list) or not sources:
        report.fail("data/status.json:sources", "expected a non-empty list")
        return {}
    entries = {}
    for index, entry in enumerate(sources):
        where = f"data/status.json:sources[{index}]"
        if not isinstance(entry, dict):
            report.fail(where, "entry is not an object")
            continue
        for field in CONTRACT["status_source"]:
            if field not in entry:
                report.fail(where, f"missing required field {field!r}")
        source_id = entry.get("id")
        if not isinstance(source_id, str):
            report.fail(where, "missing string id")
            continue
        if source_id in entries:
            report.fail(where, f"duplicate source id {source_id!r}")
        entries[source_id] = entry
        check_timestamp(entry.get("last_attempt"), allow_null=True,
                        where=f"{where}.last_attempt", report=report)
        check_timestamp(entry.get("last_success"), allow_null=True,
                        where=f"{where}.last_success", report=report)
        if not isinstance(entry.get("items"), int):
            report.fail(f"{where}.items", "must be an int")
        if not isinstance(entry.get("stale"), bool):
            report.fail(f"{where}.stale", "must be a bool")
        if not isinstance(entry.get("cadence_minutes"), int) or entry["cadence_minutes"] <= 0:
            report.fail(f"{where}.cadence_minutes", "must be a positive int")
        check_demo_markers(entry, where, report)
    return entries


def validate_status_and_freshness(report, status_entries):
    """Cross-file: status.json must agree with the feeds it describes."""
    covered = {}
    for source_id, entry in status_entries.items():
        for feed in entry.get("feeds") or []:
            if feed in covered:
                report.fail(f"data/status.json:{source_id}",
                            f"feed {feed!r} is also claimed by {covered[feed]!r}")
            covered[feed] = source_id

    for feed in FEED_SPECS:
        path = DATA_DIR / feed
        if not path.exists():
            report.fail(f"data/{feed}", "missing -- every contracted feed must be published")
            continue
        if feed not in covered:
            report.fail(f"data/{feed}", "is not covered by data/status.json")
            continue
        source_id = covered[feed]
        entry = status_entries[source_id]
        cadence = entry.get("cadence_minutes") or 1440
        last_success = entry.get("last_success")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        updated_at = doc.get("updated_at")
        if last_success and updated_at != last_success:
            report.fail(f"data/{feed}:updated_at",
                        f"{updated_at!r} does not match status last_success {last_success!r}; "
                        f"a feed must not claim a freshness its source did not record")
        if updated_at:
            check_timestamp(updated_at, allow_null=False, where=f"data/{feed}:updated_at", report=report)
            try:
                mtime = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                mtime = None
            if mtime:
                age_minutes = (datetime.now(timezone.utc) - mtime).total_seconds() / 60
                if age_minutes < -5:
                    report.fail(f"data/{feed}:updated_at",
                                f"is {int(-age_minutes)} minutes in the future")
                elif age_minutes > cadence * 2:
                    report.warn(f"data/{feed}",
                                f"is {int(age_minutes)} minutes old (2x cadence is {cadence * 2})")

        primary_feed = (entry.get("feeds") or [None])[0]
        if feed == primary_feed:
            count = item_count(doc, feed)
            if count is not None and entry.get("items") != count:
                report.fail(f"data/status.json:{source_id}.items",
                            f"is {entry.get('items')} but data/{feed} holds {count} items")

    # stale must be recomputed, not trusted: a fabricated false would hide an outage.
    for source_id, entry in status_entries.items():
        last_success = entry.get("last_success")
        cadence = entry.get("cadence_minutes") or 1440
        if not last_success:
            expected = True
        else:
            try:
                last = datetime.strptime(last_success, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                expected = True
            else:
                expected = (datetime.now(timezone.utc) - last).total_seconds() / 60 > cadence * 2
        if entry.get("stale") is not expected:
            report.fail(f"data/status.json:{source_id}.stale",
                        f"is {entry.get('stale')} but the timestamp says {expected}")

    expected_overall = "ok"
    if any(entry.get("stale") or entry.get("error") for entry in status_entries.values()):
        expected_overall = "degraded"
        if any(entry.get("stale") and entry.get("critical") for entry in status_entries.values()):
            expected_overall = "outage"
    try:
        document = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if document.get("overall") != expected_overall:
        report.fail("data/status.json:overall",
                    f"is {document.get('overall')!r} but the sources say {expected_overall!r}")

    # cves_headline.json is a slice of cves.json from the same run.
    headline = DATA_DIR / "cves_headline.json"
    cves = DATA_DIR / "cves.json"
    if headline.exists() and cves.exists():
        try:
            head = json.loads(headline.read_text(encoding="utf-8"))
            full = json.loads(cves.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if head.get("updated_at") != full.get("updated_at"):
            report.fail("data/cves_headline.json:updated_at",
                        "must match data/cves.json -- the slice and the full window come from one run")
        recent_total = (full.get("recent") or {}).get("total")
        if head.get("recent_total") != recent_total:
            report.fail("data/cves_headline.json:recent_total",
                        f"is {head.get('recent_total')!r} but cves.json recent.total is {recent_total!r}")
        if not isinstance(head.get("kev_total"), int):
            report.fail("data/cves_headline.json:kev_total", "must be an int")


def validate_public_ui(report):
    """Fail if the retired demo markers survive in the public site."""
    for path in sorted(ROOT.glob("*.html")):
        try:
            text = path.read_text(encoding="utf-8").lower()
        except OSError:
            continue
        for marker in DEMO_MARKERS:
            if marker in text:
                report.fail(f"{path.name}", f"contains demo marker {marker!r}")


def print_contract():
    print("# Data API contract")
    print()
    print("_Generated from `scripts/validate_feeds.py`. Do not edit by hand — the same")
    print("table that documents the contract is the one that enforces it._")
    print("Regenerate with:")
    print()
    print("    python3 scripts/validate_feeds.py --print-contract")
    print()
    print("Every file under `data/` is a public, no-auth read endpoint. Schema changes")
    print("increment `schema_version`. The validation rules are listed in CONSTRAINTS.md.")
    for scope, fields in CONTRACT.items():
        suffix = " (optional)" if scope.endswith("_optional") else ""
        print(f"\n## {scope}{suffix}\n")
        width = max(len(f) for f in fields)
        for field, spec in fields.items():
            print(f"  {field.ljust(width)}  {spec}")
    print(f"\n## feeds\n")
    for feed, (kind, lists) in FEED_SPECS.items():
        sections = ", ".join(".".join(p) for p, _r, _c in lists)
        print(f"  {feed.ljust(20)}  envelope={kind:<9} sections={sections}")


def git_ref_argument(value):
    if not is_safe_ref(value):
        raise argparse.ArgumentTypeError(f"unsafe git ref: {value!r}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--against", default="HEAD", type=git_ref_argument,
                        help="git ref holding the baseline for the regression check (default: HEAD)")
    parser.add_argument("--no-regression", action="store_true",
                        help="skip the baseline comparison")
    parser.add_argument("--print-contract", action="store_true",
                        help="print the published field contract and exit")
    args = parser.parse_args()

    if args.print_contract:
        print_contract()
        return 0

    if not DATA_DIR.is_dir():
        print(f"::error::{DATA_DIR}/ not found -- run from the repository root", file=sys.stderr)
        return 2

    report = Report()
    feeds = sorted(
        p for p in DATA_DIR.glob("*.json")
        if p.name not in ("manual.json", "status.json")
    )
    for path in feeds:
        validate_feed(path, report,
                      check_regression=not args.no_regression,
                      ref=args.against)
    validate_manual(report)
    status_entries = load_status(report)
    if status_entries:
        validate_status_and_freshness(report, status_entries)
    validate_public_ui(report)

    for warning in report.warnings:
        print(f"::warning::{warning}", file=sys.stderr)
    for error in report.errors:
        print(f"::error::{error}", file=sys.stderr)

    if report.errors:
        print(f"\n{len(report.errors)} error(s), {len(report.warnings)} warning(s) "
              f"across {len(feeds)} feed files. Not publishing.", file=sys.stderr)
        return 1

    print(f"All {len(feeds)} feed files valid"
          + (f" ({len(report.warnings)} warning(s))" if report.warnings else "") + ".")
    print("Contract: python3 scripts/validate_feeds.py --print-contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
