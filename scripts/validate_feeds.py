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

DATA_DIR = Path("data")
MANUAL_PATH = DATA_DIR / "manual.json"

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
    "urlhaus.json": 2,
    "domains.json": 2,
    "wiz.json": 1,
}

# Feeds that are allowed to be empty. Deliberately empty: a source that can
# legitimately have nothing to say should be listed here with a reason, not
# discovered by a red build at 3am. Anything not listed must never be empty.
ALLOW_EMPTY = {
    # (none currently -- every source we poll has continuous content)
}

# The canonical platform enum, mirroring collector.py. Duplicated on purpose:
# the validator must be able to fail when collector.py's enum drifts, so it
# cannot import it as the source of truth. validate_feeds.py is the checker, not
# the thing being checked.
CANONICAL_PLATFORMS = {
    "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack",
    "HackenProof", "Immunefi", "Self-hosted / Other",
}

THREAT_EVENT_TYPES = {"incident", "campaign", "research", "vulnerability", "malware", "threat actor"}

ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Used only for the "field is entirely markup" shape check -- see check_record.
TAG_ONLY = re.compile(r"<[^>]*>")
DEFANGED = re.compile(r"^hxxps?://")

# The published contract, as data. `--print-contract` renders this so the docs
# cannot drift from what is actually enforced.
#   scope -> which logical record the field belongs to
#   type  -> str | int | float | bool | iso_datetime | iso_date | url | nullable_str
CONTRACT = {
    "envelope": {
        "schema_version": "int -- bumped on any breaking change to this file",
        "updated_at": "iso_datetime -- when this snapshot was generated, always UTC",
    },
    # Optional envelope fields: documented, and type-checked when present, but not
    # required. A feed that normalises per-record timestamps carries this; one
    # that has no per-record timestamps (domains.json) legitimately does not.
    "envelope_optional": {
        "normalisation_failures": "list[dict] -- records whose timestamp was unparseable",
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
    "malware_url": {
        "id": "str",
        "date_added": "nullable_iso_datetime",
        "url_defanged": "str -- defanged; never a live hxxp/hxxps URL",
        "status": "str",
        "threat": "str",
        "tags": "str",
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
    "urlhaus.json": ("flat", [(("items",), "malware_url", None)]),
    "wiz.json": ("flat", [(("items",), "threat_event", None)]),
    "domains.json": ("programs", [(("programs",), "program", None)]),
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


def check_record(item, record_type, where, report):
    """Type, timestamp, and text-hygiene checks for one record."""
    for field in CONTRACT[record_type]:
        if field not in item:
            report.fail(where, f"missing required field {field!r}")
            return

    if record_type in ("cve", "advisory", "exploit", "malware_url"):
        # published is nullable on every advisory-shaped record: a single
        # unparseable upstream date is tolerated by the collector (see
        # normalize.NormalisationTally) rather than costing us the whole feed, so
        # the validator must accept the shape the collector actually emits. The
        # signal that it happened is the normalisation_failures warning below,
        # not a per-record hard error.
        check_timestamp(item.get("published") or item.get("date_added"),
                        allow_null=True,
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
        # Wiz encodes classification in the title suffix and ships no <category>
        # elements, so this is the only classification the feed carries.
        if item.get("type") is not None and item["type"] not in THREAT_EVENT_TYPES:
            report.fail(f"{where}.type",
                        f"{item['type']!r} is not one of {sorted(THREAT_EVENT_TYPES)}")

    if record_type == "malware_url":
        if not DEFANGED.match(item.get("url_defanged", "")):
            report.fail(f"{where}.url_defanged",
                        f"{item.get('url_defanged')!r} is not defanged -- a live URL "
                        f"must never reach the public API")

    # Shape check, not a security check: a text field must not consist *entirely*
    # of markup. This catches the real malformed case -- an upstream whose
    # "description" is really a fragment of an HTML page, e.g. a 503 challenge
    # body -- and has no false positives on prose that merely mentions a tag.
    #
    # Two broader rules were tried here and both were wrong, which is worth
    # recording so nobody re-adds them:
    #
    #   1. "reject any <tag>" fired on eight legitimate CVE descriptions,
    #      because CVE text routinely discusses markup.
    #   2. "reject active content (script/iframe/svg/javascript:)" still fired on
    #      CVE-2026-100174, which is an XSS vulnerability whose description quotes
    #      "<svg onload=...>" as the payload it fixes. A large share of this corpus
    #      is *about* injection, so no active-content regex can be clean here.
    #
    # Both were attempts to enforce the real security property -- "the renderer
    # escapes untrusted text" -- by inspecting data, which is the wrong layer. That
    # property belongs to the renderer and is verified by a frontend escaping test,
    # not by looking at a JSON file. The collector's only real obligation here is
    # to strip markup that the upstream's own formatting introduced (cert_eu does
    # this via strip_html); whether the *result* is escaped is the renderer's job.
    for field in ("description", "summary", "title", "name", "url_defanged"):
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
    for field, _spec in CONTRACT["envelope_optional"].items():
        if field in doc and not isinstance(doc[field], list):
            report.fail(f"{where}.{field}",
                        f"expected a list, got {type(doc[field]).__name__}")
    version = doc["schema_version"]
    expected = EXPECTED_SCHEMA_VERSION.get(feed)
    if expected is None:
        # A data/*.json file with no registered spec. Not necessarily wrong -- a
        # hand-maintained file might be legitimate -- but it is unenforced, so say
        # so rather than implying it was checked.
        report.warn(f"{where}.schema_version",
                    "no EXPECTED_SCHEMA_VERSION entry; this file is not version-checked")
    elif version != expected:
        report.fail(f"{where}.schema_version",
                    f"is {version!r} but EXPECTED_SCHEMA_VERSION says {expected!r} -- "
                    f"if the shape changed, bump both in the same commit")
    check_timestamp(doc["updated_at"], allow_null=False,
                    where=f"{where}.updated_at", report=report)


def load_baseline(feed, ref):
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


def print_contract():
    for scope, fields in CONTRACT.items():
        suffix = " (optional)" if scope.endswith("_optional") else ""
        print(f"\n## {scope}{suffix}\n")
        width = max(len(f) for f in fields)
        for field, spec in fields.items():
            print(f"  {field.ljust(width)}  {spec}")
    print(f"\n## feeds\n")
    for feed, (kind, lists) in FEED_SPECS.items():
        sections = ", ".join(".".join(p) for p, _r, _c in lists)
        print(f"  {feed.ljust(16)}  envelope={kind:<9} sections={sections}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--against", default="HEAD",
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
    feeds = sorted(p for p in DATA_DIR.glob("*.json") if p.name != "manual.json")
    for path in feeds:
        validate_feed(path, report,
                      check_regression=not args.no_regression,
                      ref=args.against)
    validate_manual(report)

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
    print(f"Contract: python3 scripts/validate_feeds.py --print-contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
