#!/usr/bin/env python3
"""
Runs the collectors and records what actually happened.

The previous workflow wrapped every source in `set -euo pipefail`: one broken
upstream (URLhaus started returning 410) aborted the whole run, so NVD, GHSA,
Exploit-DB and CERT-EU stopped updating too. Production sat frozen for days
while every other source was healthy.

This orchestrator inverts that. Each source runs in its own process, a failure
is recorded against that source, and the rest still publish. It always writes
`data/status.json`, so an outage is visible on the site instead of being
silently absorbed into a stale feed.

Exit codes:
  0  every selected source ran, or only non-critical sources failed
  1  a critical source (NVD/CISA KEV) is stale beyond its hard limit, or a
     selected source could not be started at all

Data validity is a separate gate (`validate_feeds.py`); a collector that writes
invalid data exits non-zero before replacing the previous feed, so the old file
stays live and this run records the failure.
"""
import argparse
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from feed_io import DATA_DIR, now_iso
from status import SOURCES, enrich_entry, is_due, load_status, write_status

ROOT = Path(__file__).resolve().parent.parent
CRITICAL_HARD_LIMIT_MINUTES = 24 * 60
HTTP_STATUS = re.compile(r"\b(?:HTTP(?: Error)?\s+)(\d{3})\b")


def selected_sources(value):
    if value in (None, "", "auto"):
        previous = load_status()
        due = []
        for source_id in SOURCES:
            primary = DATA_DIR / SOURCES[source_id]["primary_feed"]
            if not primary.exists() or is_due(source_id, previous.get(source_id)):
                due.append(source_id)
        return due
    if value == "all":
        return list(SOURCES)
    wanted = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [part for part in wanted if part not in SOURCES]
    if unknown:
        raise SystemExit(f"unknown source(s): {', '.join(unknown)}; known: {', '.join(SOURCES)}")
    return [source_id for source_id in SOURCES if source_id in wanted]


def http_status_from(output):
    match = HTTP_STATUS.search(output)
    return int(match.group(1)) if match else None


def run_source(source_id, previous):
    source = SOURCES[source_id]
    script = ROOT / "scripts" / source["script"]
    attempted = now_iso()
    started = time.monotonic()
    print(f"\n=== {source_id}: {source['label']} ===", flush=True)

    try:
        completed = subprocess.run(
            [sys.executable, str(script)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=900,
        )
        output = f"{completed.stdout}\n{completed.stderr}"
        succeeded = completed.returncode == 0
        error = None
        if not succeeded:
            lines = [line for line in completed.stderr.strip().splitlines() if line.strip()]
            error = (lines[-1] if lines else f"collector exited {completed.returncode}")[:300]
    except subprocess.TimeoutExpired:
        output = ""
        succeeded = False
        error = "collector timed out after 900s"
    except OSError as exc:
        output = ""
        succeeded = False
        error = f"could not start collector: {exc}"

    if output.strip():
        print(output.rstrip(), flush=True)
    duration_ms = int((time.monotonic() - started) * 1000)
    entry = enrich_entry(
        source_id,
        previous,
        attempted=attempted,
        succeeded=succeeded,
        error=error,
        duration_ms=duration_ms,
        http_status=http_status_from(output),
    )
    print(
        f"--- {source_id}: {'ok' if succeeded else 'FAILED'} "
        f"({duration_ms} ms, {entry['items']} items)"
        + (f" error={error}" if error else ""),
        flush=True,
    )
    return entry


def summarize(entries):
    print("\n=== status ===", flush=True)
    for entry in entries:
        state = "stale" if entry.get("stale") else ("failed" if entry.get("error") else "ok")
        print(
            f"  {entry['id']:11s} {state:7s} items={entry.get('items', 0):<6} "
            f"last_success={entry.get('last_success') or '-'}"
        )


def critical_outage(entries):
    now = datetime.now(timezone.utc)
    for entry in entries:
        source_id = entry["id"]
        if not SOURCES[source_id]["critical"]:
            continue
        timestamp = entry.get("last_success")
        if not timestamp:
            return source_id, "has never succeeded"
        try:
            last = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return source_id, f"has an unparseable last_success ({timestamp!r})"
        age = (now - last).total_seconds() // 60
        if age > CRITICAL_HARD_LIMIT_MINUTES:
            return source_id, f"is {int(age)} minutes stale (hard limit {CRITICAL_HARD_LIMIT_MINUTES})"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--feeds",
        default="auto",
        help="auto (cadence-driven), all, or a comma-separated source list "
             f"({', '.join(SOURCES)})",
    )
    parser.add_argument("--list", action="store_true", help="print the sources and exit")
    args = parser.parse_args()

    if args.list:
        for source_id, source in SOURCES.items():
            print(f"{source_id:11s} {source['cadence_minutes']:>6} min  {source['label']}")
        return 0

    previous = load_status()
    selected = selected_sources(args.feeds)
    if not selected:
        print("No source is due. Leaving data and status untouched.")
        return 0

    print(f"Running {len(selected)} source(s): {', '.join(selected)}")
    entries = dict(previous)
    for source_id in selected:
        entries[source_id] = run_source(source_id, previous.get(source_id))
        write_status(entries)

    document = write_status(entries)
    summarize(document["sources"])
    print(f"\nOverall: {document['overall']}")

    outage = critical_outage(document["sources"])
    if outage:
        source_id, reason = outage
        print(f"::error::critical source {source_id} {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
