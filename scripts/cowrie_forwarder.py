#!/usr/bin/env python3
"""Forward privacy-reduced Cowrie SSH connection counts to the API Worker."""

import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ip_country

DEFAULT_API_URL = "https://api.threats.top/api/sensors/cowrie/events"
MAX_READ_BYTES = 4 * 1024 * 1024
MAX_BATCH = 50
MAX_COUNT = 1_000_000_000
RETENTION = timedelta(days=7)
HEARTBEAT_SECONDS = 60


def parse_minute(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).replace(second=0, microsecond=0)


def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def minute_string(value):
    return value.strftime("%Y-%m-%dT%H:%M:00Z")


def timestamp_string(value):
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_state(path):
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "file": None, "counts": {}, "dirty": [], "last_heartbeat": None}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read forwarder state: {exc}") from exc

    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or not isinstance(state.get("counts"), dict)
        or not isinstance(state.get("dirty"), list)
    ):
        raise RuntimeError("Forwarder state has an unsupported format.")
    for key, count in state["counts"].items():
        if not isinstance(key, str):
            raise RuntimeError("Forwarder state has an invalid aggregate key.")
        minute, separator, country = key.partition("|")
        if (
            not separator
            or parse_minute(minute) is None
            or len(country) != 2
            or not country.isascii()
            or not country.isalpha()
            or type(count) is not int
            or count < 1
            or count > MAX_COUNT
        ):
            raise RuntimeError("Forwarder state has an invalid aggregate.")
    if any(not isinstance(key, str) or key not in state["counts"] for key in state["dirty"]):
        raise RuntimeError("Forwarder state has an invalid retry queue.")
    if state.get("last_heartbeat") is not None and parse_timestamp(state["last_heartbeat"]) is None:
        raise RuntimeError("Forwarder state has an invalid heartbeat timestamp.")
    return state


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(state, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def read_lines(path, previous):
    stat = path.stat()
    prior = previous if isinstance(previous, dict) else {}
    same_file = prior.get("device") == stat.st_dev and prior.get("inode") == stat.st_ino
    offset = prior.get("offset", 0) if same_file else 0
    if not isinstance(offset, int) or offset < 0 or offset > stat.st_size:
        offset = 0

    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(MAX_READ_BYTES)
    last_newline = data.rfind(b"\n")
    if last_newline < 0:
        return [], {"device": stat.st_dev, "inode": stat.st_ino, "offset": offset}

    complete = data[: last_newline + 1]
    lines = complete.splitlines()
    return lines, {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "offset": offset + len(complete),
    }


def parse_connection(line, lookup, now):
    try:
        event = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(event, dict) or event.get("eventid") != "cowrie.session.connect":
        return None

    timestamp = parse_minute(event.get("timestamp"))
    if timestamp is None:
        return None
    if timestamp < now - RETENTION or timestamp > now + timedelta(minutes=5):
        return None

    country = lookup(event.get("src_ip"))
    if not isinstance(country, str) or len(country) != 2 or not country.isalpha():
        return None
    return minute_string(timestamp), country.upper()


def post_batch(url, token, events, timeout=15):
    payload = json.dumps({"events": events}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status not in (200, 202):
                raise RuntimeError(f"Sensor API returned HTTP {response.status}.")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Sensor API returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Sensor API request failed: {exc.reason}") from exc


def forward_once(log_file, state_file, url, token, lookup, *, now=None, send=post_batch):
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state = load_state(state_file)
    lines, file_state = read_lines(log_file, state.get("file"))
    counts = dict(state["counts"])
    dirty = set(state["dirty"])

    for line in lines:
        parsed = parse_connection(line, lookup, current)
        if parsed is None:
            continue
        minute, country = parsed
        key = f"{minute}|{country}"
        count = int(counts.get(key, 0)) + 1
        if count > MAX_COUNT:
            raise RuntimeError("Country-minute count exceeded the ingestion limit.")
        counts[key] = count
        dirty.add(key)

    cutoff = current - RETENTION
    for key in list(counts):
        minute, _, country = key.partition("|")
        parsed = parse_minute(minute)
        if parsed is None or parsed < cutoff:
            counts.pop(key, None)
            dirty.discard(key)
    dirty.intersection_update(counts)

    state.update({"file": file_state, "counts": counts, "dirty": sorted(dirty)})
    save_state(state_file, state)

    remaining = sorted(dirty)
    while remaining:
        keys = remaining[:MAX_BATCH]
        events = []
        for key in keys:
            minute, country = key.split("|", 1)
            events.append({"minute": minute, "country": country, "count": counts[key]})
        send(url, token, events)
        dirty.difference_update(keys)
        remaining = remaining[len(keys):]
        state["dirty"] = sorted(dirty)
        state["last_heartbeat"] = timestamp_string(current)
        save_state(state_file, state)

    last_heartbeat = parse_timestamp(state.get("last_heartbeat"))
    if not dirty and (
        last_heartbeat is None
        or (current - last_heartbeat).total_seconds() >= HEARTBEAT_SECONDS
    ):
        send(url, token, [])
        state["last_heartbeat"] = timestamp_string(current)
        save_state(state_file, state)

    return len(lines)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", required=True, type=Path, help="Cowrie JSON output file")
    parser.add_argument("--state", required=True, type=Path, help="Private forwarder checkpoint file")
    parser.add_argument("--interval", type=int, default=15, help="Seconds between reads (default: 15)")
    parser.add_argument("--database", type=Path, help="Optional cached DB-IP Lite archive")
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be positive")

    token = os.environ.get("SENSOR_INGEST_TOKEN")
    if not token:
        parser.error("set SENSOR_INGEST_TOKEN in the service environment")
    url = os.environ.get("SENSOR_API_URL", DEFAULT_API_URL)
    try:
        database_path = args.database or ip_country.ensure_database()
        database = ip_country.load_database(database_path)
    except (ip_country.DatabaseUnavailable, OSError) as exc:
        parser.error(f"cannot load DB-IP Lite country database: {exc}")

    while True:
        try:
            processed = forward_once(
                args.log_file,
                args.state,
                url,
                token,
                database.country,
            )
            if processed:
                print(f"Processed {processed} Cowrie log records.", flush=True)
        except (OSError, RuntimeError) as exc:
            print(f"Sensor forwarder error: {exc}", file=sys.stderr, flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
