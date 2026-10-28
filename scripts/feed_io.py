#!/usr/bin/env python3
"""
Shared publishing helpers for every collector.

Two guarantees live here, so no collector has to re-implement them:

  * `write_json` replaces a feed atomically. A collector that crashes mid-write
    leaves the previous file untouched instead of publishing half a JSON
    document, which is how a truncated feed used to reach production.
  * `stable_id` derives a deterministic record ID from the fields that identify
    it upstream, so re-running a collector updates a record instead of
    duplicating it.
"""
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

SCHEMA_VERSION = 1

TAG_ONLY = re.compile(r"<[^>]*>")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value):
    """Parse one of our own ISO-8601 UTC timestamps, or return None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def stable_id(prefix, *parts):
    """Deterministic, URL-safe ID derived from the identity of a record."""
    material = "\x1f".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def write_json(path, document):
    """
    Write `document` to `path` atomically.

    The temporary file is created in the destination directory so os.replace is
    a same-filesystem rename: readers either see the old file or the new one,
    never a partial write.
    """
    path = Path(path)
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
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def is_http_url(value):
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


DEFANGED_SCHEMES = {"https": "hxxps", "http": "hxxp"}
LIVE_SCHEMES = {defanged: live for live, defanged in DEFANGED_SCHEMES.items()}


def swap_scheme(value, schemes):
    scheme, separator, rest = value.partition("://")
    replacement = schemes.get(scheme.lower())
    if not separator or replacement is None:
        return value
    return f"{replacement}{separator}{rest}"


def defang(url):
    """Neutralise a live URL so the feed can be displayed and copied safely."""
    if not isinstance(url, str):
        return ""
    return swap_scheme(url.strip(), DEFANGED_SCHEMES)


def refang(value):
    if not isinstance(value, str):
        return ""
    return swap_scheme(value.strip(), LIVE_SCHEMES)


def strip_html(text):
    """Collapse an upstream HTML fragment to plain text."""
    return " ".join(TAG_ONLY.sub(" ", text or "").split())


def truncate(value, limit):
    text = (value or "").strip()
    return text[:limit]


def envelope(source, source_url, *, schema_version=SCHEMA_VERSION, **extra):
    """
    The fields every public feed carries.

    `source` and `source_url` are provenance, not decoration: the validator
    rejects a feed without them, so a collector cannot silently publish data
    whose origin is unknown.
    """
    document = {
        "schema_version": schema_version,
        "updated_at": now_iso(),
        "source": source,
        "source_url": source_url,
    }
    document.update(extra)
    return document


def item_count(document):
    """Count the records in any of our feed envelopes."""
    if not isinstance(document, dict):
        return 0
    total = 0
    for key in ("items", "programs", "events"):
        value = document.get(key)
        if isinstance(value, list):
            total += len(value)
    for section in ("recent", "actively_exploited"):
        value = document.get(section)
        if isinstance(value, dict) and isinstance(value.get("items"), list):
            total += len(value["items"])
    return total
