#!/usr/bin/env python3
"""
IP -> country lookup backed by the DB-IP Lite database.

The live map plots phishing hosts by the country their IP is registered in.
That needs a geolocation table, and the map's legend states where it comes from,
so the licence matters: DB-IP's Lite database is CC BY 4.0 and redistributable
with attribution, which is why it was chosen over the free tiers of the
commercial lookup APIs (all non-commercial or rate-limited per visitor).

The archive is a monthly gzip CSV of start,end,country ranges. It is cached
outside `data/` because it is an input, not a published feed, and it is never
committed: 4.5 MB of address ranges would churn every branch every month.

Attribution: IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
"""
import bisect
import csv
import gzip
import io
import ipaddress
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / ".cache" / "dbip"

DB_ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
DB_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
DOWNLOAD_BASE = "https://download.db-ip.com/free"

ISO2 = re.compile(r"[A-Za-z]{2}")


class DatabaseUnavailable(RuntimeError):
    """No usable archive: download failed, or the response was not DB-IP data."""


def month_slug(now=None):
    now = now or datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


def archive_name(month):
    return f"dbip-country-lite-{month}.csv.gz"


def download_url(month):
    return f"{DOWNLOAD_BASE}/{archive_name(month)}"


def candidate_months(now=None, count=2):
    """This month first, then the previous one.

    DB-IP publishes on the first of the month; early in a month the new file can
    still be missing, and the previous month's ranges are still the best answer
    available. Two candidates is enough for that gap and keeps a broken download
    from failing slowly.
    """
    now = now or datetime.now(timezone.utc)
    months = []
    year, month = now.year, now.month
    for _ in range(count):
        months.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return months


def parse_row(row):
    """One CSV row -> (ip_version, start_int, end_int, country_code), or None."""
    if len(row) != 3:
        return None
    start_raw, end_raw, code = (part.strip() for part in row)
    if not ISO2.fullmatch(code):
        return None
    try:
        start = ipaddress.ip_address(start_raw)
        end = ipaddress.ip_address(end_raw)
    except ValueError:
        return None
    if start.version != end.version or start > end:
        return None
    return start.version, int(start), int(end), code.upper()


class CountryDatabase:
    """Sorted range tables per address family, queried with bisect."""

    def __init__(self, rows, *, skipped=0):
        self.skipped = skipped
        tables = {}
        for version in (4, 6):
            family = sorted(
                (start, end, code)
                for row_version, start, end, code in rows
                if row_version == version
            )
            tables[version] = (
                [start for start, _, _ in family],
                [end for _, end, _ in family],
                [code for _, _, code in family],
            )
        self._tables = tables

    def __len__(self):
        return sum(len(starts) for starts, _, _ in self._tables.values())

    def country(self, value):
        """ISO 3166-1 alpha-2 code for a global address, else None."""
        if value is None:
            return None
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        # Reserved and private ranges are present in the table (DB-IP labels
        # documentation ranges, for instance), but a label there would say
        # something about the address block, not about a real host.
        if not address.is_global:
            return None
        starts, ends, codes = self._tables[address.version]
        number = int(address)
        index = bisect.bisect_right(starts, number) - 1
        if index < 0 or number > ends[index]:
            return None
        return codes[index]


def load_database(path):
    path = Path(path)
    rows = []
    skipped = 0
    with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row:
                continue
            parsed = parse_row(row)
            if parsed is None:
                skipped += 1
                continue
            rows.append(parsed)
    return CountryDatabase(rows, skipped=skipped)


def valid_archive(path):
    """True when `path` is a readable gzip CSV we can parse."""
    path = Path(path)
    try:
        if not path.is_file() or path.stat().st_size == 0:
            return False
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            return bool(handle.readline().strip())
    except (OSError, EOFError, ValueError):
        return False


def install_archive(path, payload):
    """Validate a downloaded payload and atomically install it as `path`."""
    if not payload.startswith(b"\x1f\x8b"):
        raise DatabaseUnavailable("response is not a gzip archive")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as handle:
            first = handle.readline()
    except (OSError, EOFError) as exc:
        raise DatabaseUnavailable(f"gzip archive is unreadable: {exc}") from exc
    if not first.strip():
        raise DatabaseUnavailable("archive is empty")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def download_bytes(url, *, attempts=3, timeout=180):
    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "threats-top-collector", "Accept": "application/gzip"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"  download failed ({exc}); retrying")
    raise DatabaseUnavailable(f"GET failed after {attempts} attempts: {url}") from last_error


def ensure_database(*, now=None, cache_dir=None, opener=None):
    """Path to a valid cached archive, downloading one if necessary."""
    cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
    opener = opener or download_bytes
    errors = []
    for month in candidate_months(now):
        path = cache_dir / archive_name(month)
        if valid_archive(path):
            return path
        try:
            install_archive(path, opener(download_url(month)))
            return path
        except DatabaseUnavailable as exc:
            errors.append(f"{month}: {exc}")
        except OSError as exc:
            errors.append(f"{month}: {exc}")
    raise DatabaseUnavailable(
        "could not obtain a DB-IP Lite archive (" + "; ".join(errors) + ")"
    )


def main():
    path = ensure_database()
    started = datetime.now(timezone.utc)
    database = load_database(path)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    print(f"{path} ({path.stat().st_size / 1024 / 1024:.1f} MB)")
    print(
        f"{len(database)} country ranges, {database.skipped} malformed rows skipped, "
        f"parsed in {elapsed:.1f}s"
    )
    for probe in ("8.8.8.8", "1.1.1.1", "2606:4700::1111"):
        print(f"  {probe:20s} {database.country(probe) or '-'}")
    print(DB_ATTRIBUTION)
    return 0


if __name__ == "__main__":
    sys.exit(main())
