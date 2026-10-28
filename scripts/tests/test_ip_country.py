"""Unit tests for the DB-IP Lite country lookup.

The lookup drives the live map's infrastructure layer, so the cases that matter
are the boundaries (inclusive ends, holes between ranges) and the guard that
stops a private or reserved address from being labelled with a country.
"""
import gzip
import ipaddress
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ip_country
from ip_country import (
    CountryDatabase,
    DatabaseUnavailable,
    archive_name,
    candidate_months,
    download_url,
    ensure_database,
    load_database,
    month_slug,
    parse_row,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def write_archive(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def archive_lines(rows):
    return [f'"{start}","{end}","{code}"' for start, end, code in rows]


def v6(value):
    return int(ipaddress.IPv6Address(value))


class ParseRowTests(unittest.TestCase):
    """Rows reach `parse_row` already unquoted, via `csv.reader`."""

    def test_parses_a_dbip_csv_row(self):
        self.assertEqual(
            parse_row(["1.0.0.0", "1.0.0.255", "AU"]),
            (4, 16777216, 16777471, "AU"),
        )

    def test_lowercase_codes_are_normalised(self):
        self.assertEqual(parse_row(["1.0.0.0", "1.0.0.255", "au"])[3], "AU")

    def test_rejects_malformed_rows(self):
        bad = [
            [],
            ["1.0.0.0", "1.0.0.255"],
            ["1.0.0.0", "1.0.0.255", "AUS"],
            ["1.0.0.0", "1.0.0.255", ""],
            ["1.0.0.300", "1.0.0.400", "AU"],
            ["1.0.0.255", "1.0.0.0", "AU"],
            ["1.0.0.0", "::1", "AU"],
            ["garbage", "rows", "x"],
        ]
        for row in bad:
            self.assertIsNone(parse_row(row), row)


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.db = CountryDatabase([
            (4, 0x01000000, 0x010000FF, "AU"),  # 1.0.0.0 - 1.0.0.255
            (4, 0x01000200, 0x010002FF, "CN"),  # 1.0.2.0 - 1.0.2.255, 1.0.1.0 is a hole
            (4, 0x08080800, 0x080808FF, "US"),  # 8.8.8.0 - 8.8.8.255
            (4, 0x0A000000, 0x0AFFFFFF, "XX"),  # 10/8 in the table, must never be labelled
            (6, v6("2606:4700::"), v6("2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"), "US"),
        ])

    def test_range_endpoints_are_inclusive(self):
        for address in ("1.0.0.0", "1.0.0.1", "1.0.0.255"):
            self.assertEqual(self.db.country(address), "AU", address)

    def test_a_hole_between_ranges_is_unknown(self):
        self.assertIsNone(self.db.country("1.0.1.5"))
        self.assertIsNone(self.db.country("1.0.3.0"))

    def test_an_address_below_every_range_is_unknown(self):
        self.assertIsNone(self.db.country("0.255.255.255"))

    def test_ipv6_ranges_are_looked_up_separately(self):
        self.assertEqual(self.db.country("2606:4700::1111"), "US")
        self.assertEqual(self.db.country("2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"), "US")
        self.assertIsNone(self.db.country("2606:4701::1"))

    def test_private_and_reserved_addresses_are_never_geolocated(self):
        for address in (
            "10.1.2.3",
            "127.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "203.0.113.9",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
        ):
            self.assertIsNone(self.db.country(address), address)

    def test_input_is_stripped_and_garbage_returns_none(self):
        self.assertEqual(self.db.country(" 8.8.8.8 "), "US")
        for value in ("", "not an ip", None, "999.1.1.1"):
            self.assertIsNone(self.db.country(value), repr(value))

    def test_counts_the_ranges_it_holds(self):
        self.assertEqual(len(self.db), 5)

    def test_unsorted_input_is_sorted_before_lookup(self):
        db = CountryDatabase([
            (4, 0x08080800, 0x080808FF, "US"),
            (4, 0x01000000, 0x010000FF, "AU"),
        ])
        self.assertEqual(db.country("1.0.0.5"), "AU")
        self.assertEqual(db.country("8.8.8.8"), "US")


class LoadDatabaseTests(unittest.TestCase):
    def test_loads_a_gzipped_archive_and_counts_garbage_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "db.csv.gz"
            write_archive(path, [
                '"1.0.0.0","1.0.0.255","AU"',
                "this is not a row",
                '"8.8.8.0","8.8.8.255","US"',
            ])
            db = load_database(path)

        self.assertEqual(db.country("1.0.0.7"), "AU")
        self.assertEqual(db.country("8.8.8.8"), "US")
        self.assertEqual(db.skipped, 1)
        self.assertEqual(len(db), 2)

    def test_a_missing_archive_is_an_error(self):
        with self.assertRaises(FileNotFoundError):
            load_database(Path("/nonexistent/dbip-country-lite.csv.gz"))


class MonthTests(unittest.TestCase):
    def test_month_slug_and_archive_name(self):
        self.assertEqual(month_slug(NOW), "2026-10")
        self.assertEqual(archive_name("2026-10"), "dbip-country-lite-2026-10.csv.gz")
        self.assertTrue(download_url("2026-10").endswith("/dbip-country-lite-2026-10.csv.gz"))

    def test_candidates_start_with_the_current_month_and_wrap_the_year(self):
        self.assertEqual(candidate_months(NOW), ["2026-10", "2026-09"])
        self.assertEqual(
            candidate_months(datetime(2026, 1, 15, tzinfo=timezone.utc)),
            ["2026-01", "2025-12"],
        )


class EnsureDatabaseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_a_cached_archive_is_used_without_fetching(self):
        cached = self.cache / archive_name("2026-10")
        write_archive(cached, archive_lines([("1.0.0.0", "1.0.0.255", "AU")]))

        def opener(url):
            raise AssertionError(f"should not fetch {url}")

        self.assertEqual(ensure_database(now=NOW, cache_dir=self.cache, opener=opener), cached)

    def test_falls_back_to_the_previous_month(self):
        payload = _gzip_bytes(['"1.0.0.0","1.0.0.255","AU"'])
        requested = []

        def opener(url):
            requested.append(url)
            if "2026-10" in url:
                raise DatabaseUnavailable("HTTP 404")
            return payload

        result = ensure_database(now=NOW, cache_dir=self.cache, opener=opener)

        self.assertEqual(result, self.cache / archive_name("2026-09"))
        self.assertTrue(result.exists())
        self.assertEqual(len(requested), 2)

    def test_a_non_gzip_response_is_rejected_and_not_cached(self):
        def opener(url):
            return b"<html>rate limited</html>"

        with self.assertRaises(DatabaseUnavailable):
            ensure_database(now=NOW, cache_dir=self.cache, opener=opener)
        self.assertEqual(list(self.cache.glob("*.gz")), [])

    def test_a_corrupt_cached_archive_is_replaced(self):
        corrupt = self.cache / archive_name("2026-10")
        corrupt.write_bytes(b"half a download")
        payload = _gzip_bytes(['"1.0.0.0","1.0.0.255","AU"'])

        result = ensure_database(now=NOW, cache_dir=self.cache, opener=lambda url: payload)

        self.assertEqual(result, corrupt)
        self.assertEqual(load_database(result).country("1.0.0.1"), "AU")


def _gzip_bytes(lines):
    import io
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
        handle.write(("\n".join(lines) + "\n").encode("utf-8"))
    return buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
