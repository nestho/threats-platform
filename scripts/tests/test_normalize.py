"""Unit tests for timestamp normalisation and failure tolerance."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalize import (
    NormalisationTally,
    NormalisationTooManyFailures,
    UnknownTimezone,
    UnparseableTimestamp,
    parse_datetime,
    to_iso_date,
    to_iso_utc,
)


class ToIsoUtcTests(unittest.TestCase):
    def test_known_upstream_formats_normalise_to_utc(self):
        cases = {
            # CERT-EU publishes CEST, which JavaScript cannot parse.
            "Tue, 22 Sep 2026 18:52:36 CEST": "2026-09-22T16:52:36Z",
            "Fri, 11 Sep 2026 00:00:00 +0000": "2026-09-11T00:00:00Z",
            "Mon, 01 Sep 2026 09:00:00 GMT": "2026-09-01T09:00:00Z",
            # NVD publishes naive UTC.
            "2026-09-24T16:17:22.157": "2026-09-24T16:17:22Z",
            "2026-09-26T15:31:27Z": "2026-09-26T15:31:27Z",
            "2026-09-27 02:20:17": "2026-09-27T02:20:17Z",
            "2026-09-27T02:20:17+02:00": "2026-09-27T00:20:17Z",
        }
        for raw, expected in cases.items():
            self.assertEqual(to_iso_utc(raw), expected, raw)

    def test_an_unknown_zone_is_refused_not_assumed_utc(self):
        with self.assertRaises(UnknownTimezone):
            to_iso_utc("Wed, 04 Feb 2026 10:00:00 XYZ")

    def test_garbage_is_unparseable(self):
        for value in ("", "not a date", None, "2026-13-40T99:99:99Z"):
            with self.assertRaises(UnparseableTimestamp, msg=repr(value)):
                to_iso_utc(value)


class ToIsoDateTests(unittest.TestCase):
    def test_preserves_date_only_precision(self):
        self.assertEqual(to_iso_date("2026-10-26"), "2026-10-26")
        self.assertEqual(to_iso_date("2026-10-26T23:59:59Z"), "2026-10-26")

    def test_rejects_a_non_date(self):
        with self.assertRaises(UnparseableTimestamp):
            to_iso_date("26-10-2026")


class ParseDatetimeTests(unittest.TestCase):
    def test_result_is_always_timezone_aware(self):
        parsed = parse_datetime("2026-09-27 02:20:17")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)


class NormalisationTallyTests(unittest.TestCase):
    def test_a_few_bad_rows_are_tolerated_and_recorded(self):
        tally = NormalisationTally("test")
        for _ in range(7):
            self.assertIsNotNone(tally.iso("2026-10-27T00:00:00Z"))
        for _ in range(3):
            self.assertIsNone(tally.iso("garbage"))

        self.assertEqual(tally.failed, 3)
        self.assertFalse(tally.exceeded())

    def test_a_systematic_break_fails_loudly(self):
        tally = NormalisationTally("test")
        for _ in range(6):
            tally.iso("2026-10-27T00:00:00Z")
        for _ in range(4):
            tally.iso("garbage")

        self.assertTrue(tally.exceeded())
        with self.assertRaises(NormalisationTooManyFailures):
            tally.raise_if_exceeded()

    def test_failure_records_are_bounded_and_inspectable(self):
        tally = NormalisationTally("test")
        tally.iso("x" * 500, field="items[].published")
        failure = tally.failures[0]
        self.assertEqual(failure["field"], "items[].published")
        self.assertLessEqual(len(failure["value"]), 80)
        self.assertLessEqual(len(failure["error"]), 160)

    def test_date_tally(self):
        tally = NormalisationTally("test")
        self.assertEqual(tally.date("2026-10-26"), "2026-10-26")
        self.assertIsNone(tally.date("nope"))
        self.assertEqual(tally.failed, 1)


if __name__ == "__main__":
    unittest.main()
