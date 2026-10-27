"""Tests for cadence bookkeeping and the public freshness document."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import status
from feed_io import now_iso

SOURCE = {
    "label": "Test Source",
    "url": "https://example.com/feed",
    "cadence_minutes": 60,
    "critical": False,
    "script": "test_feed.py",
    "feeds": ["test.json"],
    "primary_feed": "test.json",
}


def minutes_ago(minutes):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class IsDueTests(unittest.TestCase):
    def test_a_source_that_never_succeeded_is_due(self):
        with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
            self.assertTrue(status.is_due("test", None))
            self.assertTrue(status.is_due("test", {}))

    def test_a_fresh_source_is_not_due(self):
        with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
            previous = {"last_success": minutes_ago(1)}
            self.assertFalse(status.is_due("test", previous))

    def test_cadence_and_grace_boundary(self):
        with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
            # Due five minutes before the cadence expires, so an hourly job that
            # finished a few seconds late does not wait an extra full hour.
            self.assertTrue(status.is_due("test", {"last_success": minutes_ago(56)}))
            self.assertFalse(status.is_due("test", {"last_success": minutes_ago(54)}))

    def test_an_unparseable_last_success_is_due(self):
        with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
            self.assertTrue(status.is_due("test", {"last_success": "yesterday"}))


class StaleTests(unittest.TestCase):
    def test_staleness_is_twice_the_cadence(self):
        entry = {"last_success": minutes_ago(119), "cadence_minutes": 60}
        self.assertFalse(status.mark_stale(entry)["stale"])

        entry = {"last_success": minutes_ago(121), "cadence_minutes": 60}
        self.assertTrue(status.mark_stale(entry)["stale"])

    def test_no_success_ever_is_stale(self):
        entry = {"last_success": None, "cadence_minutes": 60}
        marked = status.mark_stale(entry)
        self.assertTrue(marked["stale"])
        self.assertIsNone(marked["age_minutes"])


class OverallTests(unittest.TestCase):
    def test_clean_sources_are_ok(self):
        self.assertEqual(status.overall([{"stale": False, "error": None}]), "ok")

    def test_a_stale_non_critical_source_degrades(self):
        self.assertEqual(
            status.overall([{"stale": True, "critical": False, "error": None}]),
            "degraded",
        )

    def test_a_stale_critical_source_is_an_outage(self):
        self.assertEqual(
            status.overall([{"stale": True, "critical": True, "error": None}]),
            "outage",
        )

    def test_an_error_without_staleness_degrades(self):
        self.assertEqual(
            status.overall([{"stale": False, "critical": True, "error": "boom"}]),
            "degraded",
        )


class EnrichEntryTests(unittest.TestCase):
    def test_success_records_the_feed_timestamp_and_item_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stamp = minutes_ago(0)
            (tmp / "test.json").write_text(
                json.dumps({"updated_at": stamp, "items": [{"id": 1}, {"id": 2}]}),
                encoding="utf-8",
            )
            with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
                with mock.patch.object(status, "DATA_DIR", tmp):
                    entry = status.enrich_entry(
                        "test",
                        {},
                        attempted=now_iso(),
                        succeeded=True,
                        error=None,
                        duration_ms=123,
                    )

            self.assertEqual(entry["last_success"], stamp)
            self.assertEqual(entry["items"], 2)
            self.assertIsNone(entry["error"])
            self.assertEqual(entry["duration_ms"], 123)

    def test_failure_preserves_the_last_success_and_records_the_error(self):
        previous = {"last_success": "2026-10-01T00:00:00Z", "items": 7}
        with mock.patch.dict(status.SOURCES, {"test": SOURCE}, clear=True):
            entry = status.enrich_entry(
                "test",
                previous,
                attempted=now_iso(),
                succeeded=False,
                error="HTTP Error 503",
                duration_ms=50,
                http_status=503,
            )

        self.assertEqual(entry["last_success"], previous["last_success"])
        self.assertEqual(entry["items"], 7)
        self.assertEqual(entry["error"], "HTTP Error 503")
        self.assertEqual(entry["http_status"], 503)


class WriteStatusTests(unittest.TestCase):
    def test_document_is_ordered_and_never_omits_a_registered_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "status.json"
            sources = {
                "first": SOURCE,
                "second": {**SOURCE, "label": "Second", "feeds": ["other.json"],
                           "primary_feed": "other.json"},
            }
            entries = {}
            with mock.patch.dict(status.SOURCES, sources, clear=True):
                entries["second"] = status.enrich_entry(
                    "second", {}, attempted=now_iso(), succeeded=False,
                    error="not yet", duration_ms=0,
                )
                with mock.patch.object(status, "STATUS_PATH", path):
                    with mock.patch.object(status, "DATA_DIR", Path(tmp)):
                        document = status.write_status(entries)

            self.assertEqual([entry["id"] for entry in document["sources"]], ["first", "second"])
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["overall"], "degraded")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["sources"][0]["id"],
                             "first")


if __name__ == "__main__":
    unittest.main()
