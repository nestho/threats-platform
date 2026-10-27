"""Tests for per-source isolation, cadence selection, and outage detection."""
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_collectors
import status

BASE_SOURCE = {
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


class SelectedSourcesTests(unittest.TestCase):
    def test_all_returns_every_registered_source(self):
        sources = {"a": BASE_SOURCE, "b": BASE_SOURCE}
        with mock.patch.dict(status.SOURCES, sources, clear=True):
            self.assertEqual(run_collectors.selected_sources("all"), ["a", "b"])

    def test_explicit_list_is_ordered_by_the_registry(self):
        sources = {"a": BASE_SOURCE, "b": BASE_SOURCE, "c": BASE_SOURCE}
        with mock.patch.dict(status.SOURCES, sources, clear=True):
            self.assertEqual(run_collectors.selected_sources("c,a"), ["a", "c"])

    def test_an_unknown_source_is_refused(self):
        with mock.patch.dict(status.SOURCES, {"a": BASE_SOURCE}, clear=True):
            with self.assertRaises(SystemExit) as error:
                run_collectors.selected_sources("a,nope")
            self.assertIn("nope", str(error.exception))

    def test_auto_selects_due_and_missing_sources_only(self):
        sources = {"a": BASE_SOURCE, "b": BASE_SOURCE, "c": BASE_SOURCE}
        previous = {
            "a": {"last_success": minutes_ago(5)},    # fresh
            "b": {"last_success": minutes_ago(600)},  # overdue
            # c has no status entry and is therefore due
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "test.json").write_text("{}", encoding="utf-8")
            with mock.patch.dict(status.SOURCES, sources, clear=True):
                with mock.patch.object(run_collectors, "DATA_DIR", tmp):
                    with mock.patch.object(run_collectors, "load_status", return_value=previous):
                        self.assertEqual(run_collectors.selected_sources("auto"), ["b", "c"])

    def test_auto_selects_a_source_whose_primary_feed_is_missing(self):
        sources = {"a": BASE_SOURCE}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(status.SOURCES, sources, clear=True):
                with mock.patch.object(run_collectors, "DATA_DIR", Path(tmp)):
                    with mock.patch.object(run_collectors, "load_status", return_value={}):
                        self.assertEqual(run_collectors.selected_sources("auto"), ["a"])


class HttpStatusTests(unittest.TestCase):
    def test_status_code_is_extracted_when_present(self):
        self.assertEqual(run_collectors.http_status_from("failed with HTTP Error 503"), 503)
        self.assertEqual(run_collectors.http_status_from("HTTP 404 not found"), 404)
        self.assertIsNone(run_collectors.http_status_from("connection reset"))


class SourceIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "fail_feed.py").write_text(
            "import sys\nprint('trying')\nprint('upstream said no', file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        (scripts / "ok_feed.py").write_text("print('ok')\n", encoding="utf-8")
        self.sources = {
            "fail": {**BASE_SOURCE, "script": "fail_feed.py"},
            "ok": {**BASE_SOURCE, "script": "ok_feed.py"},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def test_a_failing_source_is_recorded_not_raised(self):
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            with mock.patch.object(run_collectors, "ROOT", self.root):
                with mock.patch.object(status, "DATA_DIR", self.root):
                    with mock.patch("builtins.print"):
                        entry = run_collectors.run_source(
                            "fail",
                            {"last_success": "2026-10-01T00:00:00Z", "items": 5},
                        )

        self.assertEqual(entry["error"], "upstream said no")
        self.assertEqual(entry["last_success"], "2026-10-01T00:00:00Z")
        self.assertEqual(entry["items"], 5)

    def test_a_successful_source_without_a_feed_file_is_not_an_error(self):
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            with mock.patch.object(run_collectors, "ROOT", self.root):
                with mock.patch.object(status, "DATA_DIR", self.root):
                    with mock.patch("builtins.print"):
                        entry = run_collectors.run_source("ok", {})

        self.assertIsNone(entry["error"])
        self.assertIsNotNone(entry["last_success"])
        self.assertEqual(entry["items"], 0)

    def test_one_failure_does_not_prevent_another_source_from_running(self):
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            with mock.patch.object(run_collectors, "ROOT", self.root):
                with mock.patch.object(status, "DATA_DIR", self.root):
                    with mock.patch("builtins.print"):
                        failed = run_collectors.run_source("fail", {})
                        succeeded = run_collectors.run_source("ok", {})

        self.assertIsNotNone(failed["error"])
        self.assertIsNone(succeeded["error"])


class CriticalOutageTests(unittest.TestCase):
    def setUp(self):
        self.sources = {
            "critical": {**BASE_SOURCE, "critical": True},
            "minor": {**BASE_SOURCE, "critical": False},
        }

    def test_a_fresh_critical_source_is_healthy(self):
        entries = [
            {"id": "critical", "last_success": minutes_ago(10)},
            {"id": "minor", "last_success": minutes_ago(10000)},
        ]
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            self.assertIsNone(run_collectors.critical_outage(entries))

    def test_a_critical_source_past_the_hard_limit_is_an_outage(self):
        entries = [{"id": "critical", "last_success": minutes_ago(25 * 60)}]
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            outage = run_collectors.critical_outage(entries)
        self.assertIsNotNone(outage)
        self.assertEqual(outage[0], "critical")
        self.assertIn("stale", outage[1])

    def test_a_critical_source_that_never_succeeded_is_an_outage(self):
        entries = [{"id": "critical", "last_success": None}]
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            outage = run_collectors.critical_outage(entries)
        self.assertEqual(outage, ("critical", "has never succeeded"))

    def test_a_stale_non_critical_source_does_not_fail_the_run(self):
        entries = [{"id": "minor", "last_success": minutes_ago(10000)}]
        with mock.patch.dict(status.SOURCES, self.sources, clear=True):
            self.assertIsNone(run_collectors.critical_outage(entries))


if __name__ == "__main__":
    unittest.main()
