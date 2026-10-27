"""Tests for the publishing gate: records, envelopes, status and demo data."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import validate_feeds
from feed_io import now_iso

NOW = now_iso()


def ioc(**overrides):
    record = {
        "id": "ioc-1",
        "type": "url",
        "value": "hxxps://evil.example/login",
        "source": "OpenPhish",
        "context": "active phishing URL",
        "severity": "HIGH",
        "first_seen": NOW,
        "last_seen": NOW,
        "link": "https://openphish.com/",
    }
    record.update(overrides)
    return record


def kev(**overrides):
    record = {
        "id": "CVE-2026-1111",
        "vendor": "Acme",
        "product": "Widget",
        "name": "Acme Widget RCE",
        "date_added": "2026-10-26",
        "ransomware_use": None,
        "description": "Exploited in the wild.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
    }
    record.update(overrides)
    return record


def program(**overrides):
    record = {
        "name": "Acme",
        "url": "https://hackerone.com/acme",
        "platform": "HackerOne",
        "domain_count": 1,
        "domains": ["acme.example"],
        "manual": False,
    }
    record.update(overrides)
    return record


def envelope(items, **overrides):
    document = {
        "schema_version": 1,
        "updated_at": NOW,
        "source": "Derived from OpenPhish and ransomware.live",
        "source_url": [
            "https://openphish.com/feed.txt",
            "https://api.ransomware.live/v2/recentvictims",
        ],
        "total": len(items),
        "items": items,
    }
    document.update(overrides)
    return document


def status_entry(**overrides):
    entry = {
        "id": "iocs",
        "label": "Derived IOC feed",
        "url": ["https://openphish.com/feed.txt"],
        "cadence_minutes": 60,
        "critical": False,
        "feeds": ["iocs.json"],
        "last_attempt": NOW,
        "last_success": NOW,
        "http_status": 200,
        "items": 1,
        "error": None,
        "stale": False,
    }
    entry.update(overrides)
    return entry


class RecordTests(unittest.TestCase):
    def test_a_valid_indicator_passes(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(ioc(), "ioc", "test", report)
        self.assertEqual(report.errors, [])

    def test_a_live_url_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(
            ioc(value="https://evil.example/login"), "ioc", "test", report
        )
        self.assertTrue(any("not defanged" in error for error in report.errors))

    def test_a_private_field_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(ioc(tenant_id="acme"), "ioc", "test", report)
        self.assertTrue(any("private field" in error for error in report.errors))

    def test_a_defanged_url_with_an_invalid_hostname_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(
            ioc(type="domain", value="not_a_hostname"), "ioc", "test", report
        )
        self.assertTrue(any("not a hostname" in error for error in report.errors))

    def test_a_javascript_link_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(ioc(link="javascript:alert(1)"), "ioc", "test", report)
        self.assertTrue(any("http(s) URL" in error for error in report.errors))

    def test_the_kev_unknown_sentinel_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(kev(ransomware_use="Unknown"), "kev", "test", report)
        self.assertTrue(any('"Unknown"' in error for error in report.errors))

    def test_a_program_outside_the_platform_enum_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(
            program(platform="BugCrowd Pro"), "program", "test", report
        )
        self.assertTrue(any("canonical enum" in error for error in report.errors))

    def test_domain_count_must_match_the_list(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(program(domain_count=3), "program", "test", report)
        self.assertTrue(any("domains has" in error for error in report.errors))

    def test_text_that_is_entirely_markup_is_rejected(self):
        report = validate_feeds.Report()
        validate_feeds.check_record(
            {"id": "CVE-2024-0001", "published": NOW, "description": "<p></p>",
             "severity": None, "score": None, "cvss_version": None,
             "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "kev": False},
            "cve",
            "test",
            report,
        )
        self.assertTrue(any("entirely of markup" in error for error in report.errors))


class EnvelopeTests(unittest.TestCase):
    def test_a_complete_envelope_passes(self):
        report = validate_feeds.Report()
        validate_feeds.check_envelope(envelope([]), "iocs.json", report)
        self.assertEqual(report.errors, [])

    def test_provenance_is_required(self):
        document = envelope([])
        del document["source_url"]
        report = validate_feeds.Report()
        validate_feeds.check_envelope(document, "iocs.json", report)
        self.assertTrue(any("source_url" in error for error in report.errors))

    def test_schema_version_must_match_the_registry(self):
        report = validate_feeds.Report()
        validate_feeds.check_envelope(envelope([], schema_version=2), "iocs.json", report)
        self.assertTrue(any("EXPECTED_SCHEMA_VERSION" in error for error in report.errors))

    def test_updated_at_must_be_explicit_utc(self):
        report = validate_feeds.Report()
        validate_feeds.check_envelope(
            envelope([], updated_at="2026-10-27T12:00:00+00:00"), "iocs.json", report
        )
        self.assertTrue(any("is not" in error for error in report.errors))


class DemoMarkerTests(unittest.TestCase):
    def test_a_nested_demo_tenant_is_found(self):
        report = validate_feeds.Report()
        validate_feeds.check_demo_markers(
            {"items": [{"note": "seeded from DEFAULT-PRO"}]}, "data/test.json", report
        )
        self.assertTrue(any("default-pro" in error for error in report.errors))

    def test_public_pages_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text("<p>demo-tenant</p>", encoding="utf-8")
            (root / "clean.html").write_text("<p>Threats</p>", encoding="utf-8")

            report = validate_feeds.Report()
            with mock.patch.object(validate_feeds, "ROOT", root):
                validate_feeds.validate_public_ui(report)

            self.assertEqual(len(report.errors), 1)
            self.assertIn("index.html", report.errors[0])


class FeedTests(unittest.TestCase):
    def test_an_empty_feed_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "iocs.json"
            path.write_text(json.dumps(envelope([])), encoding="utf-8")

            report = validate_feeds.Report()
            validate_feeds.validate_feed(path, report, check_regression=False, ref=None)
            self.assertTrue(any("zero items" in error for error in report.errors))

    def test_a_large_drop_against_the_baseline_warns(self):
        items = [ioc(id=f"ioc-{index}", value=f"hxxps://host{index}.example/x",
                     last_seen=f"2026-10-2{9 - index}T12:00:00Z") for index in range(4)]
        baseline = envelope([ioc(id=f"old-{index}") for index in range(10)])

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "iocs.json"
            path.write_text(json.dumps(envelope(items)), encoding="utf-8")

            report = validate_feeds.Report()
            with mock.patch.object(validate_feeds, "load_baseline", return_value=baseline):
                validate_feeds.validate_feed(path, report, check_regression=True, ref="HEAD")

            self.assertEqual(report.errors, [])
            self.assertTrue(any("item count fell" in warning for warning in report.warnings))

    def test_a_feed_that_empties_out_is_rejected(self):
        baseline = envelope([ioc(id=f"old-{index}") for index in range(10)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "iocs.json"
            path.write_text(json.dumps(envelope([])), encoding="utf-8")

            report = validate_feeds.Report()
            with mock.patch.object(validate_feeds, "load_baseline", return_value=baseline):
                validate_feeds.validate_feed(path, report, check_regression=True, ref="HEAD")

            self.assertTrue(any("zero items" in error for error in report.errors))


class StatusTests(unittest.TestCase):
    def make_repo(self, tmp, *, feed_items, status_overrides=None):
        tmp = Path(tmp)
        data = tmp / "data"
        data.mkdir()
        (data / "iocs.json").write_text(json.dumps(envelope(feed_items)), encoding="utf-8")
        document = {
            "schema_version": 1,
            "generated_at": NOW,
            "overall": "ok",
            "sources": [status_entry(**(status_overrides or {}))],
        }
        (data / "status.json").write_text(json.dumps(document), encoding="utf-8")
        return data

    def run_status_check(self, tmp, *, feed_items=None, status_overrides=None):
        data = self.make_repo(
            tmp,
            feed_items=feed_items if feed_items is not None else [ioc()],
            status_overrides=status_overrides,
        )
        report = validate_feeds.Report()
        with mock.patch.object(validate_feeds, "DATA_DIR", data):
            with mock.patch.object(validate_feeds, "STATUS_PATH", data / "status.json"):
                with mock.patch.dict(validate_feeds.FEED_SPECS,
                                     {"iocs.json": ("flat", [(("items",), "ioc", None)])},
                                     clear=True):
                    entries = validate_feeds.load_status(report)
                    validate_feeds.validate_status_and_freshness(report, entries)
        return report

    def test_a_consistent_feed_and_status_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_status_check(tmp)
        self.assertEqual(report.errors, [])

    def test_a_status_timestamp_must_match_the_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_status_check(
                tmp, status_overrides={"last_success": "2026-10-27T11:00:00Z"}
            )
        self.assertTrue(any("does not match status last_success" in error
                            for error in report.errors))

    def test_the_published_item_count_must_match_the_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_status_check(tmp, status_overrides={"items": 2})
        self.assertTrue(any("holds 1 items" in error for error in report.errors))

    def test_stale_false_cannot_hide_an_old_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_status_check(
                tmp,
                feed_items=[ioc(last_seen="2026-10-20T12:00:00Z")],
                status_overrides={
                    "last_success": "2026-10-20T12:00:00Z",
                    "last_attempt": "2026-10-20T12:00:00Z",
                    "stale": False,
                },
            )
        self.assertTrue(any("the timestamp says True" in error for error in report.errors))

    def test_overall_must_agree_with_the_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.run_status_check(tmp, status_overrides={"error": "HTTP 503"})
        # The feed updated_at still matches, but an error means degraded.
        self.assertTrue(any("but the sources say 'degraded'" in error
                            for error in report.errors))


if __name__ == "__main__":
    unittest.main()
