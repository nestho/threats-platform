"""Unit tests for the publishing helpers every collector relies on."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import feed_io


class WriteJsonTests(unittest.TestCase):
    def test_writes_nested_path_atomically_and_leaves_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "feed.json"
            feed_io.write_json(path, {"items": [{"title": "café"}]})

            raw = path.read_text(encoding="utf-8")
            self.assertTrue(raw.endswith("\n"))
            self.assertEqual(json.loads(raw), {"items": [{"title": "café"}]})
            self.assertEqual([entry.name for entry in path.parent.iterdir()], ["feed.json"])

    def test_a_failed_write_keeps_the_previous_file_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text('{"previous": true}\n', encoding="utf-8")

            # Sets are not JSON-serialisable; the failure happens after the
            # temporary file exists but before os.replace.
            with self.assertRaises(TypeError):
                feed_io.write_json(path, {"items": {1, 2}})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"previous": True})
            self.assertEqual([entry.name for entry in path.parent.iterdir()], ["feed.json"])

    def test_read_json_returns_default_for_missing_or_broken_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"
            self.assertIsNone(feed_io.read_json(path))
            self.assertEqual(feed_io.read_json(path, default=[]), [])

            broken = Path(tmp) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            self.assertEqual(feed_io.read_json(broken, default={}), {})


class StableIdTests(unittest.TestCase):
    def test_same_identity_produces_the_same_id(self):
        first = feed_io.stable_id("ioc", "url", "hxxps://evil.example/x")
        second = feed_io.stable_id("ioc", "url", "hxxps://evil.example/x")
        self.assertEqual(first, second)

    def test_different_identity_produces_a_different_id(self):
        self.assertNotEqual(
            feed_io.stable_id("ioc", "url", "hxxps://evil.example/x"),
            feed_io.stable_id("ioc", "url", "hxxps://evil.example/y"),
        )

    def test_id_is_prefixed_and_url_safe(self):
        value = feed_io.stable_id("rw", "LockBit", "Acme Corp", "2026-10-01")
        self.assertRegex(value, r"^rw-[0-9a-f]{16}$")

    def test_none_is_distinct_from_the_string_none(self):
        self.assertNotEqual(
            feed_io.stable_id("x", None),
            feed_io.stable_id("x", "None"),
        )


class TimestampTests(unittest.TestCase):
    def test_parse_iso_accepts_our_own_format_only(self):
        parsed = feed_io.parse_iso("2026-10-27T12:34:56Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2026)

        for value in ("2026-10-27T12:34:56+00:00", "2026-10-27", "", None, 12):
            self.assertIsNone(feed_io.parse_iso(value))


class DefangTests(unittest.TestCase):
    def test_https_and_http_are_defanged(self):
        self.assertEqual(feed_io.defang("https://evil.example/x"), "hxxps://evil.example/x")
        self.assertEqual(feed_io.defang("http://evil.example/x"), "hxxp://evil.example/x")

    def test_refang_restores_the_original(self):
        url = "https://evil.example/login?next=http://kept.example"
        self.assertEqual(feed_io.refang(feed_io.defang(url)), url)

    def test_non_http_schemes_are_left_untouched(self):
        self.assertEqual(feed_io.defang("javascript:alert(1)"), "javascript:alert(1)")
        self.assertEqual(feed_io.defang(None), "")

    def test_scheme_matching_ignores_case(self):
        self.assertEqual(feed_io.defang("HTTP://evil.example/x"), "hxxp://evil.example/x")
        self.assertEqual(feed_io.refang("HXXPS://evil.example/x"), "https://evil.example/x")

    def test_only_the_scheme_is_rewritten(self):
        url = "https://evil.example/a?b=http://c.example&d=https://e.example"
        self.assertEqual(
            feed_io.defang(url),
            "hxxps://evil.example/a?b=http://c.example&d=https://e.example",
        )


class UrlTests(unittest.TestCase):
    def test_only_absolute_http_urls_are_accepted(self):
        for value in ("https://a.example/x", "http://a.example", " HTTPS://a.example "):
            self.assertTrue(feed_io.is_http_url(value), value)

        for value in ("javascript:alert(1)", "not a url", "/relative", "", None, "ftp://a.example"):
            self.assertFalse(feed_io.is_http_url(value), value)


class EnvelopeTests(unittest.TestCase):
    def test_envelope_carries_provenance_and_a_parseable_timestamp(self):
        document = feed_io.envelope(
            "Example Source",
            ["https://a.example/feed", "https://b.example/feed"],
            total=2,
            items=[],
        )
        self.assertEqual(document["source"], "Example Source")
        self.assertEqual(document["source_url"], ["https://a.example/feed", "https://b.example/feed"])
        self.assertEqual(document["total"], 2)
        self.assertIsNotNone(feed_io.parse_iso(document["updated_at"]))

    def test_item_count_understands_every_feed_shape(self):
        self.assertEqual(feed_io.item_count({"items": [1, 2]}), 2)
        self.assertEqual(feed_io.item_count({"programs": [1]}), 1)
        self.assertEqual(feed_io.item_count({"events": [1, 2, 3]}), 3)
        self.assertEqual(
            feed_io.item_count({"recent": {"items": [1]}, "actively_exploited": {"items": [2, 3]}}),
            3,
        )
        self.assertEqual(feed_io.item_count({}), 0)
        self.assertEqual(feed_io.item_count(None), 0)


class TextTests(unittest.TestCase):
    def test_strip_html_collapses_markup_and_whitespace(self):
        self.assertEqual(
            feed_io.strip_html("<p>An <b>important</b>\n  notice.</p>"),
            "An important notice.",
        )
        self.assertEqual(feed_io.strip_html(None), "")

    def test_truncate_keeps_the_limit_and_strips_edges(self):
        self.assertEqual(feed_io.truncate("  abcdef  ", 4), "abcd")
        self.assertEqual(feed_io.truncate(None, 10), "")


if __name__ == "__main__":
    unittest.main()
