import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cowrie_forwarder import forward_once


NOW = datetime(2026, 11, 14, 12, 34, 30, tzinfo=timezone.utc)


def connection(timestamp, source="198.51.100.7", eventid="cowrie.session.connect"):
    return json.dumps({
        "eventid": eventid,
        "timestamp": timestamp,
        "src_ip": source,
        "src_port": 43210,
        "session": "private-session-id",
    }) + "\n"


class CowrieForwarderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "cowrie.json"
        self.state = self.root / "state.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_posts_country_minute_counts_without_source_ips_or_credentials(self):
        self.log.write_text(
            connection("2026-11-14T12:33:08Z")
            + connection("2026-11-14T12:33:59Z", "198.51.100.8")
            + connection("2026-11-14T12:34:12Z", eventid="cowrie.login.failed"),
            encoding="utf-8",
        )
        posted = []

        processed = forward_once(
            self.log,
            self.state,
            "https://api.example.test/ingest",
            "secret",
            lambda _address: "US",
            now=NOW,
            send=lambda url, token, events: posted.append((url, token, events)),
        )

        self.assertEqual(processed, 3)
        self.assertEqual(posted, [(
            "https://api.example.test/ingest",
            "secret",
            [{"minute": "2026-11-14T12:33:00Z", "country": "US", "count": 2}],
        )])
        state = self.state.read_text(encoding="utf-8")
        self.assertNotIn("198.51.100", state)
        self.assertNotIn("private-session-id", state)

    def test_retries_unsent_counts_without_double_counting_the_log(self):
        self.log.write_text(connection("2026-11-14T12:33:08Z"), encoding="utf-8")
        calls = []

        def fail_once(_url, _token, events):
            calls.append(events)
            if len(calls) == 1:
                raise RuntimeError("temporary network failure")

        with self.assertRaisesRegex(RuntimeError, "temporary"):
            forward_once(
                self.log, self.state, "https://api.example.test/ingest", "secret",
                lambda _address: "GB", now=NOW, send=fail_once,
            )

        forward_once(
            self.log, self.state, "https://api.example.test/ingest", "secret",
            lambda _address: "GB", now=NOW, send=fail_once,
        )
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(calls[1][0]["count"], 1)
        self.assertEqual(json.loads(self.state.read_text())["dirty"], [])

    def test_keeps_an_incomplete_json_line_until_it_is_terminated(self):
        self.log.write_text(connection("2026-11-14T12:33:08Z").rstrip("\n"), encoding="utf-8")
        posted = []
        send = lambda _url, _token, events: posted.extend(events)
        args = (
            self.log, self.state, "https://api.example.test/ingest", "secret",
            lambda _address: "CA",
        )
        self.assertEqual(forward_once(*args, now=NOW, send=send), 0)
        self.assertEqual(posted, [])

        with self.log.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        self.assertEqual(forward_once(*args, now=NOW, send=send), 1)
        self.assertEqual(posted[0]["count"], 1)

    def test_sends_a_heartbeat_even_when_no_connection_event_is_due(self):
        self.log.write_text("", encoding="utf-8")
        posted = []
        forward_once(
            self.log,
            self.state,
            "https://api.example.test/ingest",
            "secret",
            lambda _address: "US",
            now=NOW,
            send=lambda url, token, events: posted.append(events),
        )
        self.assertEqual(posted, [[]])
        self.assertEqual(json.loads(self.state.read_text())["last_heartbeat"], "2026-11-14T12:34:30Z")


if __name__ == "__main__":
    unittest.main()
