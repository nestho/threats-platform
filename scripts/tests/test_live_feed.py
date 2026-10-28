"""Unit tests for the live-map feed.

The feed is the only thing that makes the map move, so the window arithmetic,
the "drop instead of guess" rules and the coverage counters are the contract.
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live_feed import build_document, claim_events, host_events, resolve_hosts

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
COLLECTED = "2026-10-28T12:00:00Z"


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def claim(**overrides):
    item = {
        "id": "rw-1",
        "victim": "Acme Corp",
        "domain": "acme.example",
        "group": "LockBit",
        "activity": "Manufacturing",
        "country": "US",
        "published": "2026-10-28T06:00:00Z",
        "discovered": "2026-10-28T06:05:00Z",
    }
    item.update(overrides)
    return item


class ClaimEventTests(unittest.TestCase):
    def test_emits_a_plottable_claim(self):
        events, coverage = claim_events([claim()], now=NOW)

        self.assertEqual(events, [{
            "id": "rw-1",
            "kind": "claim",
            "ts": "2026-10-28T06:00:00Z",
            "country": "US",
            "group": "LockBit",
            "sector": "Manufacturing",
            "host": None,
        }])
        self.assertEqual(coverage["claims_total"], 1)
        self.assertEqual(coverage["claims_mapped"], 1)

    def test_uses_discovered_when_published_is_missing(self):
        events, _ = claim_events([claim(published=None)], now=NOW)
        self.assertEqual(events[0]["ts"], "2026-10-28T06:05:00Z")

    def test_claims_outside_the_window_are_dropped(self):
        old = claim(published=iso(NOW - timedelta(hours=73)))
        events, coverage = claim_events([old], now=NOW)

        self.assertEqual(events, [])
        self.assertEqual(coverage["claims_total"], 1)
        self.assertEqual(coverage["claims_in_window"], 0)

    def test_the_window_start_is_inclusive(self):
        edge = claim(published=iso(NOW - timedelta(hours=72)))
        events, _ = claim_events([edge], now=NOW)
        self.assertEqual(len(events), 1)

    def test_a_claim_stamped_in_the_future_is_dropped(self):
        future = claim(published=iso(NOW + timedelta(hours=1)))
        events, _ = claim_events([future], now=NOW)
        self.assertEqual(events, [])

    def test_an_unparseable_timestamp_is_dropped(self):
        broken = claim(published="not a date", discovered=None)
        events, coverage = claim_events([broken], now=NOW)

        self.assertEqual(events, [])
        self.assertEqual(coverage["claims_in_window"], 0)

    def test_a_claim_without_a_country_is_counted_but_not_plotted(self):
        for country in (None, "", "USA", "1X"):
            events, coverage = claim_events([claim(country=country)], now=NOW)
            self.assertEqual(events, [], repr(country))
            self.assertEqual(coverage["claims_total"], 1)
            self.assertEqual(coverage["claims_in_window"], 1)
            self.assertEqual(coverage["claims_mapped"], 0)

    def test_group_defaults_and_an_empty_sector_becomes_null(self):
        events, _ = claim_events([claim(group="  ", activity=None)], now=NOW)
        self.assertEqual(events[0]["group"], "Unattributed")
        self.assertIsNone(events[0]["sector"])

    def test_does_not_republish_victim_or_domain(self):
        events, _ = claim_events([claim()], now=NOW)
        self.assertNotIn("victim", events[0])
        self.assertNotIn("domain", events[0])

    def test_events_are_sorted_newest_first(self):
        items = [
            claim(id="a", published="2026-10-27T00:00:00Z"),
            claim(id="b", published="2026-10-28T10:00:00Z"),
            claim(id="c", published="2026-10-28T02:00:00Z"),
        ]
        events, _ = claim_events(items, now=NOW)
        self.assertEqual([event["id"] for event in events], ["b", "c", "a"])

    def test_duplicate_claim_ids_are_published_once(self):
        events, _ = claim_events([claim(), claim()], now=NOW)
        self.assertEqual(len(events), 1)

    def test_the_cap_keeps_the_newest_events(self):
        items = [
            claim(id=f"rw-{hour}", published=iso(NOW - timedelta(hours=hour)))
            for hour in range(5)
        ]
        events, _ = claim_events(items, now=NOW, limit=2)
        self.assertEqual([event["id"] for event in events], ["rw-0", "rw-1"])


class HostEventTests(unittest.TestCase):
    ADDRESSES = {"a.example": "8.8.8.8", "b.example": "10.0.0.1"}

    @staticmethod
    def lookup(address):
        return "US" if address == "8.8.8.8" else None

    def test_emits_a_plottable_host(self):
        events, _ = host_events(
            ["a.example"], self.ADDRESSES, self.lookup, collected_at=COLLECTED
        )
        self.assertEqual(events[0]["kind"], "host")
        self.assertEqual(events[0]["host"], "a.example")
        self.assertEqual(events[0]["country"], "US")
        self.assertEqual(events[0]["ts"], COLLECTED)
        self.assertIsNone(events[0]["group"])
        self.assertIsNone(events[0]["sector"])

    def test_a_resolved_host_without_a_country_is_counted_not_plotted(self):
        events, coverage = host_events(
            ["a.example", "b.example"], self.ADDRESSES, self.lookup, collected_at=COLLECTED
        )

        self.assertEqual([event["host"] for event in events], ["a.example"])
        self.assertEqual(coverage["hosts_total"], 2)
        self.assertEqual(coverage["hosts_resolved"], 2)
        self.assertEqual(coverage["hosts_mapped"], 1)

    def test_hosts_are_normalised_and_deduplicated(self):
        events, coverage = host_events(
            ["A.Example", "a.example", " a.example "],
            self.ADDRESSES,
            self.lookup,
            collected_at=COLLECTED,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(coverage["hosts_total"], 1)

    def test_invalid_hostnames_are_skipped(self):
        bad = ["", None, "localhost", "http://a.example/", "a.example:8080", "*.example"]
        events, coverage = host_events(bad, {}, self.lookup, collected_at=COLLECTED)
        self.assertEqual(events, [])
        self.assertEqual(coverage["hosts_total"], 0)

    def test_ids_are_stable_across_collections(self):
        first, _ = host_events(["a.example"], self.ADDRESSES, self.lookup,
                               collected_at="2026-10-28T11:00:00Z")
        second, _ = host_events(["a.example"], self.ADDRESSES, self.lookup,
                                collected_at=COLLECTED)
        self.assertEqual(first[0]["id"], second[0]["id"])


class ResolveHostsTests(unittest.TestCase):
    def test_resolves_each_valid_host_once(self):
        calls = []

        def resolver(host):
            calls.append(host)
            return "8.8.8.8"

        addresses = resolve_hosts(["a.example", "A.example", "b.example"], resolver=resolver)

        self.assertEqual(sorted(calls), ["a.example", "b.example"])
        self.assertEqual(addresses, {"a.example": "8.8.8.8", "b.example": "8.8.8.8"})

    def test_a_failing_lookup_does_not_lose_the_others(self):
        def resolver(host):
            if host == "dead.example":
                raise OSError("NXDOMAIN")
            return "1.1.1.1"

        addresses = resolve_hosts(["dead.example", "live.example"], resolver=resolver)
        self.assertEqual(addresses, {"live.example": "1.1.1.1"})

    def test_a_resolver_returning_garbage_is_ignored(self):
        addresses = resolve_hosts(
            ["a.example", "b.example"],
            resolver=lambda host: None if host == "a.example" else "not-an-ip",
        )
        self.assertEqual(addresses, {})

    def test_no_hosts_means_no_queries(self):
        self.assertEqual(resolve_hosts([], resolver=lambda host: "8.8.8.8"), {})


class BuildDocumentTests(unittest.TestCase):
    def build(self, *, lookup=None, geo_available=True):
        return build_document(
            claims=[claim(), claim(id="rw-2", country=None)],
            hosts=["a.example", "b.example"],
            addresses=HostEventTests.ADDRESSES,
            lookup=lookup or HostEventTests.lookup,
            collected_at=COLLECTED,
            geo_available=geo_available,
        )

    def test_envelope_carries_provenance_and_attribution(self):
        document = self.build()

        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["updated_at"], COLLECTED)
        self.assertEqual(document["window_hours"], 72)
        self.assertIsInstance(document["source"], str)
        self.assertEqual(len(document["source_url"]), 2)
        self.assertIn("DB-IP", document["attribution"]["ip_geolocation"])
        self.assertEqual(document["attribution"]["license_url"],
                         "https://creativecommons.org/licenses/by/4.0/")
        self.assertIsInstance(document["note"], str)

    def test_events_combine_claims_and_hosts_newest_first(self):
        events = self.build()["events"]
        self.assertEqual({event["kind"] for event in events}, {"claim", "host"})
        timestamps = [event["ts"] for event in events]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))

    def test_coverage_is_reported_not_implied(self):
        coverage = self.build()["coverage"]
        self.assertEqual(coverage["claims_total"], 2)
        self.assertEqual(coverage["claims_mapped"], 1)
        self.assertEqual(coverage["hosts_total"], 2)
        self.assertEqual(coverage["hosts_resolved"], 2)
        self.assertEqual(coverage["hosts_mapped"], 1)
        self.assertTrue(coverage["geo_available"])

    def test_without_a_country_database_claims_still_publish(self):
        document = self.build(lookup=lambda address: None, geo_available=False)
        kinds = {event["kind"] for event in document["events"]}

        self.assertEqual(kinds, {"claim"})
        self.assertFalse(document["coverage"]["geo_available"])


if __name__ == "__main__":
    unittest.main()
