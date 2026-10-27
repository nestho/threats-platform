"""Parser tests for the collectors, using small upstream-shaped fixtures."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import advisories_feed
import cert_eu_feed
import collector
import cve_feed
import epss_feed
import ghsa_feed
import iocs_feed
import phishing_feed
import ransomware_feed
import wiz_feed
from normalize import NormalisationTally

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def read_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.tally = NormalisationTally("advisories")

    def test_microsoft_feed_is_normalised(self):
        items = advisories_feed.parse_feed(
            "Microsoft", read_fixture("msrc.xml"), 60, self.tally
        )

        self.assertEqual(len(items), 1, "an item with an empty title must be dropped")
        item = items[0]
        self.assertEqual(item["vendor"], "Microsoft")
        self.assertEqual(item["id"], "CVE-2026-1234")
        self.assertIn("Windows Kernel", item["title"])
        self.assertEqual(item["summary"], "An attacker could elevate privileges on an affected system.")
        self.assertEqual(item["published"], "2026-09-22T16:52:36Z")
        self.assertEqual(self.tally.failed, 0)

    def test_ubuntu_feed_is_normalised(self):
        items = advisories_feed.parse_feed("Ubuntu", read_fixture("ubuntu.xml"), 40, self.tally)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "USN-8957-1")
        self.assertEqual(items[0]["vendor"], "Ubuntu")

    def test_cap_is_per_feed(self):
        items = advisories_feed.parse_feed("Microsoft", read_fixture("msrc.xml"), 0, self.tally)
        self.assertEqual(items, [])


class CertEuTests(unittest.TestCase):
    def test_build_item_normalises_the_zone_and_strips_markup(self):
        tally = NormalisationTally("cert_eu")
        item = cert_eu_feed.build_item(
            "2026-013",
            "Critical Vulnerability in F5 BIG-IP APM",
            "https://cert.europa.eu/publications/security-advisories/2026-013/",
            "<p>CERT-EU advises organisations to patch.</p>",
            "Tue, 22 Sep 2026 18:52:36 CEST",
            tally,
        )

        self.assertEqual(item["published"], "2026-09-22T16:52:36Z")
        self.assertEqual(item["summary"], "CERT-EU advises organisations to patch.")
        self.assertEqual(item["link"], "https://cert.europa.eu/publications/security-advisories/2026-013/")

    def test_missing_date_is_null_rather_than_fabricated(self):
        tally = NormalisationTally("cert_eu")
        item = cert_eu_feed.build_item("2026-014", "Title", "", "", "", tally)
        self.assertIsNone(item["published"])
        self.assertEqual(item["link"], "https://cert.europa.eu/publications/security-advisories/2026-014/")


class CveTests(unittest.TestCase):
    def setUp(self):
        self.tally = NormalisationTally("cve")

    def test_primary_cvss_score_wins_over_a_secondary_at_index_zero(self):
        metrics = {
            "cvssMetricV31": [
                {"cvssData": {"type": "Secondary", "baseScore": 5.0, "baseSeverity": "MEDIUM"}},
                {"cvssData": {"type": "Primary", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
            ]
        }
        result = cve_feed.extract_severity(metrics)
        self.assertEqual(result, {"score": 9.8, "severity": "CRITICAL", "cvss_version": "31"})

    def test_cvss_v40_is_read(self):
        metrics = {
            "cvssMetricV40": [
                {"cvssData": {"type": "Primary", "baseScore": 7.5, "baseSeverity": "HIGH"}}
            ]
        }
        self.assertEqual(cve_feed.extract_severity(metrics)["cvss_version"], "40")

    def test_unscored_cve_reports_null_rather_than_zero(self):
        self.assertEqual(
            cve_feed.extract_severity({}),
            {"score": None, "severity": None, "cvss_version": None},
        )

    def test_build_recent_truncates_and_marks_kev_false(self):
        raw = [{
            "cve": {
                "id": "CVE-2026-9999",
                "published": "2026-10-01T12:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "descripción"},
                    {"lang": "en", "value": "x" * 400},
                ],
                "metrics": {},
            }
        }]
        items = cve_feed.build_recent(raw, self.tally)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "CVE-2026-9999")
        self.assertEqual(items[0]["published"], "2026-10-01T12:00:00Z")
        self.assertEqual(len(items[0]["description"]), 300)
        self.assertFalse(items[0]["kev"])
        self.assertIsNone(items[0]["score"])

    def test_build_kev_drops_the_unknown_sentinel_and_old_entries(self):
        today = datetime.now(timezone.utc).date().isoformat()
        raw = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1111",
                    "vendorProject": "Acme",
                    "product": "Widget",
                    "vulnerabilityName": "Acme Widget RCE",
                    "dateAdded": today,
                    "shortDescription": "Exploited in the wild.",
                    "knownRansomwareCampaignUse": "Unknown",
                },
                {
                    "cveID": "CVE-1999-0001",
                    "vendorProject": "Old",
                    "product": "Old",
                    "vulnerabilityName": "Old",
                    "dateAdded": "1999-01-01",
                    "shortDescription": "Old.",
                    "knownRansomwareCampaignUse": "Known",
                },
            ]
        }
        items = cve_feed.build_kev(raw, self.tally)

        self.assertEqual([item["id"] for item in items], ["CVE-2026-1111"])
        self.assertIsNone(items[0]["ransomware_use"])
        self.assertEqual(items[0]["date_added"], today)


class GhsaTests(unittest.TestCase):
    def test_build_items_uses_the_first_ecosystem_and_sorts(self):
        tally = NormalisationTally("ghsa")
        raw = [
            {
                "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                "summary": " Prototype pollution ",
                "published_at": "2026-09-24T16:17:22Z",
                "description": "A long description" + "x" * 400,
                "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                "vulnerabilities": [{"package": {"ecosystem": "npm"}}],
            },
            {
                "ghsa_id": "GHSA-dddd-eeee-ffff",
                "summary": "Newer",
                "published_at": "2026-10-01T00:00:00Z",
                "description": "Newer",
                "html_url": "https://github.com/advisories/GHSA-dddd-eeee-ffff",
                "vulnerabilities": [],
            },
            {"summary": "No id must be skipped"},
        ]
        items = ghsa_feed.build_items(raw, tally)

        self.assertEqual([item["id"] for item in items],
                         ["GHSA-dddd-eeee-ffff", "GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(items[1]["title"], "Prototype pollution")
        self.assertEqual(items[1]["ecosystem"], "npm")
        self.assertLessEqual(len(items[1]["summary"]), 300)


class PhishingTests(unittest.TestCase):
    def test_urls_are_defanged_deduped_and_hosts_extracted(self):
        collected = "2026-10-27T12:00:00Z"
        items = phishing_feed.build_items(read_fixture("openphish.txt"), collected)

        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["url_defanged"], "hxxps://login-secure.example/verify")
        self.assertEqual(items[0]["host"], "login-secure.example")
        self.assertEqual(items[0]["collected_at"], collected)
        self.assertTrue(all(item["url_defanged"].startswith("hxxp") for item in items))

    def test_max_items_is_enforced(self):
        lines = "\n".join(f"https://host{i}.example/x" for i in range(400))
        items = phishing_feed.build_items(lines, "2026-10-27T12:00:00Z")
        self.assertEqual(len(items), phishing_feed.MAX_ITEMS)


class RansomwareTests(unittest.TestCase):
    def test_attacker_controlled_urls_are_kept_only_when_http(self):
        tally = NormalisationTally("ransomware")
        raw = json.loads(read_fixture("ransomware.json"))
        items = ransomware_feed.build_items(raw, tally)

        self.assertEqual(len(items), 3)
        by_victim = {item["victim"]: item for item in items}
        self.assertEqual(by_victim["only-domain.example"]["victim"], "only-domain.example")
        self.assertIsNone(by_victim["Hostile Links Ltd"]["claim_url"])
        self.assertIsNone(by_victim["Hostile Links Ltd"]["link"])
        self.assertEqual(by_victim["Hostile Links Ltd"]["screenshot"], "https://example.com/shot.png")
        self.assertEqual(by_victim["Acme Manufacturing"]["claim_url"], "http://lockbit.onion/claim/1")
        self.assertIsNone(by_victim["Acme Manufacturing"]["screenshot"])
        self.assertNotIn("<", by_victim["Acme Manufacturing"]["description"])
        # Newest published first; the record with an unparseable date sorts last.
        self.assertEqual(items[0]["victim"], "Hostile Links Ltd")
        self.assertIsNone(items[-1]["published"])


class DerivedIocTests(unittest.TestCase):
    def test_iocs_are_derived_from_phishing_and_ransomware(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            phishing = tmp / "phishing.json"
            ransomware = tmp / "ransomware.json"
            output = tmp / "iocs.json"
            phishing.write_text(json.dumps({
                "updated_at": "2026-10-27T12:00:00Z",
                "items": [{
                    "url_defanged": "hxxps://evil.example/login",
                    "collected_at": "2026-10-27T12:00:00Z",
                }],
            }), encoding="utf-8")
            ransomware.write_text(json.dumps({
                "items": [
                    {"domain": "victim.example", "published": "2026-10-27T12:00:00Z"},
                    {"domain": "not_a_domain", "published": "2026-10-27T12:00:00Z"},
                ],
            }), encoding="utf-8")

            with mock.patch.multiple(
                iocs_feed,
                PHISHING_PATH=phishing,
                RANSOMWARE_PATH=ransomware,
                OUTPUT_PATH=output,
            ):
                self.assertEqual(iocs_feed.main(), 0)

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(document["items"]), 2)
            self.assertEqual({item["type"] for item in document["items"]}, {"url", "domain"})
            self.assertEqual(
                {item["value"] for item in document["items"]},
                {"hxxps://evil.example/login", "victim.example"},
            )

    def test_missing_upstreams_fail_instead_of_publishing_an_empty_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            with mock.patch.multiple(
                iocs_feed,
                PHISHING_PATH=tmp / "missing-a.json",
                RANSOMWARE_PATH=tmp / "missing-b.json",
                OUTPUT_PATH=tmp / "iocs.json",
            ):
                self.assertEqual(iocs_feed.main(), 1)
            self.assertFalse((tmp / "iocs.json").exists())


class EpssTests(unittest.TestCase):
    def test_kev_then_score_then_recency_ordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cves.json"
            path.write_text(json.dumps({
                "recent": {"items": [
                    {"id": "CVE-2026-0001", "kev": False, "score": 5.0,
                     "published": "2026-10-03T00:00:00Z"},
                    {"id": "CVE-2026-0002", "kev": True, "score": 1.0,
                     "published": "2026-10-01T00:00:00Z"},
                    {"id": "CVE-2026-0003", "kev": False, "score": 9.0,
                     "published": "2026-10-02T00:00:00Z"},
                    {"id": None},
                ]},
                "actively_exploited": {"items": [{"id": "CVE-2026-0004"}]},
            }), encoding="utf-8")

            with mock.patch.object(epss_feed, "CVES_PATH", path):
                self.assertEqual(
                    epss_feed.candidate_cves(),
                    ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001", "CVE-2026-0004"],
                )

    def test_candidate_list_is_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cves.json"
            raw = {"recent": {"items": [
                {"id": f"CVE-2026-{index:04d}", "score": index}
                for index in range(epss_feed.MAX_CVES + 20)
            ]}}
            path.write_text(json.dumps(raw), encoding="utf-8")

            with mock.patch.object(epss_feed, "CVES_PATH", path):
                self.assertEqual(len(epss_feed.candidate_cves()), epss_feed.MAX_CVES)


class PlatformTests(unittest.TestCase):
    def test_normalize_entries_accepts_every_upstream_shape(self):
        self.assertEqual(collector.normalize_entries([{"name": "a"}]), [{"name": "a"}])
        self.assertEqual(collector.normalize_entries({"programs": [{"name": "a"}]}),
                         [{"name": "a"}])
        self.assertEqual(collector.normalize_entries({"data": [{"name": "a"}]}),
                         [{"name": "a"}])
        with self.assertRaises(ValueError):
            collector.normalize_entries("nope")

    def test_platform_detection_uses_the_hostname(self):
        self.assertEqual(collector.detect_platform("https://hackerone.com/acme"), "HackerOne")
        self.assertEqual(collector.detect_platform("https://www.bugcrowd.com/acme"), "Bugcrowd")
        self.assertEqual(collector.detect_platform("https://acme.example"), collector.UNKNOWN_PLATFORM)
        self.assertEqual(collector.detect_platform(""), collector.UNKNOWN_PLATFORM)

    def test_manual_platforms_are_matched_case_insensitively(self):
        self.assertEqual(collector.canonical_platform("bugcrowd"), ("Bugcrowd", True))
        self.assertEqual(collector.canonical_platform("HackerOne"), ("HackerOne", True))
        self.assertEqual(collector.canonical_platform("Hackerone Enterprise"),
                         ("Hackerone Enterprise", False))
        self.assertEqual(collector.canonical_platform(None), (collector.UNKNOWN_PLATFORM, True))


class WizTests(unittest.TestCase):
    def test_classification_suffix_is_extracted(self):
        self.assertEqual(
            wiz_feed.classify("Coder Module Registry Compromise (Incident)"),
            ("Coder Module Registry Compromise", "incident"),
        )
        self.assertEqual(wiz_feed.classify("Unclassified title"), ("Unclassified title", None))

    def test_a_suffix_outside_the_enum_is_dropped(self):
        title, kind = wiz_feed.classify("Something happened (Opinion)")
        self.assertEqual(title, "Something happened (Opinion)")
        self.assertIsNone(kind)


if __name__ == "__main__":
    unittest.main()
