#!/usr/bin/env python3
"""
Builds a combined vulnerability feed from two official, free, no-key sources:

1. NVD (nvd.nist.gov) — recently published CVEs (last N days).
2. CISA KEV catalog — vulnerabilities confirmed to be actively exploited
   in the wild. This is the higher-signal list: CVSS score alone doesn't
   tell you what's actually being used in attacks right now, KEV does.

Recently published CVEs that also appear in KEV are flagged accordingly,
so the site can highlight "this is new AND it's already being exploited"
as the highest-priority signal.

SCHEMA VERSION 2 (2026-09-27)
-----------------------------
Two breaking corrections landed together, so the version moved:

  * `recent` is now paginated to exhaustion. It used to request
    resultsPerPage=200 and read one page, silently discarding ~87% of the
    window (measured: 1533 available, 200 parsed). `recent.total` reported
    200, which is a *true* number, so nothing looked wrong.
  * All timestamps are ISO-8601 UTC. `recent[].published` is now explicit-UTC
    rather than a naive NVD local string; `actively_exploited[].date_added`
    stays date-only because CISA publishes no time and a bare YYYY-MM-DD is
    unambiguous to a JS Date constructor.

`recent.items_parsed` and `recent.items_available` are now both published so
validate_feeds.py can assert they agree without re-querying NVD.
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from feed_io import DATA_DIR, read_json, write_json
from normalize import NormalisationTally

OUTPUT_PATH = DATA_DIR / "cves.json"
HEADLINE_PATH = DATA_DIR / "cves_headline.json"
STATUS_PATH = DATA_DIR / "status.json"
SCHEMA_VERSION = 2
NVD_MIN_LOOKBACK_DAYS = 3
# A failed run must not leave a permanent hole. The next successful run widens
# its window to cover the gap, capped so a months-long outage cannot turn into a
# 50k-CVE download that trips NVD's rate limit.
NVD_MAX_LOOKBACK_DAYS = 120
KEV_LOOKBACK_DAYS = 90  # recent additions, not the full 1600-entry archive
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
KEV_OFFICIAL_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The homepage renders ~7 items but index.html used to fetch the whole
# window to do it -- 920 KB of JSON for 7 cards. This cap feeds a small
# purpose-built file for the homepage; cves.json keeps the complete
# window for API consumers, which is the whole point of the pagination fix.
HEADLINE_ITEMS = 25

NVD_PAGE_SIZE = 2000          # NVD 2.0 API maximum
NVD_MAX_PAGES = 25            # 50k CVEs in a 3-day window would mean the API is lying
NVD_REQUEST_INTERVAL = 7      # NVD allows 5 requests / 30s unauthenticated; stay under it

CVSS_VERSIONS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def fetch_json(url, *, attempts=4):
    """
    GET with bounded exponential backoff.

    Retry lives here rather than only in the workflow's bash `retry()` so that a
    transient 429 or 503 does not discard a whole scheduled run.
    """
    last_error = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, headers={"User-Agent": "threats-top-collector"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            delay = 5 * (2 ** (attempt - 1))
            print(f"  fetch failed ({exc}); retry {attempt}/{attempts - 1} in {delay}s")
            time.sleep(delay)
    raise RuntimeError(f"GET failed after {attempts} attempts: {url}") from last_error


def lookback_days():
    """
    Widen the NVD window to cover time since the last successful run.

    Without this, three days of failed runs meant the CVEs published during the
    outage were never collected: the fixed 3-day window had moved past them.
    """
    status = read_json(STATUS_PATH, {}) or {}
    entries = status.get("sources") or []
    last_success = next(
        (entry.get("last_success") for entry in entries
         if isinstance(entry, dict) and entry.get("id") == "cve"),
        None,
    )
    if not last_success:
        return NVD_MIN_LOOKBACK_DAYS
    try:
        last = datetime.strptime(last_success, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return NVD_MIN_LOOKBACK_DAYS
    gap = (datetime.now(timezone.utc) - last).days + 1
    return max(NVD_MIN_LOOKBACK_DAYS, min(NVD_MAX_LOOKBACK_DAYS, gap))


def fetch_nvd_recent(lookback):
    """
    Page through the whole lookback window.

    Returns (vulnerabilities, total_results). `total_results` is what NVD says
    exists, so the caller can publish both numbers and let the validator catch
    any future truncation instead of it passing unnoticed.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback)
    base_params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    collected = []
    total = None
    start_index = 0

    for page in range(1, NVD_MAX_PAGES + 1):
        params = {**base_params, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": start_index}
        url = f"{NVD_BASE_URL}?" + urllib.parse.urlencode(params)
        payload = fetch_json(url)

        total = payload.get("totalResults", 0)
        batch = payload.get("vulnerabilities") or []
        collected.extend(batch)
        start_index += len(batch)

        print(f"  NVD page {page}: {len(batch)} items (running total {len(collected)}/{total})")

        if not batch or len(collected) >= total:
            break
        if page == NVD_MAX_PAGES:
            raise RuntimeError(
                f"NVD returned more than {NVD_MAX_PAGES * NVD_PAGE_SIZE} CVEs "
                f"(have {len(collected)} of {total}) -- refusing to loop unbounded"
            )
        time.sleep(NVD_REQUEST_INTERVAL)

    return collected, (total if total is not None else 0)


def extract_severity(metrics):
    """
    Pull the authoritative CVSS score out of NVD's metrics block.

    Two corrections over the original:

    * CVSS v4.0 (cvssMetricV40) is now read. It was missing entirely, so ~12
      scored CVEs per run were published with a null severity.
    * The entry flagged `cvssData.type == "Primary"` is preferred over `[0]`.
      NVD publishes CNA-supplied secondary scores in the same list, and index 0
      is not guaranteed to be the authoritative one.

    Returns score/severity plus the CVSS version used, so a null score can mean
    "NVD has not scored this yet" unambiguously instead of being overloaded with
    "we failed to read a version we didn't handle".
    """
    for key in CVSS_VERSIONS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next(
            (e for e in entries if (e.get("cvssData") or {}).get("type") == "Primary"),
            entries[0],
        )
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        return {
            "score": score,
            "severity": data.get("baseSeverity") or primary.get("baseSeverity"),
            "cvss_version": key.replace("cvssMetricV", ""),
        }
    return {"score": None, "severity": None, "cvss_version": None}


def fetch_kev():
    # CISA's own host is not reachable from some build environments; the
    # cisagov/kev-data mirror is the same catalog published by the same org.
    try:
        return fetch_json(KEV_MIRROR_URL)
    except RuntimeError as mirror_error:
        print(f"  KEV mirror failed ({mirror_error}); trying cisa.gov", file=sys.stderr)
        return fetch_json(KEV_OFFICIAL_URL)


def build_recent(nvd_raw, tally):
    recent = []
    for entry in nvd_raw:
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        severity = extract_severity(cve.get("metrics", {}))
        recent.append({
            "id": cve_id,
            "published": tally.iso(cve.get("published"), field="recent[].published"),
            "description": description[:300],
            "severity": severity["severity"],
            "score": severity["score"],
            "cvss_version": severity["cvss_version"],
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "kev": False,  # filled in below
        })
    return recent


def build_kev(kev_raw, tally):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEV_LOOKBACK_DAYS)).date()
    kev_all = kev_raw.get("vulnerabilities", [])
    kev_recent = []
    for v in kev_all:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < cutoff:
            continue
        kev_recent.append({
            "id": cve_id,
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "name": v.get("vulnerabilityName"),
            "date_added": tally.date(v.get("dateAdded"), field="kev[].date_added"),
            # CISA publishes the literal string "Unknown". Keep it as null so a
            # consumer can test for absence instead of matching on a sentinel.
            "ransomware_use": (
                v["knownRansomwareCampaignUse"]
                if v.get("knownRansomwareCampaignUse") not in (None, "", "Unknown")
                else None
            ),
            "description": (v.get("shortDescription") or "")[:300],
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return kev_recent


def main():
    tally = NormalisationTally("cve")
    window = lookback_days()
    nvd_raw, nvd_total = fetch_nvd_recent(window)
    recent = build_recent(nvd_raw, tally)
    print(f"  NVD: parsed {len(recent)} of {nvd_total} available over {window} day(s)")

    kev_raw = fetch_kev()
    kev_recent = build_kev(kev_raw, tally)
    print(f"  KEV: {len(kev_recent)} entries in the last {KEV_LOOKBACK_DAYS} days "
          f"(catalog has {len(kev_raw.get('vulnerabilities', []))})")

    kev_ids = {v["id"] for v in kev_recent} | {
        v.get("cveID") for v in kev_raw.get("vulnerabilities", []) if v.get("cveID")
    }
    for item in recent:
        if item["id"] in kev_ids:
            item["kev"] = True

    tally.raise_if_exceeded()

    recent.sort(key=lambda x: x["published"] or "", reverse=True)
    kev_recent.sort(key=lambda x: x["date_added"] or "", reverse=True)

    output = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "NVD + CISA KEV",
        "source_url": [NVD_BASE_URL, KEV_MIRROR_URL],
        "recent": {
            "lookback_days": window,
            "total": len(recent),
            "items_available": nvd_total,
            "normalisation_failures": tally.failures,
            "items_parsed": len(recent),
            "items": recent,
        },
        "actively_exploited": {
            "lookback_days": KEV_LOOKBACK_DAYS,
            "catalog_total": len(kev_raw.get("vulnerabilities", [])),
            "total": len(kev_recent),
            "items": kev_recent,
        },
    }
    write_json(OUTPUT_PATH, output)

    # Small, purpose-built file for the homepage. Same envelope as cves.json so
    # the existing renderer works unchanged, but bounded so first paint does not
    # download the entire NVD window. The totals ride along so the homepage
    # counter can show the full window without fetching 1.8 MB.
    headline = {
        "schema_version": SCHEMA_VERSION,
        "updated_at": output["updated_at"],
        "source": output["source"],
        "source_url": output["source_url"],
        "note": "Bounded slice of cves.json for the homepage. Use /data/cves.json for the full window.",
        "normalisation_failures": output["recent"]["normalisation_failures"],
        "recent_total": output["recent"]["total"],
        "kev_total": output["actively_exploited"]["total"],
        "kev_catalog_total": output["actively_exploited"]["catalog_total"],
        "total": min(HEADLINE_ITEMS, len(recent)),
        "items": recent[:HEADLINE_ITEMS],
    }
    write_json(HEADLINE_PATH, headline)

    print(f"Wrote {len(recent)} recent CVEs (of {nvd_total} available), {len(kev_recent)} KEV entries.")

    if nvd_total and len(recent) < nvd_total:
        print(
            f"::error::NVD truncation -- parsed {len(recent)} of {nvd_total}. "
            f"data/cves.json is incomplete.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
