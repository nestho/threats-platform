# Live Attack Map — Design

**Date:** 2026-10-29
**Status:** Approved in chat ("go ahead, build the interactive threat map")
**Supersedes:** the 72-hour claims+hosts map as the primary map experience; `map.html` is upgraded in place, not duplicated.

## Problem

The homepage numbers look static and undersell the platform:

- `ransomware claims = 100` is a hard collector cap (the API returns only the 100 newest), so the count never changes even though items rotate.
- `exploited CVEs = 106` is really *CISA KEV additions in the last 90 days*; the catalog is 1,762. The label is wrong.
- Counters never show freshness ("updated N min ago"), and collection only lands every 1–8 hours because the 15-minute scheduler is blocked on a GitHub token rotation.
- The existing map shows only ransomware claims and phishing hosts; the user wants a live, interactive attack map in the visual language of the vendor maps (Radware, Check Point, Fortinet, Kaspersky) — globe, pulses, live ticker, filters, replay.

## What we cannot do, and why

Vendor maps animate source→destination arcs from proprietary sensor grids. No licence-clean free feed records both an attacker's origin and destination, so this map never fakes destination arcs. Every layer is labelled with exactly what it is.

Keyed feeds were evaluated and excluded:

- **Cloudflare Radar** — CC BY-NC 4.0 (non-commercial only); this site is for-profit.
- **abuse.ch ThreatFox / URLhaus / Feodo** — free under fair use, but the FAQ states commercial or for-profit use may require a paid subscription; threats.top is for-profit. Excluded unless the owner buys a subscription.

## Sources (all licence-clean, keyless)

| Feed | Source | Cadence | Licence |
|---|---|---|---|
| `data/ransomware.json` (existing) | ransomware.live `recentvictims` | 1h | free API, attribution on site |
| `data/incidents.json` (new) | ransomware.live `recentcyberattacks` | 3h | free API, attribution on site |
| `data/isc.json` (new) | SANS ISC / DShield API: `topips`, `topports` | 1h | commercial use with attribution allowed, no resale ([feeds doc](http://www.dshield.org/feeds_doc.html), [diary 27824](https://isc.sans.edu/diary/27824)) |
| `data/attackers.json` (new) | blocklist.de `getlast.php` (attacks reported in the last hour) | 1h | public fail2ban-report API, attribution on site |
| `data/phishing.json` (existing) | OpenPhish | 1h | free snapshot |
| `data/live.json` (existing, extended) | derived from all of the above | 1h | derived; carries DB-IP Lite attribution |

## New feeds

### `data/incidents.json`

 ransomware.live `recentcyberattacks`: public claims of cyber incidents (breaches, infostealer exposures, hacktivist claims) with an `added` date, victim country, and a public link. Keep the 200 most recent by `added`; every item has a real timestamp. Fields per item: `id`, `victim`, `domain`, `country`, `added`, `date`, `title`, `summary` (truncated, markup stripped), `link`, `claim_gang` (bool), `infostealer_compromised_users` (int or null). Envelope note: a claim is not confirmation of a successful attack.

### `data/isc.json`

SANS ISC/DShield, one call per sub-source, merged:

- `topips/records/25`: `{ip, reports_24h, targets, country}` — country filled by the existing DB-IP Lite lookup at collection time. IPs are attacker IPs observed by the DShield volunteer sensor grid in roughly the last 24h.
- `topports/records/10`: `{port, records_24h, targets, sources}` — which ports the grid saw scanned most.

Envelope note states the window is the ISC's own aggregation (not an attack timeline) and requires attribution.

### `data/attackers.json`

blocklist.de `getlast.php?time=3600`: attacker IPs whose fail2ban reports arrived in the last hour. Items: `{ip, seen (collection ISO time), country}`. Envelope note: community fail2ban reports, no per-attack timestamp, plotted at the attacker's IP geolocation.

## live.json extension

New event kinds alongside `claim` and `host`:

| kind | from | marker |
|---|---|---|
| `claim` (existing) | ransomware victim claim, 72h | pulse in victim country, tooltip victim+group+country |
| `incident` (new) | incidents.json, 72h by `added` | pulse, tooltip title+country |
| `host` (existing) | phishing host, 72h | pulse, tooltip host |
| `source` (new) | isc.json top attacker IPs | sized by `reports_24h`, tooltip IP+reports+country |
| `attacker` (new) | attackers.json, 72h | pulse, tooltip IP+time |

Window stays 72h. `coverage` counts everything unmappable. The `note` and page copy state honestly that `source`/`attacker` are observed attacking IPs and `host` is a phishing host location — none of them is a "live attack in progress".

## Map page (`map.html` upgrade)

Radware-style, same dark design system, no external deps:

- Dark world map (existing offline asset) with animated country pulses; pulse size/intensity scales with event volume and report counts.
- **Live ticker**: newest 15 events, human readable ("14:49 · payload claims Hauhinco, DE"), scrollable.
- **Layer filter chips**: Claims, Incidents, Phishing hosts, ISC sources, Attacker IPs — toggle independently; country deep-link keeps working with layers applied.
- **Replay scrubber**: 72h window, drag to scrub; "LIVE" mode auto-advances.
- **Counters**: events in window by kind, split into "last 24h" vs total, plus "updated N min ago" and a link to `/data/live.json`.
- Auto-refresh every 60s from `data/live.json`; keeps design tokens and WCAG contrast.

## Homepage counter fixes

- `stat-ransomware`: show claims in the last 24h (computed client-side) with subtext "newest <ago>"; keep card link.
- `stat-kev`: catalog total (1,762) labelled "known exploited CVEs", subtext "added in 90d: N".
- Every counter row gets "updated N min ago" from `status.json`/`data` timestamps.
- CVEs-in-window counter unchanged (it is what it says).

## Freshness

- Scheduler: after the owner sets the scoped `Actions: write` GitHub token (repo-only), deploy the existing Cloudflare cron that dispatches `workflow_dispatch` every 15 minutes. Separate workstream; not blocked by this spec.
- Cadence table gains `incidents` (3h), `isc` (1h), `attackers` (1h). `run_collectors.py --feed auto` picks them up.

## Gates and docs

- `scripts/validate_feeds.py` registers the three new feeds (schema, provenance, non-empty, no halving).
- `scripts/status.py` registers the three new feeds in the health panel.
- Python tests + fixtures for every collector and for the new live event kinds; Node tests for map ticker/filters/replay helpers.
- `docs/CONTRACT.md`, `README.md`, `ARCHITECTURE.md`, `ACCESSIBILITY.md`, and page attribution updated.
- Data lands via the existing automation PR flow (new feeds collect on the first scheduled run; no manual data commit).
- Browser QA (Playwright) at 1440/390 before shipping; then PR through protected main.
