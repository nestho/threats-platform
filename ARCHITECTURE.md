# threats-platform — Architecture & Operations

_Last audited: 2026-09-27, directly against the live `main` branch of
[nestho/threats-platform](https://github.com/nestho/threats-platform)._

This document is the source of truth for how the system is built and why.
Every time a script, page, or workflow changes, this file gets updated in
the same commit — it should never drift from what's actually deployed.

---

## 1. What this is

An open threat-intelligence data platform. It collects data from several
free, official, no-API-key sources, publishes it as static JSON + a set of
static HTML pages on GitHub Pages, and lets the operator add hand-picked
data through a small admin panel backed by a Cloudflare Worker.

No paid infrastructure. No database server. No backend process running
anywhere — everything is either a GitHub Action (scheduled batch job) or a
static file served by GitHub Pages.

---

## 2. High-level architecture

```mermaid
flowchart TB
    subgraph Sources["External free data sources"]
        PD[ProjectDiscovery<br/>public-bugbounty-programs]
        NVD[NVD API]
        KEV[CISA KEV catalog]
        GHSA_SRC[GitHub Security<br/>Advisories]
        EDB_SRC[Exploit-DB RSS]
        CERT_SRC[CERT-EU RSS]
        UH_SRC[URLhaus CSV<br/>abuse.ch]
        WIZ_SRC[Wiz Cloud Threat<br/>Landscape RSS]
    end

    subgraph Actions["GitHub Actions (scheduled, hourly cron)"]
        WF[update-data.yml<br/>picks which feed(s) to run<br/>based on UTC hour]
        C1[collector.py]
        C2[cve_feed.py]
        C3[ghsa_feed.py]
        C4[exploitdb_feed.py]
        C5[cert_eu_feed.py]
        C6[urlhaus_feed.py]
        C7[wiz_feed.py]
        GATE[validate_feeds.py<br/>THE GATE]
    end

    subgraph Repo["Repo: data/ (committed JSON)"]
        D1[domains.json]
        D2[cves.json]
        D3[ghsa.json]
        D4[exploitdb.json]
        D5[cert_eu.json]
        D6[urlhaus.json]
        D7[manual.json<br/>hand-edited, never<br/>overwritten by scripts]
        D8[wiz.json]
        D9[cves_headline.json<br/>bounded slice of cves.json]
    end

    subgraph Pages["GitHub Pages (threats.top)"]
        P1[index.html]
        P2[programs.html]
        P3[cves.html]
        P4[admin/index.html]
    end

    subgraph Admin["Manual data entry path"]
        Worker["Cloudflare Worker<br/>worker/admin.js<br/>IN version control"]
        GH_API[GitHub Contents API]
    end

    PD --> C1
    NVD --> C2
    KEV --> C2
    GHSA_SRC --> C3
    EDB_SRC --> C4
    CERT_SRC --> C5
    UH_SRC --> C6
    WIZ_SRC --> C7

    WF --> C1 & C2 & C3 & C4 & C5 & C6 & C7
    C1 --> D1
    C2 --> D2
    C3 --> D3
    C4 --> D4
    C5 --> D5
    C6 --> D6
    C7 --> D8
    C2 --> D9
    D7 -.merged into.-> D1

    C1 & C2 & C3 & C4 & C5 & C6 & C7 --> GATE
    GATE -->|"pass"| Repo
    GATE -.->|"fail: nothing committed"| WF

    D1 & D2 & D3 & D4 & D5 & D6 & D8 & D9 --> Pages

    P4 -- password + payload --> Worker
    Worker -- reads/writes --> D7
    Worker -- commits via --> GH_API
    GH_API -- pushes to --> Repo
```

---

## 3. Repository layout

```
threats-platform/
├── .github/workflows/
│   └── update-data.yml       # hourly cron (staggered feeds) + weekly cron (wiz).
│                             # validate -> commit, in that order
├── admin/
│   └── index.html            # manual data-entry UI (same-origin /admin-api)
├── assets/
│   ├── app.css                # design tokens, header, controls, tabs, badges
│   ├── app.js                 # esc, timeAgo, timeKey, copy, fetch, initTabs
│   └── app.test.mjs           # node --test; esc() is the XSS boundary
├── data/                      # generated JSON, committed to the repo
│   ├── domains.json           # bug bounty programs + domains (collector.py)
│   ├── cves.json              # NVD recent (full window) + CISA KEV (cve_feed.py)
│   ├── cves_headline.json     # bounded 25-item slice of cves.json, for the homepage
│   ├── ghsa.json              # GitHub Security Advisories (ghsa_feed.py)
│   ├── exploitdb.json         # Exploit-DB entries (exploitdb_feed.py)
│   ├── cert_eu.json           # CERT-EU advisories (cert_eu_feed.py)
│   ├── urlhaus.json           # malware URLs, defanged (urlhaus_feed.py)
│   ├── wiz.json               # cloud incidents/campaigns (wiz_feed.py, weekly)
│   └── manual.json            # HAND-EDITED ONLY — never overwritten by scripts
├── scripts/
│   ├── normalize.py           # shared timestamp normalisation (+ self-check)
│   ├── validate_feeds.py      # THE GATE. runs before every commit
│   ├── collector.py
│   ├── cve_feed.py
│   ├── ghsa_feed.py
│   ├── exploitdb_feed.py
│   ├── cert_eu_feed.py
│   ├── urlhaus_feed.py
│   └── wiz_feed.py
├── worker/
│   ├── admin.js               # the only write path into published data
│   ├── admin.test.mjs         # node --test; 20 tests over the auth boundary
│   └── wrangler.toml          # deploy config; secrets are NOT in this file
├── index.html                 # homepage: stats, recent activity, API catalog
├── programs.html              # program browser (cards/table/grouped)
├── cves.html                  # vulnerability browser (5 tabs)
├── threats.html               # cloud threat landscape (Wiz)
├── docs/
│   ├── DEEP-ANALYSIS.md       # audit: what is wrong and why
│   └── CONTRACT.md            # generated API contract (from validate_feeds.py)
├── CNAME                      # threats.top
├── requirements.txt           # empty on purpose — stdlib only, no dependencies
├── CONSTRAINTS.md             # the quality bar
└── README.md                  # placeholder, not yet written
```

Frontend design system: dark neutral background (`#09090b`), Inter for UI
text, JetBrains Mono for code/IDs, orange accent (`#f97316`). `index.html`,
`programs.html`, and `cves.html` all share this system. **`admin/index.html`
is still on an older, different color scheme** (teal/orange on near-black) —
cosmetic inconsistency, not a functional bug (see §7).

---

## 4. Data sources

| Source | Script | Output | Auth | Cadence | Notes |
|---|---|---|---|---|---|
| ProjectDiscovery public-bugbounty-programs | `collector.py` | `domains.json` | none | every 6h | Also merges `manual.json` by name; detects platform (HackerOne/Bugcrowd/etc) from program URL |
| NVD API 2.0 | `cve_feed.py` | `cves.json` → `recent` | none | every 2h | **Known bug: capped at 200 results, no pagination — see §7** |
| CISA KEV catalog | `cve_feed.py` | `cves.json` → `actively_exploited` | none | every 2h | Also cross-flags `recent` items with `kev: true` |
| GitHub Security Advisories | `ghsa_feed.py` | `ghsa.json` | none | every 3h | Atom feed, official GitHub endpoint |
| Exploit-DB | `exploitdb_feed.py` | `exploitdb.json` | none | every 4h | Official RSS (`exploit-db.com/rss.xml`) |
| CERT-EU | `cert_eu_feed.py` | `cert_eu.json` | none | every 4h | RSS with a regex fallback parser in case the feed isn't strict XML |
| URLhaus (abuse.ch) | `urlhaus_feed.py` | `urlhaus.json` | none | every hour | **URLs are defanged (`hxxp`, `[.]`) before being written — deliberate, see §6** |
| Wiz Cloud Threat Landscape | `wiz_feed.py` | `wiz.json` | none | **weekly** | Cloud incidents, campaigns, supply-chain compromises. **Analysis feed, not an alert feed** — 0 items in 7d, 3 in 30d measured over its 509-item feed, so it has its own cron and is labelled as analysis in the UI. Added 2026-09-27; it closed the platform's largest content gap (every other feed is vulnerability/exploit shaped) |

**Dropped source:** PacketStorm Security — killed its free RSS on
2025-10-23, now paid-API only. Not pursued further.

**Considered and deliberately skipped:** MITRE ATT&CK (no clean CVE→ATT&CK
mapping feed exists; would require guessing) and `cve.org`/`cvelistV5`
(redundant with NVD, which already ingests from it; the only gain is a
few hours' head start before NVD scores a CVE, not worth the added
complexity of parsing GitHub Release zip deltas).

---

## 5. Scheduling logic

Single workflow (`update-data.yml`), single hourly cron
(`0 * * * *`), which decides **which** feeds to run based on the current
UTC hour — avoids juggling multiple overlapping cron expressions:

| Feed | Runs |
|---|---|
| `urlhaus` | every hour |
| `cve` | even hours (every 2h) |
| `ghsa` | hours divisible by 3 |
| `exploitdb`, `cert_eu` | hours divisible by 4 |
| `collector` | hours divisible by 6 |

`wiz` is **not** in the hourly rotation. It has its own weekly cron
(`17 6 * * 1`) because its publication rate is roughly monthly, and running it
alongside hourly feeds would imply a freshness it does not have.

`workflow_dispatch` allows manually triggering a single feed or `all`.

The commit step has retry logic on both the feed script itself (up to 4
attempts with exponential backoff) and on `git push` (rebases on conflict
and retries), since multiple scheduled runs could in theory race — though
`concurrency: cancel-in-progress: false` also serializes runs so this is
mostly defense-in-depth.

### The validation gate (added 2026-09-27)

Step order is **fetch → validate → commit**. `scripts/validate_feeds.py` runs
against `HEAD`, which at that point is still the previously committed data, so it
can compare this run's output to what was live before it. Nothing invalid reaches
`main`.

This exists because the old contract — "exit 0 means the file is good" — was
false. A collector served an HTML error page wrote `{"total": 0, "items": []}`,
exited 0, and the workflow committed it and reported success. The gate now
catches that case, a >50% item-count drop, NVD truncation, schema drift, an
unbumped `schema_version`, non-ISO timestamps, a non-canonical `platform`, and
defanging regressions. See `docs/DEEP-ANALYSIS.md` §2.1.

---

## 6. Manual data entry (admin panel)

Path: `threats.top/admin/` → Cloudflare Worker (`threats-admin`) → GitHub
Contents API → `data/manual.json` → picked up by `collector.py` on its next
run and merged into `domains.json`.

- The Worker holds `GITHUB_TOKEN` (fine-grained PAT, Contents:
  read/write, scoped to this one repo only) and `ADMIN_PASSWORD` as
  Cloudflare **secrets** — never exposed client-side.
- `admin/index.html` never stores the password; it's typed in each visit
  and held only in a JS variable in memory. The "Unlock" step calls the
  Worker's `/list` endpoint to genuinely verify the password (not just a
  cosmetic UI toggle).
- **The Worker's source is now in this repo** as `worker/admin.js`, with
  `worker/wrangler.toml` for deployment and `worker/admin.test.mjs` (20 tests over
  the auth boundary). It is served from this zone at `/admin-api/*` rather than a
  `*.workers.dev` subdomain, so the admin page's call is same-origin and the URL
  is no longer a discoverable third-party endpoint.
  **It is a clean-room reconstruction, not a copy** — diff it against the
  dashboard version before deploying. Items marked `VERIFY` in the source are
  assumptions.
- **Secrets are `ADMIN_PASSWORD_HASH` (a SHA-256 digest, not the password) and
  `GITHUB_TOKEN`**, set via `wrangler secret put`. The Worker fails closed if the
  hash is unset.

Security properties already in place:
- CORS should be restricted to `https://threats.top` (verify this is
  actually set — it was flagged during development, confirm in the
  Cloudflare dashboard since the Worker isn't in the repo to check here).
- Malware URLs from URLhaus are defanged before ever reaching a page.
- All external/untrusted string data (program names, platforms, domain
  names, CVE descriptions) is passed through an `esc()` helper before
  being inserted into the DOM in `index.html`, `programs.html`, and
  `cves.html` — confirmed present and applied consistently as of this
  audit.

---

## 7. Known issues / tech debt

**Closed on `p0-data-integrity` (2026-09-27, unmerged).** Full detail and
reproductions in [`docs/DEEP-ANALYSIS.md`](docs/DEEP-ANALYSIS.md).

1. ~~NVD CVE feed silently truncated~~ — **fixed.** Now paginates on
   `totalResults`. Measured 200 → 1533 CVEs; `items_available`/`items_parsed` are
   both published so truncation is detectable.
2. ~~Cloudflare Worker not version-controlled~~ — **fixed.** See §6.
3. ~~`admin/index.html` on the old colour scheme~~ — **fixed.** All pages now use
   `assets/app.css`.
4. ~~No schema validation~~ — **fixed.** `scripts/validate_feeds.py` gates every
   commit. (The underlying RSS fragility it mitigates is permanent; see below.)
5. ~~CERT-EU timestamps unparseable in the browser~~ — **fixed.** All timestamps
   are ISO-8601 UTC via `scripts/normalize.py`.
6. ~~CVSS v4.0 scores discarded~~ — **fixed.** +158 real scores per run.
7. ~~Platform enum split (`Bugcrowd` / `BugCrowd`)~~ — **fixed.** Manual values
   are canonicalised on read and validated on write.
8. ~~Keyboard-inaccessible program cards~~ — **fixed.** Cards are real
   `<button>`s with `aria-expanded`; tabs have `role="tablist"`; result counts
   are announced.
9. **RSS-scraped sources remain fragile by nature.** Exploit-DB, CERT-EU, URLhaus
   and Wiz are all website feeds, not APIs. A site-side change breaks them
   silently. The empty-feed gate converts that from *silent* to *loud*, which is
   mitigation, not a fix.

**Still open:**

10. **`README.md` is still the placeholder.** Now more costly than it was: the
    project advertises a public API and ships
    [`docs/CONTRACT.md`](docs/CONTRACT.md) instead. The README should at least
    point at it.
11. **No JSON Schema files.** `validate_feeds.py` enforces the contract in code
    and generates the docs from the same table, so they cannot drift — but a
    consumer cannot machine-validate against it without running Python.
12. **Frontend has no end-to-end or accessibility test.** `assets/app.test.mjs`
    covers `esc()` and the time helpers as units. Nothing verifies that a rendered
    page is actually navigable, and nothing catches a future renderer passing
    unescaped data to `innerHTML`. This is the highest-value remaining gap,
    because `esc()` is the only XSS control the site has.
13. **The Worker's in-memory rate limiter is best-effort.** It resets when a
    Worker isolate is recycled. Cloudflare Rate Limiting Rules or a Durable
    Object would be a real control.
14. **HoneyDB is not integrated.** The API works and would add live attacker
    infrastructure, which nothing else here covers — but its terms require a
    paid licence for "distributing as a value-added service", and this platform
    publishes to a public API. Needs a licensing decision first.

## 8. Open questions for the next session

- [ ] **Is the deployed Worker's CORS actually restricted, and does it
      rate-limit?** `worker/admin.js` does both, but the live dashboard version
      is what has been serving traffic. Diff it before deploying.
- [ ] **Should `admin/` be publicly deployed at all?** It now shares an origin
      with the site. A Cloudflare Access policy in front of `/admin/*` would
      remove the shared-password question entirely.
- [ ] **Do we want a stability guarantee for the public JSON?** `schema_version`
      and `docs/CONTRACT.md` exist, but there is no `/v1/` and no deprecation
      window. If third parties depend on this, a versioned contract is worth it.
      If it is a hobby feed, documenting today's shape is enough. This gates
      whether JSON Schema files are worth adding.
- [ ] **What to do with the 28 programs that publish no domains?** They render as
      empty cards on the site's core page. `domains.json` now reports the count as
      `programs_without_domains`, but nothing acts on it. Filtering them is a
      judgement call about whether undisclosed scope belongs on a scope page.
- [ ] **HoneyDB licensing.** See §7.14. Do not integrate before this is resolved.
- [ ] **Should URLhaus get a UI?** It is deliberately API-only — it is live
      malware distribution URLs and there is no browsing experience that makes
      that a good idea. Worth confirming that is the intent rather than an
      oversight.

## 9. Documentation policy going forward

Every time we add or materially change a script, data file, page, or
workflow step, this file gets a corresponding update **in the same
commit** — new row in the source table, new architecture note, or an
entry in §7 if it's a known limitation rather than a finished feature.
No feature is "done" until this doc reflects it.
