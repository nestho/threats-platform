# threats-platform — Architecture & Operations

_Last reviewed: 2026-10-29 against `main`, the live `threats.top` deployment, and the Pro subscription API._

This document describes what is deployed and why. When a script, page, feed, workflow, or API route changes materially, this file changes in the same pull request.

---

## 1. What this is

A static threat-intelligence publication plus one small transactional API. Free, official, no-key sources are collected by scheduled GitHub Actions, normalised into committed JSON, validated before publication, and served by GitHub Pages at `threats.top`.

The public site has no database server, no long-running backend, and no runtime dependency. The only network-facing service beyond GitHub Pages is the Cloudflare Worker `threats-platform-api` on `api.threats.top`. It sells and administers Pro: orders, subscriptions, licences, admin sessions, and the STIX export. It stores operational data in D1, never writes to git, and never serves or alters the public feeds. A second Worker, `threats-scheduler`, only dispatches collection.

Three properties are non-negotiable:

1. **No demo data.** Every published number comes from a live upstream. An empty or malformed feed is a failure, not a reason to render a placeholder.
2. **No direct path to `main`.** Automated and manual changes both arrive as pull requests that must pass the required checks.
3. **Subscription data never enters git.** Orders, emails, phone numbers, and licence hashes live in D1; the repository contains code and public feeds only.

---

## 2. High-level architecture

```mermaid
flowchart TB
    subgraph Sources["Free upstreams (no API key)"]
        NVD[NVD 2.0]
        KEV[CISA KEV]
        GHSA[GitHub Security Advisories]
        EDB[Exploit-DB RSS]
        CERT[CERT-EU RSS]
        WIZ[Wiz Cloud Threat Landscape]
        PD[ProjectDiscovery programs]
        RL[ransomware.live]
        OP[OpenPhish]
        VEND[MSRC + Ubuntu RSS]
        EPSS[FIRST EPSS]
    end

    subgraph Collect["scripts/run_collectors.py (hourly trigger, cadence-driven)"]
        CVE[cve_feed.py]
        GHSAF[ghsa_feed.py]
        EDBF[exploitdb_feed.py]
        CERTF[cert_eu_feed.py]
        WIZF[wiz_feed.py]
        DOM[collector.py]
        RWF[ransomware_feed.py]
        PHF[phishing_feed.py]
        ADV[advisories_feed.py]
        EPSSF[epss_feed.py]
        IOC[iocs_feed.py]
        STATUS[status.py]
    end

    subgraph Validate["Gate"]
        VALIDATE[scripts/validate_feeds.py]
        TESTS[validate.yml: Feed data / Unit tests / Python tests]
    end

    subgraph Publish["Delivery"]
        PR[automation/data-* pull request]
        RULE[ruleset protect-main<br/>no bypass, squash only]
        PAGES[GitHub Pages<br/>threats.top]
    end

    subgraph Pro["Pro (separate, transactional)"]
        API[threats-platform-api<br/>api.threats.top]
        D1[(D1 threats-platform)]
        API --> D1
    end

    DATA[(data/*.json<br/>committed)]

    NVD & KEV --> CVE
    GHSA --> GHSAF
    EDB --> EDBF
    CERT --> CERTF
    WIZ --> WIZF
    PD --> DOM
    RL --> RWF
    OP --> PHF
    VEND --> ADV
    EPSS --> EPSSF
    PHF & RWF --> IOC
    CVE & GHSAF & EDBF & CERTF & WIZF & DOM & RWF & PHF & ADV & EPSSF & IOC --> STATUS

    CVE & GHSAF & EDBF & CERTF & WIZF & DOM & RWF & PHF & ADV & EPSSF & IOC --> DATA
    DATA --> VALIDATE
    VALIDATE --> PR
    PR --> TESTS
    TESTS --> RULE
    RULE --> DATA
    DATA --> PAGES
    PAGES -. checkout, Pro console, admin .-> API
    PAGES -. STIX reads cves.json and iocs.json .-> API
```

The loop at the top is the public pipeline: a collector never writes to production. It writes a candidate file, the validator inspects it against the previous committed version, and only a pull request that passes all three checks can update `main`, from which Pages deploys.

The Pro path is deliberately separate. The Worker owns orders, subscriptions, licences, and admin sessions in D1; it reads the published feeds over HTTPS when a licensed buyer asks for STIX. It has no write path to git and no path into the collection pipeline.

---

## 3. Repository layout

```
.github/
  workflows/
    update-data.yml       hourly collection → validate → automation PR
    validate.yml          pull-request gate: Feed data, Unit tests, Python tests
  dependabot.yml          SHA-pinned action updates
assets/
  app.css                 shared design system
  app.js                  esc(), time helpers, tabs, fetch helpers
  app.test.mjs            XSS and time-helper tests
  live-map.js             pure model helpers for the live map
  live-map.test.mjs       window, replay, aggregation and ingest-state tests
  checkout.js             subscribe page helpers and wiring
  admin.js                owner console helpers and wiring
  pro.js                  licence activation and STIX download
data/                     committed JSON; this is the database
  cves.json               NVD window + KEV
  cves_headline.json      bounded homepage slice
  ghsa.json               GitHub advisories
  exploitdb.json          Exploit-DB
  cert_eu.json            CERT-EU
  wiz.json                Cloud incidents and campaigns
  domains.json            bug bounty programs
  manual.json             hand-edited scope, merged into domains.json
  ransomware.json         leak-site claims
  phishing.json           defanged OpenPhish URLs
  advisories.json         Microsoft and Ubuntu notices
  epss.json               EPSS scores for the CVE window
  iocs.json               derived phishing + ransomware indicators
  live.json               geo-placed claims and phishing hosts for the live map
  status.json             per-source freshness and health
scripts/
  run_collectors.py       cadence selection, subprocess isolation, status
  status.py               source table, freshness rules, status document
  feed_io.py              atomic writes, provenance envelope, escaping helpers
  normalize.py            timestamp normalisation and self-check
  validate_feeds.py       the gate and the contract source of truth
  dev.py                  local test/validate/sync/serve CLI
  setup-ruleset.sh        idempotent repository protection
  admin-credentials.mjs   owner-run password hash + TOTP enrolment URI generator
  *_feed.py               one collector per source
  tests/                  Python unit tests and fixtures
admin/
  index.html              owner console: login, orders, subscriptions, audit, settings
worker/
  wrangler.toml           Worker name, api.threats.top, D1 binding, daily cron
  migrations/0001_init.sql  settings, customers, orders, subscriptions, licenses, audit
  src/index.mjs           router, CORS, error mapping, scheduled prune
  src/public.mjs          config, orders, lookup, Pro status, STIX download
  src/admin.mjs           session, orders, subscriptions, customers, audit, CSV
  src/auth.mjs            PBKDF2, TOTP, session HMAC, cookie parsing
  src/repo.mjs            the only SQL; an in-memory fake mirrors it in tests
  src/stix.mjs            STIX 2.1 bundle construction and feed fetch cache
  src/validation.mjs      order, lookup, months, and email rules
  src/codes.mjs           order codes and licence keys
  src/settings.mjs        writable settings whitelist and public config
  src/license.mjs         licence shape and salted hash
  src/subscriptions.mjs   expiry extension and status
  src/csv.mjs             formula-neutralised CSV
  test/                   handler, schema, auth, domain, STIX and repo tests
scheduler/
  wrangler.toml           threats-scheduler Cron Trigger every 15 minutes
  src/index.mjs           dispatches update-data.yml
*.html                    static pages, one per public surface
docs/                     contract, payment runbook, design, analysis
```

The API's SQL is confined to `worker/src/repo.mjs`, so every handler is tested
against an in-memory implementation of the same interface. The schema test
applies the real migration to SQLite; `wrangler dev --local` exercises the same
statements against D1 before deployment.

---

## 4. Data sources

| Source | Script | Output | Cadence | Notes |
|---|---|---|---|---|
| NVD 2.0 | `cve_feed.py` | `cves.json` → `recent` | 2h | Window widens after an outage, capped at 120 days. Paginates to exhaustion and publishes `items_parsed`/`items_available`. |
| CISA KEV | `cve_feed.py` | `cves.json` → `actively_exploited` | 2h | Last 90 days of additions; recent CVEs are cross-flagged `kev: true`. |
| GitHub Security Advisories | `ghsa_feed.py` | `ghsa.json` | 3h | REST API with the job token; ecosystem is preserved. |
| Exploit-DB | `exploitdb_feed.py` | `exploitdb.json` | 4h | Official RSS. |
| CERT-EU | `cert_eu_feed.py` | `cert_eu.json` | 4h | RSS with a tolerant parser. |
| Wiz Cloud Threat Landscape | `wiz_feed.py` | `wiz.json` | 30 days | Analysis, not alerts; the low cadence is deliberate. |
| ProjectDiscovery + curated | `collector.py` | `domains.json` | 6h | Merges `manual.json` by program name; canonical platform enum. |
| ransomware.live | `ransomware_feed.py` | `ransomware.json` | 1h | Attacker-supplied text is truncated; only http(s) URLs are kept. |
| OpenPhish | `phishing_feed.py` | `phishing.json` | 1h | Every URL is defanged before it is written. |
| Microsoft MSRC + Ubuntu | `advisories_feed.py` | `advisories.json` | 4h | Two RSS feeds, per-upstream partial-failure reporting. |
| FIRST EPSS | `epss_feed.py` | `epss.json` | 6h | Scores only the CVE ids in the current window; no bulk archive. |
| Derived | `iocs_feed.py` | `iocs.json` | 1h | Combines phishing and ransomware domains into one indicator list. |
| DB-IP Lite | `ip_country.py` | lookup table | monthly archive | Free CC BY 4.0 country database, cached under `.cache/` and never committed. Downloads the current month, falls back to the previous one. |
| Derived | `live_feed.py` | `live.json` | 1h | Joins the ransomware window and the OpenPhish snapshot: claims keep the country they publish, phishing hosts are resolved and located by registered IP country. Exits non-zero on an empty result; publishes claims alone if the database is unavailable. |

Keyed feeds (URLhaus, ThreatFox, Feodo, DShield) are deliberately excluded. They are either retired upstream, require an abuse.ch Auth-Key, or return empty. See the design record in `docs/superpowers/specs/`.

---

## 5. Scheduling and freshness

Collection is driven by the `threats-scheduler` Worker in `scheduler/`, whose Cloudflare Cron Trigger fires every 15 minutes and calls `workflow_dispatch` on `update-data.yml`. GitHub's own schedule is best-effort and was delivering only a fraction of events, so the workflow keeps three hourly `schedule` entries (`:07`, `:27`, `:47`) as a fallback. Runs that find nothing due are cheap and publish nothing.

The run itself does not use cron arithmetic. It reads `scripts/status.py` and runs a source when:

```
now >= last_success + cadence - 5 minutes
```

The five-minute grace prevents an hourly source from waiting an extra hour because the previous run finished seconds late. A source that has never succeeded is always due.

Each collector runs in its own subprocess with a 900-second timeout. Output is captured, the status entry records duration, HTTP status when available, item count, and the last error line, and `status.json` is rewritten after every source so a crash halfway through still leaves an accurate record.

Freshness rules:

- A source is `stale` when its age exceeds **twice** its cadence.
- `status.json.overall` is:
  - `ok` — no stale source and no recorded error;
  - `degraded` — a non-critical source is stale, or any source has an error;
  - `outage` — the critical source (`cve`) is stale.
- The workflow step *Fail on critical collector outage* exits non-zero when `cve` has never succeeded or is older than 24 hours. Publication happens before that step, so healthy feeds still ship during a partial outage.

Collectors also fail loudly on invalid data. `NormalisationTally` tolerates a small number of unparseable timestamps (5%, floor 3) so one odd advisory does not destroy a feed, records the failures in the output, and raises once the count looks systematic.

---

## 6. Delivery, validation, and branch protection

### 6.1 The scheduled pipeline

`update-data.yml`:

1. Checks out `main` with `persist-credentials: false`.
2. Resolves a bot token from the GitHub App (`DATA_BOT_APP_ID` + `DATA_BOT_PRIVATE_KEY`) or the PAT fallback (`DATA_BOT_TOKEN`).
3. Runs the due collectors with a read-only job token.
4. Runs `validate_feeds.py --against HEAD` even if collection failed.
5. If `data/` changed, commits the snapshot to `automation/data-<UTC>` and opens a PR, or pushes onto the one already-open automation PR. It then enables auto-merge with squash and branch deletion.
6. Fails the run if a critical collector is beyond its hard limit, after publication has been attempted.

The bot identity matters. A PR created with the built-in `GITHUB_TOKEN` does not trigger other workflows, so the required checks would never appear and the PR could never merge. `update-data.yml` warns and skips publication when no bot credential exists rather than opening a permanently blocked PR.

### 6.2 The pull-request gate

`validate.yml` runs on `pull_request` against `main` and on manual dispatch, with `contents: read` and no secrets. It has three independent jobs:

| Job name | What it proves |
|---|---|
| **Feed data** | Fetches the base commit and validates this PR's `data/` against it. Catches an emptied or halved feed, schema drift, bad timestamps, non-canonical enums, demo markers, and cross-file status inconsistencies. |
| **Unit tests** | `node --test assets worker scheduler` — escaping, the API's auth and handlers against the in-memory repository, the D1 schema, STIX shape, and the scheduler contract. 194 tests. |
| **Python tests** | `python3 -m unittest discover -s scripts/tests -t scripts` — normalisation, collectors, status, orchestrator, validator. 171 tests. |

A fourth **Design detector** job runs Impeccable over the pages and styles. It annotates findings and fails only if the scanner itself cannot run; it is advisory, not required, because taste rules must not override a human. Python tests need no Node and unit tests need no Python, which keeps both fast.

Using `pull_request` rather than `pull_request_target` means fork PRs get a read-only token and no secrets.

### 6.3 The ruleset

`scripts/setup-ruleset.sh` creates or updates `protect-main`:

- target: the default branch;
- enforcement: active;
- `bypass_actors: []` — no account, including the owner, can push around it;
- deletion and non-fast-forward forbidden;
- required linear history;
- pull request required, squash-only;
- required checks: **Feed data**, **Unit tests**, **Python tests**;
- `strict_required_status_checks_policy: false` so an automation PR is not deadlocked every time another data PR lands first.

The script also sets:

- squash-only merges, auto-merge on, delete-branch-on-merge on;
- the default Actions token to read-only and unable to approve PRs;
- Pages to serve `main` / with HTTPS enforced for `threats.top`.

Zero required approvals is deliberate: GitHub does not allow an author to approve their own PR, and a solo-maintained repository would deadlock. The gate is the PR plus the three checks. Raise the count to 1 when a second maintainer exists.

`require_extra_approval_for_unattributed_changes` is explicitly disabled. It defaults to on and would demand a human approval for bot-authored commits, which would make automated data PRs unmergeable.

---

## 7. Frontend

Each page is static HTML with an inline module that fetches its JSON from `/data/`. There is no build step, framework, or bundler.

| Page | Data |
|---|---|
| `index.html` | headline CVE slice, programs, ransomware, status |
| `cves.html` | `cves.json`, `epss.json`, `exploitdb.json`, `cert_eu.json`, `ghsa.json` |
| `programs.html` | `domains.json` |
| `iocs.html` | `iocs.json` |
| `ransomware.html` | `ransomware.json` |
| `map.html` | `live.json` |
| `phishing.html` | `phishing.json` |
| `threats.html` | `wiz.json`, `advisories.json` |
| `status.html` | `status.json` |
| `saas.html` | static pricing plus `/api/config` for the current price and support address |
| `subscribe.html` | `/api/config`, `/api/orders`, `/api/orders/lookup` |
| `pro.html` | `/api/config`, `/api/pro/me`, `/api/stix` |
| `admin/index.html` | `/api/admin/*`; public HTML, every read and write enforced server-side |

Public pages fetch committed JSON from `/data/`. The three Pro surfaces fetch the API cross-origin with credentials. All upstream strings pass through `esc()` before entering the DOM; the console pages render with `textContent` and never build HTML from input. URLs are validated as `http(s)` on the collector side; defanged indicators are rendered as text, not links. A page whose data fetch fails shows an explicit error state rather than stale or fabricated content.

The admin page is `noindex`. Being able to load it grants nothing: the API checks the signed session cookie on every read and the CSRF token on every mutation, and refuses a foreign `Origin` before a handler runs.

---

## 8. The Pro API and the retired Worker

The old `worker/admin.js` authenticated an admin password or an HMAC key and committed `manual.json` and tenant data straight to `main` through a GitHub PAT. That was a second write path that bypassed every check, and the tenant data it wrote was public. It is gone: the file and its tests were deleted, and every legacy `/admin-api/*` route now has no handler and returns the router's 404.

The replacement is `threats-platform-api`, a single Worker on `api.threats.top` with a D1 database named `threats-platform`:

- **Public routes** — `GET /api/health`, `GET /api/config`, `POST /api/orders`, `POST /api/orders/lookup`. Order creation is rate-limited to five per hour per hashed IP, uses a honeypot, and refuses a duplicate `(method, transaction reference)` pair.
- **Licence routes** — `GET /api/pro/me` and `GET /api/stix`. The licence key is a Bearer credential; only a salted hash and an 8-character prefix are stored. STIX is rate-limited per licence and returns a STIX 2.1 bundle built from the published `cves.json` and `iocs.json`, cached for five minutes at the edge.
- **Admin routes** — sign-in with password and TOTP, orders, subscriptions, customers, audit, stats, settings, and CSV export. Reads need an HMAC-signed 8-hour session cookie; mutations also need the CSRF token issued with that session and a matching `Origin`.
- **Scheduled** — a daily cron deletes unpaid pending orders past the retention window, prunes login attempts and rate-limit windows, and leaves paid history intact.

Tables: `settings`, `customers`, `orders`, `subscriptions`, `licenses`, `audit_log`, `login_attempts`, `rate_limit`. All SQL lives in `worker/src/repo.mjs`. Orders store hashed IP and user agent, never raw values; no PII is written to logs.

The two wallets, price, STIX limit, support address, and retention window are D1 settings, editable in the admin panel and audited. Secrets (`ADMIN_PASSWORD_HASH`, `TOTP_SECRET`, `SESSION_SECRET`, `LICENSE_SALT`, `IP_HASH_SALT`) are Worker secrets only. The retired `threats-admin` Worker is still parked at 410 until its secrets are deleted with the owner's approval; it is not part of this codebase's deploy path.

The operator procedure, including on-chain verification, refunds, key rotation, revocation, backup, retention, and incident response, is [`docs/PAYMENTS.md`](docs/PAYMENTS.md). The design record is [`docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md`](docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md). `docs/SAAS-ARCHITECTURE.md` is an earlier exploration and is superseded by both.

---

## 9. Known limitations

1. **RSS-scraped sources are fragile.** Exploit-DB, CERT-EU, Wiz, MSRC, and Ubuntu are website feeds, not contracts. A site-side change breaks them. The empty-feed and schema gates make that loud instead of silent.
2. **Wiz is low-volume by nature.** Thirty-day cadence and an analysis label are honest, not a bug.
3. **NVD is rate-limited.** Unauthenticated access allows five requests per 30 seconds; `NVD_REQUEST_INTERVAL = 7` stays under it. A long outage widens the window up to 120 days.
4. **EPSS is a rolling snapshot.** `epss.json` scores the current CVE window, not the full historical catalogue.
5. **The automation depends on a bot credential.** It is configured as the GitHub App `threats-data-bot`; if the App is uninstalled or its key revoked, collection and validation still run but nothing publishes.
6. **No end-to-end browser test.** `node --test` covers the escaping helper, the API handlers, the schema, and the scheduler contract; it does not prove a rendered page is navigable. Browser QA is manual at 1440 and 390.
7. **No machine-readable JSON Schema.** The contract is enforced in Python and generated into `docs/CONTRACT.md`; a consumer cannot validate without running it.
8. **Payment verification is manual.** There is no on-chain watcher and no price oracle. A wrong-network transfer, a short amount, or a fake token is caught by a human at review time, not by code. Approval latency is a person, not a queue.
9. **One admin account, one role.** TOTP replay is blocked by persisting the accepted step, but there is no per-user identity, no second reviewer, and no way to grant read-only access.
10. **No automatic renewal or dunning.** A customer's subscription simply expires; there is no reminder email and no recurring charge. Renewals are new orders, reviewed the same way.
11. **Pro availability depends on one Worker and one D1 database.** The public site is unaffected by an API outage, but checkout, the Pro console, and the admin panel stop working. There is no multi-region failover.
12. **One maintainer, zero required approvals.** The checks are the gate; there is no second human review.
13. **Pages has no atomic deploy hook.** It builds from `main`, so a merge is live after the Pages build completes, typically within a minute or two. The API is deployed separately with Wrangler and is not part of the Pages build.

---

## 10. Operations

### Check health

`/data/status.json` and `/status.html`. Look at `overall`, then each source's `stale`, `error`, and `age_minutes`.

For Pro, `GET https://api.threats.top/api/health` returns `{"status":"ok","schema":1,"time":"…"}`. Cloudflare observability is enabled for the Worker; `npx wrangler tail threats-platform-api` streams live requests during an incident.

### Deploy the API

From `worker/`:

```bash
npx wrangler d1 migrations apply threats-platform --remote
npx wrangler secret put SESSION_SECRET      # plus the other four, once
npx wrangler deploy
curl -fsS https://api.threats.top/api/health
```

`ADMIN_PASSWORD_HASH` and `TOTP_SECRET` come from `node scripts/admin-credentials.mjs`, run locally by the owner. No secret is written to the repository, a chat, or an issue. The full checklist and rotation effects are in [`docs/PAYMENTS.md`](docs/PAYMENTS.md) §2 and §13.

### Review a payment

Sign in at `admin/`, open **Orders**, filter to `pending`, and verify the transfer on the explorer named in [`docs/PAYMENTS.md`](docs/PAYMENTS.md). Approve with a month count, or reject with a required note. A new subscriber's licence key is shown once; a renewal keeps the existing key.

### Back up or restore D1

```bash
cd worker
npx wrangler d1 export threats-platform --remote --output ./backup.sql
npx wrangler d1 time-travel info threats-platform --remote
```

The export contains buyer PII: never commit it. Time Travel keeps 30 days of history. Restore replaces the whole database at the chosen bookmark; prefer a targeted correction through the panel for a single bad row.

### Force a collection

Run *Update Threat Data* with:

- `feeds=auto` — only sources whose cadence is due;
- `feeds=all` — every source;
- `feeds=cve,phishing` — a specific list.

### Change program scope by hand

Edit `data/manual.json`, run `python3 scripts/dev.py sync --feed domains`, and open a PR. Nothing writes `manual.json` automatically.

### Roll back

Revert the offending PR. Because `data/` is committed history, any prior snapshot is recoverable, and the next scheduled run will regenerate forward from the reverted state.

The Worker is deployed separately: reverting a Worker PR restores the previous code only after `npx wrangler deploy` from the reverted commit. D1 data is not part of the revert. If a bad change wrote subscription state, export the table first, then correct it through the panel or a targeted statement.

### Re-apply protection

```bash
bash scripts/setup-ruleset.sh
```

It is idempotent and prints the verified ruleset, merge settings, token permissions, Pages state, and whether bot credentials exist.

---

## 11. Documentation policy

A feature is not done until this file, the contract, and the constraints file reflect it. The contract is generated from the same table the validator enforces, so it cannot drift; the other two are reviewed in the same pull request as the change.
