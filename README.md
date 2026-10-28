# threats.top

[![Update Threat Data](https://github.com/nestho/threats-platform/actions/workflows/update-data.yml/badge.svg)](https://github.com/nestho/threats-platform/actions/workflows/update-data.yml)
[![Validate](https://github.com/nestho/threats-platform/actions/workflows/validate.yml/badge.svg)](https://github.com/nestho/threats-platform/actions/workflows/validate.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=nestho_threats-platform&metric=alert_status)](https://sonarcloud.io/dashboard?id=nestho_threats-platform)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Open threat intelligence, built from free official sources and published as static JSON and HTML. GitHub Actions collects the data, `scripts/validate_feeds.py` gates it, GitHub Pages serves `threats.top`, and every change to production arrives through a pull request. A single Cloudflare Worker on `api.threats.top` handles the paid side only — orders, licences, admin review, and the STIX export — and never writes to git.

Every number on the site comes from a live feed. There is no demo data, no sample tenant, and no placeholder row that could be mistaken for real intelligence.

## Live pages

| Page | What it shows |
|---|---|
| [Home](https://threats.top/) | Current counts, source health, API catalog, recent activity |
| [Vulnerabilities](https://threats.top/cves.html) | NVD window, CISA KEV, EPSS, Exploit-DB, CERT-EU, GHSA |
| [Live indicators](https://threats.top/iocs.html) | Defanged phishing URLs and ransomware victim domains |
| [Ransomware](https://threats.top/ransomware.html) | Leak-site claims with group, sector, and country |
| [Live map](https://threats.top/map.html) | Victim claims and phishing hosting by country, with a 72-hour replay |
| [Phishing](https://threats.top/phishing.html) | A deduplicated OpenPhish snapshot |
| [Cloud threats](https://threats.top/threats.html) | Wiz Research incidents plus Microsoft and Ubuntu advisories |
| [Programs](https://threats.top/programs.html) | Bug bounty scope and in-scope domains |
| [Status](https://threats.top/status.html) | Per-source freshness, item counts, and last error |
| [Pricing](https://threats.top/saas.html) | Free public data, Pro terms, and what is still roadmap |
| [Subscribe](https://threats.top/subscribe.html) | USDT (TRC20) or BTC checkout, order status lookup |
| [Pro console](https://threats.top/pro.html) | Activate a licence, check expiry, download the STIX 2.1 export |
| [Admin](https://threats.top/admin/) | Owner-only order review, subscriptions, settings, audit |

## Feeds

All public feeds are unkeyed. Each file carries `schema_version`, `source`, `source_url`, and `updated_at`; the field contract is in [`docs/CONTRACT.md`](docs/CONTRACT.md).

| Feed | Source | Cadence | Content |
|---|---|---|---|
| `data/cves.json` | NVD 2.0 + CISA KEV | 2h | Recent CVEs, exploited CVEs, CVSS scores |
| `data/cves_headline.json` | Derived from `cves.json` | 2h | Bounded 25-item slice for the homepage |
| `data/ghsa.json` | GitHub Security Advisories | 3h | npm, PyPI, RubyGems, Go and other ecosystems |
| `data/exploitdb.json` | Exploit-DB | 4h | Public proof-of-concept exploits |
| `data/cert_eu.json` | CERT-EU | 4h | EU institutional security advisories |
| `data/wiz.json` | Wiz Cloud Threat Landscape | 30 days | Cloud incidents, campaigns, supply-chain compromises |
| `data/domains.json` | ProjectDiscovery + curated | 6h | Bug bounty programs and in-scope domains |
| `data/ransomware.json` | ransomware.live | 1h | Recent leak-site claims |
| `data/phishing.json` | OpenPhish | 1h | Defanged phishing URLs |
| `data/advisories.json` | Microsoft MSRC + Ubuntu | 4h | Vendor security notices |
| `data/epss.json` | FIRST EPSS | 6h | Exploit prediction scores for the CVE window |
| `data/iocs.json` | Derived | 1h | Combined phishing and ransomware indicators |
| `data/live.json` | Derived + DB-IP Lite | 1h | Geo-placed claims and phishing hosts for the live map |
| `data/status.json` | Derived | every run | Health of every source above |

Phishing host locations in `live.json` come from [DB-IP Lite](https://db-ip.com)
under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); the attribution
is repeated on the page and in the feed metadata.

Wiz publishes analysis, not alerts (measured: 0 items in 7 days, 3 in 30), so it runs on a 30-day cadence and is labelled as analysis in the UI rather than implying hourly freshness.

## How data reaches production

1. Collection is triggered every 15 minutes by a Cloudflare Cron Trigger in `scheduler/`, which calls `workflow_dispatch` on `update-data.yml`. GitHub's own scheduler delivered only 3–8 of 24 daily events, in 2–5 hour gaps, so the three `schedule` slots remain only as a fallback. `scripts/run_collectors.py` decides which sources are due from the cadence table in `scripts/status.py`, runs each collector in its own subprocess with a 900-second timeout, and writes `status.json` after each one. A failed source does not stop the healthy ones.
2. `scripts/validate_feeds.py` checks schema, provenance, timestamps, URL schemes, empty and halved feeds, status cross-file consistency, and the public HTML for demo markers.
3. If `data/` changed, the workflow commits to an `automation/data-*` branch and opens or updates one pull request. Auto-merge (squash) is enabled, so it lands as soon as the required checks pass.
4. `validate.yml` runs on every pull request and must report three green checks:
   - **Feed data** — validates the snapshot against the base commit, so the gate answers "did this PR empty or halve a feed" rather than "is a feed empty".
   - **Unit tests** — `node --test assets worker scheduler` (194 tests).
   - **Python tests** — `python3 -m unittest discover -s scripts/tests -t scripts` (171 tests).
   A fourth, advisory **Design detector** job annotates layout and accessibility findings without blocking a merge.
5. `main` is protected by the `protect-main` ruleset with **no bypass actors**: pull requests only, linear history, squash merge only, no deletion, no force-push. Pages deploys from `main`.

The automation publishes as the GitHub App `threats-data-bot` (id `5502502`), installed on this repository only with Contents and Pull requests write, configured through `vars.DATA_BOT_APP_ID` + `secrets.DATA_BOT_PRIVATE_KEY`. The bot identity matters because pull requests created with the built-in `GITHUB_TOKEN` do not trigger the required checks. `secrets.DATA_BOT_TOKEN` remains a fine-grained PAT fallback. `scripts/setup-ruleset.sh` prints the setup steps and verifies the credentials.

## Pro subscriptions

Pro is sold directly, in USDT (TRC20) or BTC, with manual review. There is no payment processor and no card data. The flow:

1. The buyer chooses a term on `subscribe.html`, sends the equivalent of the monthly price to the displayed wallet, and submits the order form with the transaction reference. The page returns an order code.
2. The owner verifies the transfer on the matching explorer and approves the order at `admin/`. Approval creates or extends a subscription and issues a `THREATS-PRO-…` licence key, shown once.
3. The buyer activates the key at `pro.html` and uses it as a Bearer token for `/api/pro/me` and the STIX 2.1 export at `/api/stix`.

Subscription state lives in Cloudflare D1, outside git. Only a salted hash and an 8-character prefix of each licence are stored. Admin sign-in is a password plus TOTP behind an HMAC-signed, HttpOnly, SameSite=Strict session cookie with CSRF protection; every mutation is audited. Wallets, prices, limits, and retention are editable in the admin panel without a deploy.

The complete procedure — on-chain checks, refusals, refunds, rotation, revocation, backup, retention, and incident steps — is in [`docs/PAYMENTS.md`](docs/PAYMENTS.md).

## Local development

Runtime dependencies are zero. Python 3 standard library only; the JavaScript tests use Node's built-in test runner.

```bash
python3 scripts/dev.py test                  # normalisation checks, feed validation, Python and Node tests
python3 scripts/dev.py validate              # validate every data/*.json without the git regression check
python3 scripts/dev.py sync --feed auto      # run every source that is due
python3 scripts/dev.py sync --feed phishing  # run one source
python3 scripts/dev.py serve --port 8080     # serve the site at http://localhost:8080
```

Direct equivalents:

```bash
python3 scripts/normalize.py
python3 scripts/validate_feeds.py
python3 -m unittest discover -s scripts/tests -t scripts -v
node --test assets worker scheduler
```

The API Worker is developed and deployed with Wrangler, invoked through `npx` and never added as a repository dependency:

```bash
cd worker
npx wrangler d1 migrations apply threats-platform --local
npx wrangler dev --local                    # http://127.0.0.1:8787, state in .wrangler/
node --test test                            # Worker unit tests only
```

`worker/.dev.vars` holds local-only secrets and is ignored; start from `worker/.dev.vars.example`. The full end-to-end rehearsal is described in [`docs/PAYMENTS.md`](docs/PAYMENTS.md) §13.

## Repository layout

```
data/                 generated JSON; committed because it is the database
scripts/              collectors, shared normalisation, validator, status, dev CLI
scripts/tests/        Python unit tests and XML/JSON fixtures
assets/               shared CSS, escaping/time helpers, checkout/admin/pro modules, JS tests
*.html                static pages; each fetches its data from /data/ or the API
admin/                owner console; every read and write is enforced by the API
worker/               threats-platform-api: D1 schema, handlers, auth, STIX, tests
scheduler/            Cloudflare Worker that dispatches collection every 15 minutes
.github/workflows/    collection and pull-request validation
docs/                 API contract, payment runbook, design history, deep analysis
```

The API Worker never writes to git and holds no feed data. The static site does not depend on it: if the Worker is down, every public page keeps working and only checkout, the Pro console, and the admin panel report an error. Subscription state is not committed; see [`docs/PAYMENTS.md`](docs/PAYMENTS.md) for the backup and restore procedure.

## Operations

- **Check health:** [`/data/status.json`](https://threats.top/data/status.json) or [`/status.html`](https://threats.top/status.html). `overall` is `ok`, `degraded`, or `outage`; a source is `stale` after twice its cadence.
- **Check the API:** `curl -fsS https://api.threats.top/api/health` returns `{"status":"ok","schema":1,"time":"…"}`. The admin Overview shows pending orders, active Pro, MRR, and expiring subscriptions.
- **Collect now:** run the *Update Threat Data* workflow with `feeds=auto`, `all`, or a comma-separated source list.
- **Scheduling:** `scheduler/` holds the Cron Trigger. From that directory run `npx wrangler deploy`, then `npx wrangler secret put GH_TOKEN` with a fine-grained token that has only `Actions: write` on this repository. Tokens expire: a `401` in `npx wrangler tail` means rotate it, and the resulting gap surfaces as `degraded` or `outage` on `/status.html`.
- **Deploy the API:** from `worker/`, apply migrations with `npx wrangler d1 migrations apply threats-platform --remote`, set the five secrets listed in [`docs/PAYMENTS.md`](docs/PAYMENTS.md) §2, and run `npx wrangler deploy`. `ADMIN_PASSWORD_HASH` and `TOTP_SECRET` are generated locally with `node scripts/admin-credentials.mjs` and never shared.
- **Review a payment:** follow [`docs/PAYMENTS.md`](docs/PAYMENTS.md) §3–§5: verify the transfer on the matching explorer, then approve or reject with a note in `admin/`.
- **Back up D1:** `npx wrangler d1 export threats-platform --remote --output ./backup.sql`. The file contains buyer PII and is never committed; Time Travel covers the last 30 days.
- **Change scope by hand:** edit `data/manual.json`, regenerate `domains.json`, and open a pull request. This is the only supported write path for published data.
- **Roll back:** revert the offending pull request. Feed history is ordinary git history, so any previous snapshot is recoverable. Reverting a page or the Worker does not touch D1; export it first if the rollback changes entitlement behaviour.
- **Apply repository protection:** `bash scripts/setup-ruleset.sh` is idempotent and verifies the ruleset, merge settings, token permissions, Pages HTTPS, and bot credentials after applying them.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Generated public JSON contract |
| [`docs/PAYMENTS.md`](docs/PAYMENTS.md) | Pro payment verification, licences, refunds, D1 backup, incidents |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Pipeline, scheduling, delivery, API, frontend, operations |
| [`CONSTRAINTS.md`](CONSTRAINTS.md) | Quality bar and the command behind each verdict |
| [`docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md`](docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md) | Design record for the Pro subscription system |
| [`docs/SAAS-ARCHITECTURE.md`](docs/SAAS-ARCHITECTURE.md) | Earlier Phase 2 exploration; superseded by the subscription design |
| [`docs/DEEP-ANALYSIS.md`](docs/DEEP-ANALYSIS.md) | Historical audit behind the 2026-09 integrity rework |
| [`docs/superpowers/specs/2026-10-27-real-threats-platform-design.md`](docs/superpowers/specs/2026-10-27-real-threats-platform-design.md) | Design record for the v1 rebuild |

## Community

| Document | Purpose |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development setup, pull request rules, how to add a source |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability reporting and scope |
| [`ACCESSIBILITY.md`](ACCESSIBILITY.md) | WCAG 2.2 AA target and known limitations |

## License

Licensed under the [Apache License 2.0](LICENSE). Upstream data remains subject to
each source's own terms; the licence covers the code and does not grant rights to
third-party feed content. The software is provided as-is, without warranty.

