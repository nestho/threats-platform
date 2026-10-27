# threats.top

Open threat intelligence, built from free official sources and published as static JSON and HTML. There is no database server and no backend process at runtime: GitHub Actions collects the data, `scripts/validate_feeds.py` gates it, GitHub Pages serves `threats.top`, and every change to production arrives through a pull request.

Every number on the site comes from a live feed. There is no demo data, no sample tenant, and no placeholder row that could be mistaken for real intelligence.

## Live pages

| Page | What it shows |
|---|---|
| [Home](https://threats.top/) | Current counts, source health, API catalog, recent activity |
| [Vulnerabilities](https://threats.top/cves.html) | NVD window, CISA KEV, EPSS, Exploit-DB, CERT-EU, GHSA |
| [Live indicators](https://threats.top/iocs.html) | Defanged phishing URLs and ransomware victim domains |
| [Ransomware](https://threats.top/ransomware.html) | Leak-site claims with group, sector, and country |
| [Phishing](https://threats.top/phishing.html) | A deduplicated OpenPhish snapshot |
| [Cloud threats](https://threats.top/threats.html) | Wiz Research incidents plus Microsoft and Ubuntu advisories |
| [Programs](https://threats.top/programs.html) | Bug bounty scope and in-scope domains |
| [Status](https://threats.top/status.html) | Per-source freshness, item counts, and last error |
| [Pricing](https://threats.top/saas.html) | Free public data, waitlist for the Pro tier |

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
| `data/status.json` | Derived | every run | Health of every source above |

Wiz publishes analysis, not alerts (measured: 0 items in 7 days, 3 in 30), so it runs on a 30-day cadence and is labelled as analysis in the UI rather than implying hourly freshness.

## How data reaches production

1. `update-data.yml` runs hourly at `:07`. `scripts/run_collectors.py` decides which sources are due from the cadence table in `scripts/status.py`, runs each collector in its own subprocess with a 900-second timeout, and writes `status.json` after each one. A failed source does not stop the healthy ones.
2. `scripts/validate_feeds.py` checks schema, provenance, timestamps, URL schemes, empty and halved feeds, status cross-file consistency, and the public HTML for demo markers.
3. If `data/` changed, the workflow commits to an `automation/data-*` branch and opens or updates one pull request. Auto-merge (squash) is enabled, so it lands as soon as the required checks pass.
4. `validate.yml` runs on every pull request and must report three green checks:
   - **Feed data** — validates the snapshot against the base commit, so the gate answers "did this PR empty or halve a feed" rather than "is a feed empty".
   - **Unit tests** — `node --test assets worker` (19 tests).
   - **Python tests** — `python3 -m unittest discover -s scripts/tests -t scripts` (98 tests).
5. `main` is protected by the `protect-main` ruleset with **no bypass actors**: pull requests only, linear history, squash merge only, no deletion, no force-push. Pages deploys from `main`.

The automation publishes as the GitHub App `threats-data-bot` (id `5502502`), installed on this repository only with Contents and Pull requests write, configured through `vars.DATA_BOT_APP_ID` + `secrets.DATA_BOT_PRIVATE_KEY`. The bot identity matters because pull requests created with the built-in `GITHUB_TOKEN` do not trigger the required checks. `secrets.DATA_BOT_TOKEN` remains a fine-grained PAT fallback. `scripts/setup-ruleset.sh` prints the setup steps and verifies the credentials.

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
node --test assets worker
```

## Repository layout

```
data/                 generated JSON; committed because it is the database
scripts/              collectors, shared normalisation, validator, status, dev CLI
scripts/tests/        Python unit tests and XML/JSON fixtures
assets/               shared CSS, escaping/time helpers, JS tests
*.html                static pages; each fetches its data from /data/
worker/               retired Edge Worker; every legacy route returns 410
.github/workflows/    scheduled collection and pull-request validation
docs/                 API contract, design history, deep analysis
```

The `worker/` directory is retained only so the retired surface is explicit and testable. Phase 2 replaces it with a D1-backed API; see [`docs/SAAS-ARCHITECTURE.md`](docs/SAAS-ARCHITECTURE.md).

## Operations

- **Check health:** [`/data/status.json`](https://threats.top/data/status.json) or [`/status.html`](https://threats.top/status.html). `overall` is `ok`, `degraded`, or `outage`; a source is `stale` after twice its cadence.
- **Collect now:** run the *Update Threat Data* workflow with `feeds=auto`, `all`, or a comma-separated source list.
- **Change scope by hand:** edit `data/manual.json`, regenerate `domains.json`, and open a pull request. This is the only supported write path.
- **Roll back:** revert the offending pull request. Feed history is ordinary git history, so any previous snapshot is recoverable.
- **Apply repository protection:** `bash scripts/setup-ruleset.sh` is idempotent and verifies the ruleset, merge settings, token permissions, Pages HTTPS, and bot credentials after applying them.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Generated public JSON contract |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Pipeline, scheduling, delivery, frontend, operations |
| [`CONSTRAINTS.md`](CONSTRAINTS.md) | Quality bar and the command behind each verdict |
| [`docs/SAAS-ARCHITECTURE.md`](docs/SAAS-ARCHITECTURE.md) | Phase 2 design for accounts, watchlists, and Pro alerting |
| [`docs/DEEP-ANALYSIS.md`](docs/DEEP-ANALYSIS.md) | Historical audit behind the 2026-09 integrity rework |
| [`docs/superpowers/specs/2026-10-27-real-threats-platform-design.md`](docs/superpowers/specs/2026-10-27-real-threats-platform-design.md) | Design record for the v1 rebuild |

Upstream data remains subject to each source's own terms. The code is published as-is, without warranty.
