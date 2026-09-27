# threats.top

Open threat intelligence for researchers. Static JSON feeds and a browsable site,
built from free official sources. No API keys, no database, no backend — a
GitHub Action collects, GitHub Pages serves.

## What it covers

| Feed | Source | Cadence | Content |
|---|---|---|---|
| `data/cves.json` | NVD + CISA KEV | 2h | Recent CVEs + vulnerabilities confirmed exploited in the wild |
| `data/ghsa.json` | GitHub Security Advisories | 3h | Vulnerabilities in npm, PyPI, RubyGems, Go modules |
| `data/exploitdb.json` | Exploit-DB | 4h | Public proof-of-concept exploits |
| `data/cert_eu.json` | CERT-EU | 4h | EU institutional advisories |
| `data/wiz.json` | Wiz Research | **weekly** | Cloud incidents, campaigns, supply-chain compromises |
| `data/urlhaus.json` | abuse.ch | 1h | Live malware distribution URLs, **defanged** |
| `data/domains.json` | ProjectDiscovery + curated | 6h | Bug bounty programs and in-scope domains |

Browse it at **[threats.top](https://threats.top)** — programs, vulnerabilities,
and cloud threats.

## Using the API

Every file above is a public read endpoint. No key, no auth.

```bash
curl -s https://threats.top/data/cves.json | jq '.recent.items[] | select(.kev) | .id'
curl -s https://threats.top/data/wiz.json  | jq '.items[] | select(.type=="incident") | .title'
```

**Read [`docs/CONTRACT.md`](docs/CONTRACT.md) first.** It documents every field
and lists the sharp edges worth knowing before you depend on a shape:

- Every file carries a `schema_version`. Pin the one you built against.
- `cves.json` is ~920 KB. `cves_headline.json` is a 25-item slice for UIs — do not
  fetch the full file to render a list.
- `severity` is `null` for ~35% of recent CVEs. That is NVD's "Awaiting Analysis"
  state, not missing data; `cvss_version` distinguishes the two.
- All timestamps are ISO-8601 UTC with a trailing `Z`. An ISO string *without* an
  offset means local time.
- `url_defanged` is irreversible by design. The live URL is never stored.

The contract is **generated** from `scripts/validate_feeds.py --print-contract` —
the same table that documents the API is the one that enforces it, so they cannot
drift.

## Why the URLs are defanged

`urlhaus.json` contains live malware distribution URLs. Every one is defanged
(`hxxp://`, `[.]`) **at the collector**, before it is ever written to disk, so no
renderer anywhere has to remember to do it. Clicking one is how people get
infected. There is deliberately no UI for this feed.

## Development

No dependencies. Python 3 standard library only, and `node --test` for the two
test suites. There is no build step and no framework, and adding one would be a
regression rather than an improvement.

```bash
python3 scripts/validate_feeds.py     # the gate — run this before committing
python3 scripts/validate_feeds.py --print-contract
python3 scripts/normalize.py          # timestamp self-check
node --test assets worker             # 33 tests: XSS escaping + admin auth boundary

python3 scripts/cve_feed.py           # any single collector
```

Run collectors from the repository root — they use relative paths.

### How changes ship

```
main                    production, GitHub Pages
└── develop             integration
    └── fix/*  feat/*   short-lived
```

Two workflows gate this. Both are currently **advisory**, because `main` is not
yet protected — a direct push with `--no-verify` bypasses both. That is the
difference between a gate and a gate that is merely present:

- `update-data.yml` — hourly. Selects feeds by UTC hour, fetches, **validates**,
  then commits. A feed that parses to zero items, halves in size, or drifts from
  its schema fails the run and nothing is committed.
- `validate.yml` — on every pull request. Feed validity plus both test suites,
  with `contents: read` only.

```bash
scripts/setup-ruleset.sh    # needs: gh auth login
```

## Documentation

| | |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How it is built and why. Source of truth; updated in the same commit as any change |
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | The public API contract. Generated |
| [`CONSTRAINTS.md`](CONSTRAINTS.md) | The quality bar, with the command that produces each verdict |
| [`docs/DEEP-ANALYSIS.md`](docs/DEEP-ANALYSIS.md) | Audit behind the 2026-09-27 rework, with reproductions |

## Manual data entry

`threats.top/admin/` writes to `data/manual.json`, which `collector.py` merges
into the published program list. The write path is a Cloudflare Worker
(`worker/admin.js`, in this repo) with server-side validation, a single-origin
CORS allowlist, digest-based credential storage, and 20 tests over its auth
boundary.

Secrets are Workers secrets, never in this repository:

```bash
printf %s 'yourpassword' | shasum -a 256    # -> ADMIN_PASSWORD_HASH
wrangler secret put ADMIN_PASSWORD_HASH
wrangler secret put GITHUB_TOKEN            # fine-grained PAT: Contents rw, this repo only
wrangler deploy
```

## Licence

Data belongs to its respective sources — NVD, CISA, GitHub, Exploit-DB, CERT-EU,
Wiz Research, abuse.ch, ProjectDiscovery. This repository holds the collection
and presentation code.
