# Data API contract

_Generated from `scripts/validate_feeds.py`. Do not edit by hand — the same table
that documents the contract is the one that enforces it, so they cannot drift.
Regenerate with:_

    python3 scripts/validate_feeds.py --print-contract

Every file under `data/` is a public, no-auth read endpoint. There is no key, no
rate limit and no version negotiation beyond the `schema_version` field described
below.

## Stability

`schema_version` is bumped whenever a published shape changes in a way that could
break a consumer. `scripts/validate_feeds.py` holds an expected version per feed
and fails CI if a file's version does not match, so a shape change cannot land
without the version moving in the same commit.

**There is no `/v1/` and no deprecation window.** If you depend on these files,
pin the `schema_version` you built against and check it.


## envelope

  schema_version  int -- bumped on any breaking change to this file
  updated_at      iso_datetime -- when this snapshot was generated, always UTC

## envelope_optional (optional)

  normalisation_failures  list[dict] -- records whose timestamp was unparseable

## program

  name          str
  url           str
  platform      enum -- one of ['Bugcrowd', 'HackenProof', 'HackerOne', 'Immunefi', 'Intigriti', 'Self-hosted / Other', 'YesWeHack']
  domain_count  int
  domains       list[str]
  manual        bool -- true if the entry came from data/manual.json

## cve

  id            str -- CVE-YYYY-NNNN
  published     nullable_iso_datetime -- null only if the upstream date was unparseable
  description   str -- truncated to 300 chars
  severity      nullable_str -- null means NVD has not scored this yet
  score         nullable_float
  cvss_version  nullable_str -- 40/31/30/2, or null when unscored
  link          url
  kev           bool

## kev

  id              str
  vendor          nullable_str
  product         nullable_str
  name            nullable_str
  date_added      iso_date -- CISA publishes no time component
  ransomware_use  nullable_str -- null, not the string "Unknown"
  description     str
  link            url

## advisory

  id         str
  title      str
  published  nullable_iso_datetime
  summary    str
  link       url

## exploit

  id           str -- EDB numeric id, else the bare guid
  title        str
  type         nullable_str
  published    nullable_iso_datetime
  description  str
  link         url

## threat_event

  id         str -- stable UUID guid from the feed
  title      str -- classification suffix stripped
  type       nullable_enum -- incident | campaign | research | null when unclassified
  published  nullable_iso_datetime
  summary    str
  author     nullable_str
  link       url

## malware_url

  id            str
  date_added    nullable_iso_datetime
  url_defanged  str -- defanged; never a live hxxp/hxxps URL
  status        str
  threat        str
  tags          str

## feeds

  cves.json         envelope=nested    sections=recent.items, actively_exploited.items
  cves_headline.json  envelope=flat      sections=items
  ghsa.json         envelope=flat      sections=items
  exploitdb.json    envelope=flat      sections=items
  cert_eu.json      envelope=flat      sections=items
  urlhaus.json      envelope=flat      sections=items
  wiz.json          envelope=flat      sections=items
  domains.json      envelope=programs  sections=programs


## Known sharp edges

These are current behaviours, not bugs to be fixed silently. Consumers should
code around them.

- **`cves.json` → `recent` is the full NVD window** (currently ~1500 CVEs over 3
  days, ~920 KB). `cves_headline.json` is a bounded 25-item slice for UIs. Do not
  fetch `cves.json` to render a small list.
- **`severity` and `score` are `null` for ~35% of recent CVEs.** That is NVD's
  "Awaiting Analysis" state, not missing data. Use `cvss_version` to tell a
  v4.0/v3.1 score apart from an absent one.
- **`ransomware_use` is `null`, never the string `"Unknown"`.** CISA publishes
  `"Unknown"`; the collector normalises it so absence is testable.
- **`actively_exploited[].date_added` is date-only** (`YYYY-MM-DD`). CISA
  publishes no time component. A bare date is UTC midnight to a JS `Date`.
- **Every other timestamp is ISO-8601 UTC with a trailing `Z`.** An ISO string
  *without* an offset means local time, so do not strip the `Z`.
- **`id` means different things per feed** — CVE, GHSA, EDB, CERT-EU advisory
  (e.g. `2026-013`), Wiz UUID. There is no `type` discriminator on the envelope;
  branch on which file you read.
- **`urlhaus.json` → `url_defanged` is irreversible.** The live URL is never
  stored. Refanging is a lossy guess, which is the point.
- **`domains.json` → `platform` is a closed enum**, published in the file's own
  `platforms` array. `platform_warnings` is non-empty when a hand-edited
  `manual.json` entry used a non-canonical value.
- **`normalisation_failures`** is present on feeds that normalise per-record
  timestamps. A non-empty list means some records have a `null` date; the
  validator warns on it.
- **URLhaus is API-only.** It has no UI, deliberately: the feed is live malware
  distribution URLs and there is no browsing experience that makes that a good
  idea.
