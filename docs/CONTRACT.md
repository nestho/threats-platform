# Data API contract

_Generated from `scripts/validate_feeds.py`. Do not edit by hand — the same
table that documents the contract is the one that enforces it._
Regenerate with:

    python3 scripts/validate_feeds.py --print-contract

Every file under `data/` is a public, no-auth read endpoint. Schema changes
increment `schema_version`. The validation rules are listed in CONSTRAINTS.md.

## envelope

  schema_version  int -- bumped on any breaking change to this file
  updated_at      iso_datetime -- when this snapshot was generated, always UTC
  source          str -- human-readable upstream name
  source_url      str | list[str] -- the exact upstream URL(s)

## envelope_optional (optional)

  normalisation_failures  list[dict] -- records whose timestamp was unparseable
  note                    str -- provenance or interpretation caveat
  partial                 list[str] | null -- upstreams that failed while others succeeded

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

## vendor_advisory

  id         str
  vendor     str -- Microsoft | Ubuntu
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

## ransomware_claim

  id           str -- deterministic claim ID
  victim       str
  domain       nullable_str -- victim domain, when the leak site names one
  group        nullable_str
  activity     nullable_str -- claimed sector
  country      nullable_str
  published    nullable_iso_datetime
  discovered   nullable_iso_datetime
  description  str -- attacker-supplied, truncated
  claim_url    nullable_url -- .onion claim page
  link         nullable_url -- ransomware.live record
  screenshot   nullable_url

## phishing_url

  id            str -- derived from the live URL
  url_defanged  str -- defanged; never a live hxxp/hxxps URL
  host          str -- hostname extracted from the live URL
  collected_at  iso_datetime -- the snapshot time, not a first-seen claim

## epss_score

  cve         str
  epss        float -- 0..1
  percentile  float -- 0..1
  date        iso_date

## ioc

  id          str
  type        enum -- one of ['domain', 'url']
  value       str -- defanged URL for type=url, hostname for type=domain
  source      str
  context     str -- what the indicator means
  severity    enum -- one of ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']
  first_seen  nullable_iso_datetime
  last_seen   nullable_iso_datetime
  link        url

## status_source

  id               str
  label            str
  url              str | list[str]
  cadence_minutes  int
  last_attempt     nullable_iso_datetime
  last_success     nullable_iso_datetime
  http_status      nullable_int
  items            int
  error            nullable_str
  stale            bool

## feeds

  cves.json             envelope=nested    sections=recent.items, actively_exploited.items
  cves_headline.json    envelope=flat      sections=items
  ghsa.json             envelope=flat      sections=items
  exploitdb.json        envelope=flat      sections=items
  cert_eu.json          envelope=flat      sections=items
  wiz.json              envelope=flat      sections=items
  ransomware.json       envelope=flat      sections=items
  phishing.json         envelope=flat      sections=items
  advisories.json       envelope=flat      sections=items
  epss.json             envelope=flat      sections=items
  iocs.json             envelope=flat      sections=items
  domains.json          envelope=programs  sections=programs
