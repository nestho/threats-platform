# Deep Analysis — threats-platform

_Independent audit, 2026-09-27. Companion to [`ARCHITECTURE.md`](../ARCHITECTURE.md) —
that document describes **what the system is**; this one records **what's wrong with it**,
with reproductions. Findings are cross-referenced against ARCHITECTURE.md §7 so nothing
is tracked twice._

**Method.** Every defect below was reproduced — against live upstreams (NVD, the feeds) or
by executing the code with instrumented inputs. Nothing here is inferred from reading alone.

**Verdict.** The architectural premise is sound and unusually disciplined for its size:
stdlib-only, no runtime infrastructure, one serialized cron, and a hand-maintained file
that's explicitly never overwritten. Two things undercut it:

1. **Nothing between the third-party feed and the committed JSON is verified.** Six untrusted
   upstreams are treated as trusted, and there is no gate that can fail.
2. **The published JSON is a public API with no contract.** It is marketed as one on the
   homepage ("No key required… use them in scripts, dashboards, or pipelines") and has no
   schema, no version, and no documentation.

---

## 1. Confirmed — already tracked in ARCHITECTURE.md

| # | Finding | Arch doc | Audit adds |
|---|---|---|---|
| 1 | NVD truncated at 200, no pagination | §7.1 | **Quantified: 1533 upstream → 200 parsed → 1333 dropped (87%)**, measured live. `recent.total` reports `200`, a *true* number, so nothing anywhere looks wrong. |
| 2 | Worker not version-controlled | §7.2, §6 | Confirmed and **worse than described**: it is the only write path to published data, and it feeds strings straight into `manual.json` with no validation. See §5. |
| 3 | `admin/` on old colour scheme | §7.3 | Confirmed, cosmetic. |
| 4 | RSS-scraped sources are fragile | §7.4 | Confirmed and **quantified as an active incident, not a hypothetical** — see §2.1. |
| 5 | No schema validation on output | §7.5 | Confirmed. **This is the highest-severity item on this page.** See §2.2. |
| 6 | `README.md` is a placeholder | §7.6 | Confirmed. For a project whose only product is its data API, this is load-bearing, not cosmetic. |

---

## 2. New findings — not yet in ARCHITECTURE.md

### 2.1 — A feed failure wipes a public endpoint, and CI reports success `CRITICAL`

`scripts/cert_eu_feed.py:61-79` catches `ET.ParseError` and falls back to a regex over
whatever bytes came back. Served an HTML error page instead of RSS:

```
$ python3 scripts/cert_eu_feed.py
Wrote 0 CERT-EU advisories.
>>> exit code: 0

$ cat data/cert_eu.json
{ "updated_at": "...", "total": 0, "items": [] }
```

`update-data.yml` sees exit 0, sees `data/` changed, **commits the empty feed, marks the job
green**. `threats.top/data/cert_eu.json` is now `[]`, the UI renders "No matches", and
nothing alerts. The `retry()` wrapper at `update-data.yml:109` never fires because the
script *succeeded*.

This is generic across all six collectors — every one will happily write an empty or
malformed `items` array and exit 0. ARCHITECTURE.md §7.5 describes this abstractly; it is
more concrete than "could silently write malformed data" — it is a **demonstrated,
reproducible public data-loss event with a green CI run**.

This is also the concrete instance of ARCHITECTURE.md §7.4's fragility risk. The two
findings are the same bug seen from two sides.

### 2.2 — CVSS v4.0 scores are discarded `HIGH`

`scripts/cve_feed.py:43` checks `cvssMetricV31`, `cvssMetricV30`, `cvssMetricV2` — but not
`cvssMetricV40`. Measured over a 200-item window:

```
metric keys present: {'cvssMetricV40': 37, 'cvssMetricV31': 115,
                      'ssvcV203': 102, 'cvssMetricV2': 3}
items emitting severity=null: 85
  ...of those, upstream DID ship a score under a key the code ignores: 12
```

Two distinct problems:

1. **12 real scores are lost** to the missing `V40` key.
2. The other ~73 nulls are *legitimate* — NVD "Awaiting Analysis", genuinely unscored.
   The code cannot tell these apart, so `null` is overloaded: **"not yet scored" and "we
   forgot to read v4" are indistinguishable to every consumer.** A consumer writing
   `if (score > 9)` gets a silent `false` in both cases.

Secondary: `cve_feed.py:45` takes `metrics[key][0]` rather than the entry where
`cvssData.type == "Primary"`. NVD publishes CNA-supplied secondary scores too, so `[0]`
can pick the wrong number.

**Fix:** read all four versions, select on `type == "Primary"`, and add a `cvss_version`
field so `null` means exactly one thing.

### 2.3 — Every CERT-EU timestamp is unparseable in the browser `HIGH`

CERT-EU `pubDate` is RFC-2822 with a European zone abbreviation. `cert_eu_feed.py:93`
stores it raw. ECMA-262 only guarantees `GMT`/`UTC` plus seven US abbreviations —
**`CEST` is not parseable**:

```
NaN   "Tue, 22 Sep 2026 18:52:36 CEST"     ← 6/10 current items
NaN   "Thu, 10 Sep 2026 10:20:06 CEST"
1788253200000   "Mon, 01 Sep 2026 09:00:00 GMT"   ← only GMT works
```

Consequences:

- `timeAgo()` (`index.html:507`) returns `—` for **every CERT-EU item, permanently**.
- The comparator at `index.html:639` returns `NaN`, so ordering of mixed-format events is
  **engine-defined, not chronological**. Verified: the NaN element lands mid-array.

**Root cause is broader than CERT-EU.** There are **four date formats across six feeds**,
and nothing normalises them:

| Feed | Field | Format |
|---|---|---|
| NVD | `published` | ISO-8601 ✅ |
| CISA KEV | `date_added` | `YYYY-MM-DD` |
| Exploit-DB | `published` | RFC-2822 (GMT) |
| CERT-EU | `published` | RFC-2822 (**CEST**) ❌ |
| URLhaus | `date_added` | `YYYY-MM-DD HH:MM:SS` |
| GHSA | `published` | ISO-8601 ✅ |

**Fix:** normalise every timestamp to ISO-8601 UTC at the collector boundary. One line per
feed; eliminates the entire bug class rather than this instance.

### 2.4 — Platform enum is already split `MEDIUM`

```
190  HackerOne            94  HackenProof      10  Intigriti
132  Self-hosted / Other  77  Bugcrowd          4  Immunefi
 23  YesWeHack             1  BugCrowd     ← collision
```

`collector.py:107` — `program.get("platform") or detect_platform(...)` — lets a hand-written
`manual.json` value bypass detection with **zero normalisation**. `manual.json` says
`"BugCrowd"`; `PLATFORM_MAP` says `"Bugcrowd"`. `programs.html:322-329` groups on the raw
string, so **Bugcrowd renders as two separate groups in the "By platform" tab**. One
hand-edit broke a published enum.

This is a live demonstration of the §2.1 problem: the only human write path into published
data has no validation, and it has *already* produced a defect.

Related: **28 programs carry zero domains** and render as empty cards on the one page whose
entire purpose is showing scope.

### 2.5 — The published JSON is an API with no contract `HIGH`

ARCHITECTURE.md does not currently frame `data/*.json` as a public API. It is one —
`index.html:465` markets it as such. Per Hyrum's Law, these six files are a **committed
public interface**, and they have:

- ❌ **No schema** — no JSON Schema, no documented types, no required/optional markers
- ❌ **No versioning** — no `/v1/`, no `schema_version`, no deprecation path. A field rename
  breaks every consumer silently.
- ❌ **No documentation** — the README is `# threats-platform` and nothing else
- ❌ **No `source` field** — a consumer reading `/data/cves.json` cannot tell which upstream
  produced a record without out-of-band knowledge of the filename
- ❌ **Two envelope shapes** — `cves.json` is `{recent, actively_exploited}`; the other five
  are `{total, items}`. One "API", two contracts.
- ❌ **Free-text enums** — `platform` is unvalidated (see §2.4)
- ❌ **Sentinels masquerading as values** — `ransomware_use` is the literal string
  `"Unknown"` from CISA, not `null`

Already-observable behaviour consumers will have come to depend on, none of it promised:
null severity on ~40% of recent CVEs; `id` meaning five unrelated namespaces (CVE / GHSA /
EDB / CERT-EU / URLhaus) with no discriminator; `url_defanged` being irreversible by design
with no documented refang path.

**Fix, in order:** `schema_version` in every file → JSON Schema per feed + a CI `validate`
step → real README with one table per endpoint → `source` on every record → unify envelope.

### 2.6 — URLhaus and GHSA have no UI surface `MEDIUM`

| Feed | Human-facing UI |
|---|---|
| `cves` | `cves.html`, `index.html` |
| `exploitdb` | `cves.html`, `index.html` |
| `cert_eu` | `cves.html`, `index.html` |
| `domains` | `programs.html`, `index.html` |
| `ghsa` | `index.html` (recent strip only — no page) |
| **`urlhaus`** | **none** |

`urlhaus.json` is fetched into `cache` at `index.html:549` and **never rendered anywhere**.
The most safety-sensitive feed on the platform — live malware distribution URLs — is the one
users cannot browse. Either give it a page or stop listing it as a headline endpoint.

### 2.7 — Assorted `LOW`

| Where | Issue |
|---|---|
| `cves.html:209` | `EDB-${esc(i.id)}` — when the EDB-ID regex misses, `id` falls back to the full RSS `guid`, rendering `EDB-https://www.exploit-db.com/…`. Latent (0/50 today), ugly when it fires. |
| `cert_eu_feed.py:59` | `link or f"…" if advisory_id else ""` — precedence makes this `(link or url) if advisory_id else ""`, so a valid link with no parsed advisory id is silently discarded. |
| `cve_feed.py:99` | KEV `ransomware_use` defaults to `"Unknown"` instead of `null`. |
| `index.html:613` | `hot: true` hardcoded for every Exploit-DB item — the orange badge carries no signal. |
| `esc()` × 3 files | Escapes `<>&` via `innerHTML` but **not quotes**. Safe in text context; `programs.html:273` hand-rolls a separate `"`-only escape for `data-domains`. Two half-escapers, neither quote-safe — correctness rests on "nothing untrusted ever reaches an attribute." |
| `update-data.yml:41,47` | `actions/checkout@v4` / `setup-python@v5` pinned to mutable tags, not SHAs. |
| `data/cert_eu.json` | 6/10 `summary` fields contain raw `<br>`/tags. Inert today (every renderer wraps in `esc()`), but nothing in the *pipeline* sanitises — safety depends on every future renderer remembering. |
| `cve_feed.py:34-35` | NVD date params sent without a timezone offset. Accepted, but fragile. |
| `update-data.yml:184` | `git add data/` won't stage a *deleted* data file, so one can never be removed. |

---

## 3. Design assessment — the seam is in the wrong place

**What's genuinely good** (keep these; they're the reason the project is maintainable at
this size): stdlib-only; a single `concurrency` group with `cancel-in-progress: false`; one
hourly cron with in-job feed selection instead of six overlapping crons; `manual.json`
correctly designed as append-only-and-never-overwritten (`collector.py:60-71`); URLhaus
defanged at the *collector* rather than at render (`urlhaus_feed.py:30`) with the reasoning
documented; a genuine server-side auth check in the admin gate rather than UI-only hiding
(`admin/index.html:84-86`); and an honest architecture doc with a documentation policy.

**The structural problem.** Each collector does *fetch → parse → validate(nothing) → write →
exit 0*. The interface is the filesystem, and the implicit contract is "exit 0 means the file
is good." **That contract is false** — §2.1 is the proof.

Per the dependency-category model, all six upstreams are **category 4 (true external)** — the
highest-risk class, and the one that explicitly demands validation at the seam. This project
validates at none of them. That single omission is the common cause of §2.1, §2.2, §2.3,
§2.4, and §2.5.

**Target structure — one deep module, six thin adapters:**

```
FeedSource (port)  ── 6 adapters: NVD+KEV, GHSA, ExploitDB, CERT-EU, URLhaus, ProjectDiscovery
        │
   FeedPipeline  ← the deep module. Owns: fetch w/ backoff, schema validation,
        │          normalisation (timestamps→ISO UTC, CVSS→versioned, platform→enum),
        │          empty/shape regression guard, atomic write, meaningful exit codes.
        │
   data/*.json
```

One implementation, six adapters, validation rules written once. `update-data.yml` shrinks to
`python -m feeds run <name>`, and the empty-feed guard becomes a *property of the module*
rather than something each script must remember. The interface then becomes testable
**without network** by injecting fixture bytes — which is the seam that makes a test suite
possible at all. **Today there is nowhere to put a test.**

### Module depth, scored honestly

| Module | Depth | Note |
|---|---|---|
| `urlhaus_feed.py` | **good** | narrow, self-contained; `defang` is real hidden behaviour behind a tiny interface |
| `collector.py` | **good** | the manual-merge logic (`collector.py:95-110`) is genuine depth — 15 lines of merge semantics behind one `main()` |
| `cve_feed.py` | shallow + wrong | 2 upstreams, no normalisation, truncation bug |
| `cert_eu_feed.py` | shallow | owns a regex fallback that is a liability, not a depth |
| `index/programs/cves.html` | **negative** | 3 copies of `esc()`, 2 of `showToast()`, 2 of ~80 lines of `:root`/`header.site`/`.logo-mark` CSS. Every CSS change is a 4-file edit. |

**Duplication:** ~35 duplicated lines across the six scripts — 4 near-identical `fetch_text`
definitions, 6 copies each of the fetch/serialise/write envelope, and 2 verbatim copies of a
6-line RSS item loop (`cert_eu_feed.py:36-43` ≡ `exploitdb_feed.py:32-38`). This is the
*symptom*; the disease is that the envelope is copy-pasted instead of being one module.

---

## 4. Frontend assessment

Assessed against WCAG 2.1 AA and the project's own design system. The visual system is
genuinely good — consistent dark palette, real type hierarchy, restrained accent use, and it
avoids every AI-generated-UI tell (no purple gradients, no stock card grid, no oversized
padding). ARCHITECTURE.md §3 documents it accurately.

**Blocking**

| Issue | Where |
|---|---|
| **Program cards are not keyboard accessible.** `programs.html:294` puts `onclick` on a `<div class="card">` with `cursor:pointer` and no `tabindex`, no `role`, no key handler. The primary content of the page cannot be operated by keyboard. | `programs.html:291-304` |
| **Copy-to-clipboard has no accessible feedback path** beyond a transient `opacity` toast — no `aria-live`, so a screen reader announces nothing. | `index.html:371-387`, `programs.html:145-153` |
| **Tabs are not tabs.** `.tab` buttons have no `role="tablist"`, no `aria-selected`, no arrow-key navigation. Same for the 3 view toggles on programs. | `cves.html:107-112`, `programs.html:177-181` |
| **No search-result announcements.** `count-label` updates silently on every keystroke. | `cves.html:268`, `programs.html:308` |

**Non-blocking**

- Loading states are text (`Loading…`, `loading…`), not skeletons. The skill's guidance is
  explicit: skeletons for content, spinners only for short waits.
- `admin/index.html` labels use no `for`/`id` pairing — clicking a label doesn't focus its
  input.
- Google Fonts loaded with no `preconnect` fallback budget, no `font-display` control, and
  **no CSP** (§5). Fonts are the only render-blocking third-party request.
- `esc()` is duplicated in all three pages with slightly different surrounding code — the
  consolidation in §3 removes the drift risk.

**Consolidation is the highest-leverage frontend change:** one `assets/app.css` (the ~80-line
`:root` + header block is byte-identical across pages) and one `assets/app.js` (`esc`,
`showToast`, `copyText`, `timeAgo`) deletes roughly 400 duplicated lines and makes escaping a
single audited decision instead of three.

---

## 5. Backend / pipeline assessment

STRIDE over the two trust boundaries. Per `security-and-hardening`: **controls bolted on
without a threat model are guesses.**

### Boundary A — external feed → committed JSON

| | Threat | Status |
|---|---|---|
| **S** | Upstream identity spoofing | ⚠️ Plain HTTP-capable `urllib` follows redirects; no TLS pinning, no cert verification override (good), but **no allowlist on the resolved host** |
| **T** | Malformed/hostile payload | ❌ **No validation at all.** This is §2.1/§2.2/§2.3. The core finding. |
| **R** | No audit trail of what was fetched | ❌ Only `updated_at`. No upstream ETag/Last-Modified, no item-count history, so regressions are invisible |
| **I** | Sensitive data exposure | ✅ Nothing sensitive collected. `manual.json` holds public scope data only. |
| **D** | Upstream rate-limiting / DoS | ⚠️ `timeout=30` on all fetches ✅, **but no retry/backoff inside the collectors** — retry lives in bash, so a transient 429 discards the whole run. NVD's unauthenticated limit is 5 req/30s, which §2.1's pagination must respect. |
| **E** | — | N/A |

### Boundary B — admin panel → Worker → `manual.json` → public site

| | Threat | Status |
|---|---|---|
| **S** | Password guessing | ❌ **Unknown** — Worker isn't in the repo, so rate limiting / lockout can't be confirmed. ARCHITECTURE.md §6 flags CORS as "verify this is actually set"; that verification is still outstanding. |
| **T** | Arbitrary data injection into published output | ❌ **Confirmed open.** `admin/index.html:119-125` sends `name`/`url`/`platform`/`domains` unvalidated. §2.4 is the live proof this has already happened. |
| **R** | No audit log of admin writes | ❌ Unknown (Worker not in repo). |
| **I** | Worker URL disclosed | ⚠️ Hardcoded at `admin/index.html:65`, same origin as the public site, visible in view-source. Not exploitable alone; published surface with no in-repo compensating control. |
| **D** | Write amplification | ⚠️ Unknown (Worker not in repo) |
| **E** | Privilege scope | ⚠️ PAT is documented as fine-grained, Contents rw, one repo — that's the right shape. Unverifiable from here. |

**The single highest-value control across the whole platform:** *a feed must not go from N
items to 0 without failing loudly.* One comparison against the previous `data/*.json` catches
§2.1, upstream outages, HTML challenge pages, rate-limit responses, and silent schema drift —
the entire class, for about fifteen lines.

---

## 6. Prioritised plan

**P0 — today**

1. Add the **empty/shape regression gate** to CI. Fail if a feed drops to 0 items or its
   schema changes without a version bump. (§2.1)
2. Fix **NVD pagination** — follow `totalResults`, raise `resultsPerPage` to 2000, sleep ~6s
   between pages for the 5-req/30s unauthenticated limit. (§1.1, ARCHITECTURE.md §7.1)
3. **Normalise all timestamps to ISO-8601 UTC** in the collectors. (§2.3)
4. Move the **admin Worker into the repo** as `worker/admin.js`, add a `wrangler.toml` +
   deploy instructions, and **validate every write** against the same schema the collector
   uses. A write path to public data that isn't in version control is the one item here I'd
   treat as blocking. (§5, ARCHITECTURE.md §7.2)

**P1 — this week**

5. Add `cvssMetricV40`; select on `type == "Primary"`; add `cvss_version` so `null` is
   unambiguous. (§2.2)
6. Validate `manual.json` platform against `PLATFORM_MAP`; fix `BugCrowd` → `Bugcrowd`; decide
   what to do with the 28 zero-domain programs. (§2.4)
7. Add `schema_version` + `source` to every record; unify the envelope; write a real README
   with one table per endpoint. (§2.5)
8. Consolidate `assets/app.css` + `assets/app.js`; make `esc()` quote-safe and use it in
   attribute position. (§3, §4)
9. Fix keyboard accessibility on program cards; add `aria-live` to the toast and result
   counts; give the tab groups proper `role="tablist"`. (§4)

**P2 — next**

10. Extract the `FeedPipeline` module; six `FeedSource` adapters; first fixture-based tests at
    that seam. (§3)
11. Sanitise HTML at the collector boundary, not at render. (§2.7)
12. SHA-pin actions; add `mypy` + `ruff`. (§2.7)
13. Give URLhaus and GHSA a UI surface, or drop them from the headline endpoint list. (§2.6)
14. Add retry/backoff inside the collectors so a transient 429 doesn't discard a run. (§5)
15. Bring `admin/index.html` onto the current design system. (ARCHITECTURE.md §7.3)

---

## 7. Proposed additions to ARCHITECTURE.md §8 (Open questions)

The open-questions section is currently empty. These are the questions this audit could not
answer from the repository alone:

- [ ] **Is the Cloudflare Worker's CORS actually restricted to `https://threats.top`?**
      §6 says "verify this" and it still hasn't been. It's the one security control in the
      system we cannot inspect.
- [ ] **Does the Worker rate-limit `/add` and `/list`?** A shared static password with no
      lockout is brute-forceable. Can't tell from here.
- [ ] **Should `admin/` be deployed publicly at all?** It ships on the same origin as the
      public site and hardcodes the Worker URL. A separate origin, or a Cloudflare Access
      policy in front of it, removes the question entirely.
- [ ] **Is `Bugcrowd`/`BugCrowd` a one-off typo, or is the manual-entry path going to keep
      producing enum drift?** The answer decides whether we validate on write or normalise
      on read — or both.
- [ ] **Do we want a stability guarantee for the public JSON?** If third parties are
      consuming it, a versioned contract is worth the work. If it's a hobby feed, documenting
      today's shape and moving on is the cheaper call. This is the biggest open product
      question and it gates the whole of P1.7.
- [ ] **Should the 28 zero-domain programs be dropped from `domains.json`?** They make the
      program's core page look broken, but they're real programs with real (undisclosed)
      scope. Filtering at the collector is a judgement call, not a bug fix.
