# Constraints

_Last reviewed: 2026-09-27. Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) (what the
system is) and [`docs/DEEP-ANALYSIS.md`](docs/DEEP-ANALYSIS.md) (what's wrong with it). This
file is the quality bar: what "good enough to ship" means, with numbers._

**Status: Floor active and enforced. The feed-validation dimensions are implemented
and running in CI. Types/lint/secrets/supply-chain are still PROPOSED** — see
§Open Decisions.

Everything in the "Enforced" table below runs with **zero dependencies**, because the
project's defining constraint is `requirements.txt` being empty. The feed gate is
`scripts/validate_feeds.py`; the escaping tests are `node --test`.

---

## Floor (always enforced, no setup required)

- No new suppression comments: `# noqa`, `# type: ignore`, `# nosemgrep`
- No unimplemented stubs: `raise NotImplementedError`, bare `except:`, empty `except: pass`
  that converts a failure into silence
- No skipped or deleted tests without a reason in the commit message
- No secrets in source. Admin password and `GITHUB_TOKEN` are Cloudflare secrets, never in
  this repo.
- **Every collector exits non-zero on failure.** `exit 0` currently means "the file is
  good", which is false — see DEEP-ANALYSIS §2.1. This floor line exists because that
  contract is the project's most dangerous lie.
- This file does not get weakened to make a change pass.

---

## Enforced with numbers

| Dimension | Rule | Checked by | Runs at |
|---|---|---|---|
| **Feed completeness** | A feed must not drop from N>0 items to 0 | `python3 scripts/validate_feeds.py` | CI (pre-commit) |
| **Feed schema** | Every record matches the contract in the validator | `python3 scripts/validate_feeds.py` | CI (pre-commit) |
| **NVD completeness** | `items_parsed` == `items_available` | `python3 scripts/validate_feeds.py` | CI |
| **Timestamps** | Every date field is ISO-8601 UTC (`Z`) or date-only | `python3 scripts/validate_feeds.py` | CI |
| **Enums** | `platform` ∈ canonical set; Wiz `type` ∈ canonical set | `python3 scripts/validate_feeds.py` | CI |
| **Schema version** | `schema_version` == the expected version for that file | `python3 scripts/validate_feeds.py` | CI |
| **Defanging** | Every `urlhaus` URL starts `hxxp`/`hxxps` | `python3 scripts/validate_feeds.py` | CI |
| **Sentinels** | No `"Unknown"` standing in for a null | `python3 scripts/validate_feeds.py` | CI |
| **XSS: escaping** | `esc()` emits no raw `< > " '` and is injective | `node --test assets/app.test.mjs` | pre-commit, CI |
| **Auth boundary** | Worker rejects bad origin/password/payload, fails closed | `node --test worker/admin.test.mjs` | pre-commit, CI |
| **Timestamp rules** | Normalisation handles every upstream format, refuses unknowns | `python3 scripts/normalize.py` | pre-commit |
| Types (Python) | Zero type errors | `mypy scripts/` | pre-commit |
| Lint | Zero errors | `ruff check scripts/` | pre-commit |
| Secrets | No secrets in source | `gitleaks detect --redact --no-banner` | pre-commit, CI |
| Workflow supply chain | Actions pinned to commit SHA | `zizmor scan` | CI |
| Accessibility | Zero critical/serious axe violations | `axe https://threats.top --tags wcag2a,wcag2aa` | post-deploy |
| Project coverage | 0% → **must not fall**; 32 unit tests at the two boundaries | `node --test assets worker` | CI |

Every row names the command that produces the verdict. A dimension with a number and no
command is an aspiration, not a constraint.

**Ratchet note.** There is no line-coverage number yet because there is no Python test
runner — the two suites are `node --test` against the JS boundaries. The count is 32
tests, all passing, covering the two places where a silent failure would be worst: the
XSS escaper and the admin auth boundary. The collectors themselves are covered only by
`validate_feeds.py` running against their real output in CI, which catches shape and
completeness regressions but not logic errors. That gap is real and is listed in
ARCHITECTURE.md §7.12.

---

## Measured, not yet enforced

| Metric | Today (2026-09-27) | Direction |
|---|---|---|
| Copies of `esc()` across HTML pages | **1** (`assets/app.js`) | was 3 — target met |
| Copies of the `:root`/header CSS block | **1** (`assets/app.css`) | was 3 — target met |
| Feeds with a human-facing UI | **5 of 7** | was 4 of 6 (GHSA + Wiz added) |
| Homepage first-paint payload | **282 KB raw / 45 KB gz** | was 1188 / 213 before the pagination fix |
| Runtime dependencies | **0** | must stay 0 |
| `worker/` source in version control | **yes** | was no |

---

## Deliberate non-constraints

These look like violations and are not. Do not "fix" them.

- **No framework, no build step, no bundler.** Static HTML + stdlib Python is the reason
  this project costs nothing to run and has no supply chain. Adding React/Vite/npm to
  "improve" the frontend would be a regression, not an improvement.
- **No `requirements.txt` entries.** The file is empty on purpose (ARCHITECTURE.md §3).
  Dev-only tools (mypy, ruff, pytest) belong in a separate `requirements-dev.txt`.
- **`data/*.json` is committed.** It is the database. Do not add `.gitignore` entries for it
  and do not "clean up" the churn from the hourly feed commits.
- **No pagination in the UI beyond what exists.** 30-per-page client-side paging over a
  ~450KB JSON payload is the right call at this scale.

---

## Exceptions

_None yet._

Format for new rows: `| ID | Rule | Path | Reason | Owner | Expires |` — 90-day expiry,
per the skill's default.

---

## Open Decisions

The feed-validation and escaping rows are implemented and blocking. These remain:

1. **Types/lint/secrets for Python?** `mypy` and `ruff` would be two dev
   dependencies. The project has held `requirements.txt` at zero for its whole life;
   a `requirements-dev.txt` keeps runtime at zero but is still a policy decision.
2. **Block or warn?** Proposed: block on the Floor and every row above; warn on
   types/lint for two weeks if they are added at all.
3. **Accessibility check.** `axe` needs a running URL, so it belongs on a post-deploy
   hook. There is none. Worth standing one up — the keyboard-accessibility work on this
   branch was done by reading, not by testing, and nothing prevents a regression.
4. **Python test runner?** The collectors have no unit tests. `pytest` is one dev
   dependency and would let `normalize.py` and the merge logic in `collector.py` be
   tested against fixtures instead of against live upstreams in CI.

---

## Guarding the bar itself

Per the skill: if the agent writes the code and the checks, the checks prove something. At
review time, watch the diff for the five standard moves — a threshold moved, a test got
easier, a checker got silenced, work left unfinished, or a new exception appeared. Tightening
this file should be silent; loosening it should be loud.
