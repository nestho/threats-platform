# Constraints

_Last reviewed: 2026-10-28. Companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) (what the system is) and [`docs/CONTRACT.md`](docs/CONTRACT.md) (the public data shape). This file is the quality bar: what "good enough to publish" means, with the command that produces each verdict._

**Status: enforced.** `main` is protected by the `protect-main` ruleset with no bypass actors. Every change, including scheduled data, arrives as a pull request that must pass **Feed data**, **Unit tests**, and **Python tests**. The default Actions token is read-only, and Pages serves `threats.top` over enforced HTTPS.

Unlike the 2026-09 version of this file, these are no longer advisory: a direct push to `main` is rejected by GitHub, not just discouraged by convention.

---

## Floor (always enforced)

- No suppression comments: `# noqa`, `# type: ignore`, `# nosemgrep`.
- No unimplemented stubs: `raise NotImplementedError`, bare `except:`, or `except: pass` that converts a failure into silence.
- No skipped or deleted tests without a reason in the commit message.
- No secrets in source. Bot credentials live in GitHub Actions variables and secrets; the retired Worker holds none.
- **Every collector exits non-zero on failure.** A zero exit means the file is valid, and the validator is what decides validity.
- **No demo, sample, or placeholder data.** A missing feed is an error state, not a reason to render invented rows.
- **No invented geography.** The live map places only records whose feed carries a country. Phishing hosts are placed by the registered IP country (DB-IP Lite) and labelled as hosting, never as attacker origin. There are no source-to-destination arcs, because no publishable feed records attacker origin.
- This file does not get weakened to make a change pass.

---

## Enforced with numbers

| Dimension | Rule | Checked by | Runs at |
|---|---|---|---|
| **Feed completeness** | A feed must not drop from N>0 items to 0 | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Feed regression** | A feed must not lose >50% of its items versus the base commit | `python3 scripts/validate_feeds.py --against <sha>` | cron **+ PR** |
| **Feed schema** | Every record matches the contract in the validator | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **NVD completeness** | `items_parsed` == `items_available` | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Provenance** | Every feed carries `source`, `source_url`, `updated_at`, `schema_version` | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Timestamps** | Every date is ISO-8601 UTC (`Z`) or date-only | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Enums** | `platform`, Wiz `type`, and vendor are canonical | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Schema version** | `schema_version` equals the expected version for that file | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **URL schemes** | Published links are `http(s)`; `javascript:` and relative payloads are rejected | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Defanging** | Published phishing and ransomware URLs start `hxxp` | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Sentinels** | No `"Unknown"` standing in for a null | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Status consistency** | `status.json` item counts, timestamps, and `overall` agree with the feeds | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **Demo data** | No demo markers in feeds or public HTML | `python3 scripts/validate_feeds.py` | cron **+ PR** |
| **XSS: escaping** | `esc()` emits no raw `< > " '` and is injective | `node --test assets` | **PR**, local |
| **Retired Worker** | Every legacy admin route fails closed with 410 | `node --test worker` | **PR**, local |
| **Timestamp rules** | Normalisation handles every upstream format and refuses unknown zones | `python3 scripts/normalize.py` | **PR**, local |
| **Python logic** | Collectors, status, orchestrator, and validator behave as specified | `python3 -m unittest discover -s scripts/tests -t scripts` | **PR**, local |
| **PR gate** | The three checks above are required by the ruleset | `bash scripts/setup-ruleset.sh` (verifies) | repo setting |
| **No bypass** | `bypass_actors` is empty; direct pushes are rejected | `gh api repos/nestho/threats-platform/rulesets` | repo setting |
| **Token hardening** | Default workflow token is read-only and cannot approve PRs | `gh api repos/nestho/threats-platform/actions/permissions/workflow` | repo setting |
| **Action pinning** | Every `uses:` is pinned to a full commit SHA | `grep -rn "uses:" .github/workflows/` | review |

A dimension with a number and no command is an aspiration, not a constraint.

---

## Measured, not yet enforced

| Metric | Today (2026-10-28) | Direction |
|---|---|---|
| Sources collected | **12** | add only with a real upstream |
| Published feeds | **13** (`+ status.json`) | every feed has a UI surface |
| Python unit tests | **169** | must not fall |
| JavaScript unit tests | **72** | must not fall |
| Runtime dependencies | **0** | must stay 0 |
| GitHub Actions pinned to a SHA | **9 of 9** | must stay 9 of 9 |
| Paths to `main` that bypass a check | **0** | must stay 0 |
| Pages HTTPS enforced | **yes** (`threats.top`) | must stay yes |
| Source files git treats as binary | **0** | must stay 0 |
| Required human approvals | **0** | raise to 1 with a second maintainer |

---

## Deliberate non-constraints

These look like violations and are not. Do not "fix" them.

- **No framework, build step, or bundler.** Static HTML plus stdlib Python is why this costs nothing to run and has no frontend supply chain.
- **No `requirements.txt` entries.** Runtime dependencies are zero on purpose. Dev-only tools, if added, belong in `requirements-dev.txt`.
- **`data/*.json` is committed.** It is the database and the audit trail. Do not gitignore it or "clean up" feed churn.
- **Zero required approvals.** GitHub forbids self-approval, and the repository has one maintainer plus a bot. The PR plus three checks is the gate; a fourth human gate would deadlock. This is a staffing constraint, not a security preference.
- **Wiz runs every 30 days.** Its publication rate is monthly. Running it hourly would imply freshness it does not have.
- **The Worker is retired, not deleted.** Keeping it in the tree with tests makes the removed write path explicit and prevents it from being silently reintroduced.
- **No client-side pagination beyond what exists.** Client-side paging over committed JSON is correct at this scale.

---

## Exceptions

_None._

Format for new rows: `| ID | Rule | Path | Reason | Owner | Expires |` — 90-day expiry.

---

## Open decisions

1. **Second maintainer / human approval.** Set `required_approving_review_count` to 1 when someone else can review. The script documents the change.
2. **JSON Schema files.** The contract is enforced in Python and generated into `docs/CONTRACT.md`. A `data/*.schema.json` set would let consumers validate without Python.
3. **Browser end-to-end and accessibility tests.** `node --test` covers `esc()` and the Worker, not a rendered page. A headless smoke test over every page would close the highest-value remaining gap.
4. **Python type checking and linting.** `mypy` and `ruff` are dev dependencies. The project has held runtime dependencies at zero; a separate `requirements-dev.txt` keeps that property.
5. **Worker removal.** Delete `worker/` once the Phase 2 D1 API exists and the retirement page is no longer needed.

---

## Guarding the bar itself

At review time, watch the diff for five moves: a threshold was moved, a test got easier, a checker was silenced, work was left unfinished, or a new exception appeared. Tightening this file should be silent; loosening it should be loud.
