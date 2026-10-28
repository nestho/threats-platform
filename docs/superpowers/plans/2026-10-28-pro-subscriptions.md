# Pro Subscriptions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a crypto checkout, an audited admin panel, and a license-key-gated STIX export for Pro, backed by a Cloudflare Worker and D1.

**Architecture:** A single Worker (`threats-platform-api`) on `api.threats.top` owns orders, subscriptions, licenses, sessions, and the STIX export. GitHub Pages keeps serving the static site; the browser calls the API cross-origin with credentials. All SQL lives behind one repository module so handlers stay testable with an in-memory fake; the real SQL is exercised locally through `wrangler dev --local` before deployment.

**Tech Stack:** Cloudflare Workers (ES modules), D1, WebCrypto, vanilla ES modules on the pages, Node's built-in test runner. No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md`

## Global Constraints

- No new runtime dependencies; `requirements.txt` stays empty and no `package.json` is added at the repo root.
- No secrets in git. `.dev.vars` and `.wrangler/` are ignored.
- `main` stays protected; all work lands through one PR with the existing Feed data, Python, Unit, Design, and Sonar checks green.
- No card data is collected. USDT is TRON (TRC20); BTC is native SegWit.
- Pro day-one value is a license key plus `/api/stix`; watchlists and alerting stay labelled roadmap.
- Admin secrets are set by the owner; nothing sensitive appears in chat or commits.
- All public errors use `{ "error": { "code": "...", "message": "..." } }`; no stack traces or PII.

---

### Task 1: Worker scaffold, D1 migration, repository contract

**Files:**
- Modify: `worker/wrangler.toml`
- Delete: `worker/admin.js`
- Create: `worker/migrations/0001_init.sql`
- Create: `worker/src/repo.mjs` (D1 adapter, all SQL)
- Create: `worker/test/schema.test.mjs`
- Create: `worker/test/fake-repo.mjs`

**Interfaces:**
- Produces: `createRepo(db)` returning the methods listed in Task 4; the fake implements the same surface.
- Produces: the schema with tables `settings`, `customers`, `orders`, `subscriptions`, `licenses`, `audit_log`, `login_attempts`, `rate_limit`.

- [ ] Write `0001_init.sql` with the spec's columns, checks, uniques, and indexes; seed `settings` with `pro_monthly_cents=3900`, `usdt_trc20_address=TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2`, `btc_address=bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq`, `stix_rate_per_min=600`, `support_email=nestho@icloud.com`, `order_retention_days=180`.
- [ ] `schema.test.mjs` applies the migration with `sqlite3` to a temp file and asserts every table and index exists, plus that duplicate `(method, tx_ref)` fails.
- [ ] Run `node --test worker/test/schema.test.mjs`; expect pass.
- [ ] Point `wrangler.toml` at `src/index.mjs`, name `threats-platform-api`, custom domain `api.threats.top`, `[d1_databases]` binding `DB` (id filled at deploy), daily cron, no `workers_dev`.
- [ ] Commit.

### Task 2: Auth primitives

**Files:**
- Create: `worker/src/auth.mjs`
- Test: `worker/test/auth.test.mjs`

**Interfaces:**
- Produces: `hashPassword(password) => "pbkdf2_sha256$210000$<salt>$<hash>"`, `verifyPassword(password, stored) => Promise<boolean>`
- Produces: `base32Decode(s)`, `totpCode(secret, timeMs)`, `verifyTotp(secret, code, lastStep) => {ok, step}`
- Produces: `signSession(payload, secret)`, `verifySession(token, secret, nowMs)`, `randomToken(bytes)`, `hashIp(ip, salt)`, `timingSafeEqual(a, b)`

- [ ] Write failing tests: PBKDF2-HMAC-SHA256 vector (`password`/`salt`, 1 iteration → `120fb6cf…17b`), RFC 6238 SHA-1 vector (secret `12345678901234567890`, t=59 → `287082`), wrong code and replayed step rejected, session tamper rejected, expired session rejected, IP hash salted and stable.
- [ ] Run tests; expect import failures.
- [ ] Implement with WebCrypto (`crypto.subtle.deriveBits`, `importKey`, HMAC-SHA256, HMAC-SHA1) and base64url helpers.
- [ ] Run `node --test worker/test/auth.test.mjs`; expect pass.
- [ ] Commit.

### Task 3: Domain rules

**Files:**
- Create: `worker/src/validation.mjs`, `worker/src/codes.mjs`, `worker/src/subscriptions.mjs`, `worker/src/settings.mjs`, `worker/src/csv.mjs`
- Test: `worker/test/domain.test.mjs`

**Interfaces:**
- Produces: `parseOrder(body, settings, now) => {ok, value|errors}`; `parseLookup`, `parseMonths`, `normalizeEmail`
- Produces: `orderCode(random)` (`TH-XXXXX-XXXXX`), `licenseKey(random)` (`THREATS-PRO-` + 20 Crockford chars), `licensePrefix(key)`
- Produces: `extendExpiry(now, currentExpiry, months)`, `subscriptionStatus(expiresAt, now)`, `daysLeft`
- Produces: `defaultSettings`, `validateSetting(key, value)`, `publicConfig(settings)`
- Produces: `toCsv(rows, columns)` with formula neutralisation

- [ ] Write failing tests for every function: email normalisation, name/phone/txid bounds, months whitelist, honeypot, duplicate-free code charset, 100-bit key length, renewal from the later date, expired subscription, settings address/price rejection, CSV injection neutralised.
- [ ] Implement the modules.
- [ ] Run `node --test worker/test/domain.test.mjs`; expect pass.
- [ ] Commit.

### Task 4: D1 repository and in-memory fake

**Files:**
- Modify: `worker/src/repo.mjs`
- Create: `worker/test/fake-repo.mjs`
- Test: `worker/test/repo-contract.test.mjs` (runs the same expectations against the fake; the D1 adapter is verified in Task 12 integration)

**Interfaces:**
- Produces methods: `getSettings`, `putSetting`, `upsertCustomer`, `findCustomerByEmail`, `getCustomer`, `listCustomers`, `insertOrder`, `findOrderByCode`, `findOrderByTx`, `getOrder`, `listOrders`, `markOrder`, `insertSubscription`, `getSubscription`, `activeSubscriptionFor`, `listSubscriptions`, `updateSubscription`, `insertLicense`, `findLicenseByHash`, `licenseForSubscription`, `revokeLicenses`, `touchLicense`, `audit`, `listAudit`, `stats`, `hitRate`, `recordLogin`, `recentFailures`, `prune`

- [ ] Write contract tests: order code lookup, unique txid, status filtering and pagination, customer upsert by case-insensitive email, active subscription lookup, license lookup by hash, fixed-window rate limit, failure counting, stats totals.
- [ ] Implement the fake with deterministic inserts; run tests.
- [ ] Implement the D1 adapter with prepared statements mirroring the fake, including `ON CONFLICT` behaviour.
- [ ] Commit.

### Task 5: HTTP layer, public orders API, Pro API

**Files:**
- Create: `worker/src/http.mjs`, `worker/src/public.mjs`, `worker/src/index.mjs`
- Test: `worker/test/public-api.test.mjs`

**Interfaces:**
- Consumes: `createRepo`, auth, validation, codes, subscriptions, settings.
- Produces: `handleRequest(request, env)`; routes per spec §7; `json`, `fail`, `corsHeaders`, `readJsonBody`.

- [ ] Write failing handler tests with the fake: config hides nothing sensitive; order create returns code/amount/wallet; honeypot silently rejects; duplicate txid 409; 6th order in an hour 429; lookup requires matching email; `/api/pro/me` rejects missing/revoked/expired licences and reports days left; STIX requires a licence.
- [ ] Implement router, CORS allowlist (`https://threats.top`, `http://localhost:8080`, local dev origin), method dispatch, error mapping, `/api/health`.
- [ ] Run `node --test worker/test/public-api.test.mjs`; expect pass.
- [ ] Commit.

### Task 6: STIX 2.1 export

**Files:**
- Create: `worker/src/stix.mjs`
- Modify: `worker/src/public.mjs`
- Test: `worker/test/stix.test.mjs`

**Interfaces:**
- Produces: `uuidv5(name)`, `buildBundle({cves, iocs}) => {type:"bundle", id, objects}` with `vulnerability` for KEV entries, `indicator` for each IOC (defanged pattern, `x_threats_defanged: true`), and one `report`.
- Consumes: `fetchFeed(origin, path, fetchImpl, cache)` with five-minute cache.

- [ ] Write failing tests: stable UUIDs across calls, valid STIX IDs, one vulnerability per KEV, indicators match IOC count up to the cap, patterns use the feed's exact defanged value, bundle timestamps use feed `updated_at`, no claims included.
- [ ] Implement and wire `GET /api/stix` with per-license rate limiting.
- [ ] Run tests; commit.

### Task 7: Admin API

**Files:**
- Create: `worker/src/admin.mjs`
- Modify: `worker/src/index.mjs`
- Test: `worker/test/admin-api.test.mjs`

**Interfaces:**
- Session payload: `{sub:"admin", iat, exp, csrf}`; cookie `admin_session`, HttpOnly, Secure (except dev), SameSite=Strict.
- Produces handlers for login/logout/session/orders/subscriptions/customers/audit/stats/settings/export.

- [ ] Write failing tests: login needs password and TOTP; 10 failures lock out; session cookie round-trips; mutations without CSRF or with a foreign Origin are 403; approve extends from the later expiry, issues one key, marks the order, writes audit; reject needs a note; revoke kills the licence; rotate replaces the key; comp creates a subscription without an order; settings only accept whitelisted keys; CSV escapes formulas; stats reflect the fake.
- [ ] Implement; run tests; commit.

### Task 8: Subscribe page

**Files:**
- Create: `subscribe.html`, `assets/checkout.js`, `assets/checkout.test.mjs`
- Modify: `assets/app.css` only if a shared control is missing

- [ ] Write tests for client helpers: amount formatting, plan labels, error-code copy map, wallet explorer links.
- [ ] Build the page: plan radio group, wallet cards with copy buttons and network warnings, form (name, email, phone optional, method, txid, note, honeypot), submit states, confirmation with order code, lookup form, offline/error states, Plex type, 58ch measure.
- [ ] Browser-test at 1440 and 390 against a local stub API; keyboard and reduced motion.
- [ ] Commit.

### Task 9: Admin panel

**Files:**
- Rewrite: `admin/index.html`
- Create: `assets/admin.js`

- [ ] Login screen (password + TOTP), lockout and error copy.
- [ ] App shell with tabs: Overview, Orders, Subscriptions, Customers, Audit, Settings.
- [ ] Orders: filter/search/paginate, detail dialog with explorer links, approve (months), reject (note), copy licence message after approval.
- [ ] Subscriptions: extend, revoke, rotate key, comp grant; Customers: history; Audit: paginated; Settings: wallets, prices, limits, support email.
- [ ] CSV export via authenticated fetch; session expiry returns to login; all rendering via `textContent`.
- [ ] Browser-test with a local stub session; 1440 and 390; keyboard dialogs.
- [ ] Commit.

### Task 10: Pro console and pricing page

**Files:**
- Create: `pro.html`, `assets/pro.js`
- Modify: `saas.html`, rail links in all pages

- [ ] Pro console: key activation (optional remember), status/expiry/masked key, STIX download, curl example, forget device, clear messages for revoked/expired.
- [ ] Pricing: Pro card becomes Subscribe with day-one benefits; watchlists/alerting labelled roadmap; FAQ covers crypto-only payment, manual verification, licence handling, privacy.
- [ ] Add "Pro console" and "Subscribe" links where they belong; keep every rail consistent.
- [ ] Browser QA; commit.

### Task 11: Documentation and project constraints

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CONSTRAINTS.md`, `ACCESSIBILITY.md`
- Create: `docs/PAYMENTS.md`

- [ ] PAYMENTS runbook: verify TRC20/BTC, approve/refuse, refund policy, key rotation, revoke, D1 export/restore, retention, incident steps.
- [ ] Document the Worker, hostname, D1, secrets, deploy commands, and that no subscription data is in git.
- [ ] Update measured test counts and the CI description.
- [ ] Commit.

### Task 12: Local integration, deploy, production QA, PR

**Files:**
- Create: `worker/scripts/smoke.mjs`, `worker/.dev.vars.example`
- Modify: `.gitignore`

- [ ] `.gitignore`: add `worker/.dev.vars`, `worker/.wrangler/`, `worker/node_modules/`.
- [ ] `wrangler d1 migrations apply threats-platform --local`, `wrangler dev --local --persist`, run the smoke script: create order → login with a generated TOTP → approve → `/api/pro/me` → `/api/stix` → revoke → 401.
- [ ] Create D1 `threats-platform`, apply migrations remotely, set `SESSION_SECRET`, `LICENSE_SALT`, `IP_HASH_SALT`; deploy; `curl https://api.threats.top/api/health`.
- [ ] Owner runs `node scripts/admin-credentials.mjs` and sets `ADMIN_PASSWORD_HASH` and `TOTP_SECRET`; verify login and a real test order, then revoke the test entitlement.
- [ ] Browser QA production pages; Impeccable at 1280 and 390; all gates green; open the PR and wait for confirmation before merging.

## Self-review

- Spec coverage: config/orders/lookup (5), Pro (5-6), admin (7), STIX (6), pages (8-10), security (2, 7), deploy/runbook (11-12), testing (1-7).
- No placeholder steps; every task names files, interfaces, and verification commands.
- Shared names (`createRepo`, `handleRequest`, `signSession`, `extendExpiry`, `licenseKey`) are defined once and reused.
