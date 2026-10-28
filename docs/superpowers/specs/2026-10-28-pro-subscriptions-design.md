# Pro subscriptions: crypto checkout, manual approval, admin panel

**Status:** approved 2026-10-28
**Branch:** `feat/pro-subscriptions`
**Supersedes:** the retired `/admin-api/*` Worker described in `docs/SAAS-ARCHITECTURE.md` §4

## 1. Problem

Pro is sold on `saas.html` as a waitlist with manual invoices. There is no
checkout, no order record, no way to see who paid, and no entitlement. The
retired admin Worker wrote to `main` with a long-lived token and was replaced
because that bypassed review. Subscription state is operational data, not
published threat intelligence, so it must live in a store outside git.

## 2. Goals

- A public payment page showing the two existing wallets (USDT TRC20, BTC) and
  a form that records a real order.
- An admin panel where the owner verifies the transfer and enables Pro, with
  every action audited.
- A Pro entitlement that does something real on day one: a license key that
  unlocks a STIX 2.1 export of the public feeds.
- No card data, no third-party payment processor, no new runtime dependency.

## 3. Non-goals

- Private watchlists, feed correlation, webhook alerting, and email delivery.
  They stay marked as roadmap on the pricing page and are not charged for.
- Automatic on-chain verification. A human checks the transaction.
- Multi-admin roles. One owner account; the audit log records `admin`.
- Gating static pages. Everything under `/data/` stays public.

## 4. Decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Store | Cloudflare D1 | documented Phase 2 path; relational queries for orders and stats |
| Runtime | one Worker replacing `worker/admin.js` | the old route is retired; a second worker would duplicate auth |
| Admin auth | password + TOTP | no identity provider; secrets set by the owner, never in git |
| Payment | USDT TRC20 + BTC, manual check | existing wallets; no processor or card data |
| Pro delivery | license key + STIX export | real, buildable today; watchlists are roadmap |
| Phone | optional | email is sufficient to verify a payment |

USDT is on TRON (the `T…` address); BTC is native SegWit (`bc1q…`). The payment
page labels both networks and warns that a wrong-network transfer is not
recoverable by us.

## 5. Architecture

```
subscribe.html ──POST /api/orders──▶ Worker ──▶ D1 (orders, customers)
      │                                  │
      └─GET /api/orders/:code────────────┘
admin/index.html ──/api/admin/*──▶ Worker (session cookie + CSRF) ──▶ D1
pro.html ──Bearer license──▶ /api/pro/me, /api/stix ──▶ D1 + /data/*.json
```

- Worker name `threats-platform-api`, route `threats.top/api/*`, D1 binding `DB`.
- Static UI stays on GitHub Pages. The Worker never writes to git.
- The STIX endpoint fetches `/data/cves.json`, `/data/iocs.json`, and
  `/data/ransomware.json` from `SITE_ORIGIN` (default `https://threats.top`) with
  a five-minute edge cache. It never trusts client input.
- A daily cron prunes orders that were never paid, login attempts, and expired
  rate-limit windows.

## 6. Data model (D1, `worker/migrations/0001_init.sql`)

| Table | Purpose | Key constraints |
| --- | --- | --- |
| `settings` | wallets, prices, limits, seed rows | `key` primary key |
| `customers` | one row per email | `email` unique, `COLLATE NOCASE` |
| `orders` | payment claims | `code` unique, `(method, tx_ref)` unique, status check |
| `subscriptions` | entitlement windows | status `active/expired/revoked`, index on `(status, expires_at)` |
| `licenses` | issued keys | `key_hash` unique, status `active/revoked` |
| `audit_log` | every admin mutation | append-only |
| `login_attempts` | lockout evidence | indexed by IP hash and time |
| `rate_limit` | fixed windows | `(key, window_start)` primary key |

Settings seeded with: `pro_monthly_cents=3900`, `usdt_trc20_address`,
`btc_address`, `stix_rate_per_min=600`, `support_email`,
`order_retention_days=180`.

Amounts are USD cents configured server-side. The buyer sends the equivalent in
the chosen asset; the admin compares it to the invoice amount on the explorer.
No external price feed is consulted, so volatility is a human decision at
review time.

### Order state machine

```
pending ──approve──▶ approved
   │                    │
   ├──reject──▶ rejected│
   └──cron────▶ expired │
                        ▼
              subscription active
```

Approval from `pending` or `rejected` is allowed (a rejected order may be
re-reviewed after a mistake). `approved` and `expired` are terminal for the
order. Approving creates or extends a subscription and issues one license.

### Subscription rules

- Expiry starts at `max(now, current active expiry)` so renewals never lose
  paid days.
- One active subscription per customer at a time; extending applies to it.
- Revoking sets status `revoked` and revokes the license immediately.
- Re-issuing a license revokes the previous key and returns the new one once.

### License keys

`THREATS-PRO-` plus 20 Crockford base32 characters (100 bits), shown once.
Only a SHA-256 hash and an 8-character display prefix are stored. The key is
the bearer credential for `/api/pro/me` and `/api/stix`; revocation takes
effect on the next request.

## 7. API

All responses are JSON. Errors use `{ "error": { "code": "...", "message": "..." } }`.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/api/health` | none | liveness and schema version |
| GET | `/api/config` | none | wallets, prices, plan lengths |
| POST | `/api/orders` | none | rate-limited, honeypot, unique txid |
| POST | `/api/orders/lookup` | code + email | status lookup |
| GET | `/api/pro/me` | license bearer | plan, expiry, limits |
| GET | `/api/stix` | license bearer | STIX 2.1 bundle, 600/min |
| POST | `/api/admin/login` | password + TOTP | sets session cookie |
| POST | `/api/admin/logout` | session | clears cookie |
| GET | `/api/admin/session` | session | identity + CSRF token |
| GET | `/api/admin/orders` | session | filter, search, paginate |
| GET | `/api/admin/orders/:id` | session | full order |
| POST | `/api/admin/orders/:id/approve` | session + CSRF | creates entitlement |
| POST | `/api/admin/orders/:id/reject` | session + CSRF | note required |
| GET | `/api/admin/subscriptions` | session | filter, search |
| POST | `/api/admin/subscriptions` | session + CSRF | comp grant |
| POST | `/api/admin/subscriptions/:id/extend` | session + CSRF | months 1-24 |
| POST | `/api/admin/subscriptions/:id/revoke` | session + CSRF | note required |
| POST | `/api/admin/subscriptions/:id/license` | session + CSRF | rotate key |
| GET | `/api/admin/customers` | session | search |
| GET | `/api/admin/audit` | session | paginated |
| GET | `/api/admin/stats` | session | MRR, counts, expiring |
| GET | `/api/admin/settings` | session | all settings |
| PUT | `/api/admin/settings` | session + CSRF | validated whitelist |
| GET | `/api/admin/export` | session | CSV orders or subscriptions |

Order creation validates name (2-80), email (RFC-shaped, ≤254), optional phone
(5-32, phone punctuation), months ∈ {1,3,12}, method ∈ {usdt_trc20,btc},
transaction reference (8-128, `[A-Za-z0-9:_-]`), note ≤500. A hidden `company`
field must be empty. Limits: 5 orders per IP per hour, 10 login attempts per IP
per 15 minutes.

## 8. Security

- Password is stored as `pbkdf2_sha256$210000$salt$hash` in the
  `ADMIN_PASSWORD_HASH` secret; verification is constant-time.
- TOTP is RFC 6238, SHA-1, 6 digits, 30-second step, ±1 step, with the last
  accepted step persisted so a code cannot be replayed.
- Session: HMAC-SHA256 signed, HttpOnly, Secure, SameSite=Strict, 8-hour TTL,
  bound to a CSRF token returned by `/api/admin/session`. Mutations also reject
  a mismatched `Origin`.
- Secrets: `ADMIN_PASSWORD_HASH`, `TOTP_SECRET`, `SESSION_SECRET`,
  `LICENSE_SALT`, `IP_HASH_SALT` — Worker secrets only, never git.
- Orders store hashed IP and user agent, never the raw values. No PII in logs.
- The admin page is public HTML but every read and write is enforced by the API.
- CSV export neutralises spreadsheet formulas (leading `= + - @`).
- Rate limits are fixed-window in D1; the STIX limit is per license.

## 9. UI

- `subscribe.html`: plan, wallet cards with copy buttons and network warnings,
  form, confirmation with order code, status lookup. States for submitting,
  invalid, rate-limited, and offline.
- `pro.html`: activate a key (optionally remembered on the device), show plan,
  expiry, days remaining, masked key, STIX download, `curl` example, forget
  device. A revoked or expired key gets a clear message.
- `admin/index.html`: login, dashboard (pending, active, MRR, expiring, monthly
  orders), orders with filters/search/detail/approve/reject, subscriptions with
  extend/revoke/rotate/comp, customers, audit log, settings, CSV export. Uses
  the existing console shell and type scale; noindex.
- `saas.html`: Pro card becomes Subscribe; feature list matches what is actually
  delivered; watchlists/alerting are labelled roadmap; FAQ explains manual
  verification, crypto-only payment, and the licence.

## 10. Testing

- Node unit tests: validation and normalization, order code and key generation,
  PBKDF2/TOTP RFC vectors, session sign/verify and tamper rejection, CSRF,
  expiry and extension math, state transitions, rate limits, CSV escaping, STIX
  bundle shape and deterministic IDs, settings validation.
- Handler tests against an in-memory repository implementing the same interface
  as the D1 adapter.
- Schema test applies the migration with the `sqlite3` CLI and asserts tables
  and indexes.
- Local integration: `wrangler dev --local`, apply migrations, run a scripted
  end-to-end flow (create order, log in with a generated TOTP, approve, activate
  a key, fetch STIX) against real D1 SQL.
- Browser QA at 1440 and 390; Impeccable clean; existing feed, Python, and unit
  gates stay green.

## 11. Deployment and access

1. Create D1 `threats-platform`, apply migrations, capture the database id.
2. Set `SESSION_SECRET`, `LICENSE_SALT`, `IP_HASH_SALT` (server-generated).
3. Owner runs `node scripts/admin-credentials.mjs`, which prints the password
   hash and a TOTP enrollment URI, and pipes both into `wrangler secret put`.
   Neither value is shown in chat or committed.
4. Deploy `threats-platform-api` on `threats.top/api/*`; delete the retired
   `/admin-api/*` route and its unused secrets.
5. Verify `/api/health`, create a real test order, approve it with the owner's
   credentials, and confirm the key unlocks STIX.
6. Document verification, refunds, revocation, rotation, D1 backups, and
   retention in `docs/PAYMENTS.md`.

## 12. Rollout

One pull request through the protected `main` branch. If the Worker is unhealthy,
the static site is unaffected; the subscribe page reports that orders are
unavailable and shows the support address. Reverting the PR restores the
previous pages; the D1 data stays intact and can be exported.
