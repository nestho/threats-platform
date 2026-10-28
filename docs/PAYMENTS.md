# Pro payments and entitlements runbook

_Last reviewed: 2026-10-29. Companion to the design in
[`docs/superpowers/specs/2026-10-28-pro-subscriptions-design.md`](superpowers/specs/2026-10-28-pro-subscriptions-design.md)._

Pro is sold directly, in USDT (TRC20) or BTC, and activated by hand. There is
no payment processor, no card data, and no automatic on-chain verification. This
file is the procedure the owner follows for every order: what to check, what to
click, how to recover, and what never to do.

Operational data lives in Cloudflare D1. It is **never committed to git** and
never appears in the public feeds or `/data/*.json`.

---

## 1. Surfaces

| Surface | URL | Purpose |
|---|---|---|
| Pricing | `https://threats.top/saas.html` | Plan terms and what Pro unlocks today |
| Checkout | `https://threats.top/subscribe.html` | Wallets, order form, status lookup |
| Admin | `https://threats.top/admin/` | Sign-in, review, subscriptions, audit |
| Pro console | `https://threats.top/pro.html` | Buyer activates a licence and exports STIX |
| API | `https://api.threats.top/api/*` | Orders, licence checks, admin actions, STIX |

The Worker is `worker/`, named `threats-platform-api`, with the D1 binding
`DB`. The static site stays on GitHub Pages; the pages call the API
cross-origin from an allowlist (`https://threats.top`, plus
`http://localhost:8080` for local QA).

---

## 2. Configuration and secrets

Values in this section are set with Wrangler and never written to the
repository, a chat, or a ticket.

| Secret | What it protects | Rotation effect |
|---|---|---|
| `ADMIN_PASSWORD_HASH` | Admin sign-in password | Only the password changes |
| `TOTP_SECRET` | Authenticator second factor | Existing sessions stay valid until expiry |
| `SESSION_SECRET` | Session cookie signature | **All admin sessions are invalidated** |
| `LICENSE_SALT` | Licence key hashes | **Every issued licence stops verifying** |
| `IP_HASH_SALT` | Hashed client IP and user agent | Old hashes no longer correlate |

Generate the admin credential locally, never in chat:

```bash
node scripts/admin-credentials.mjs
```

The script prints a password (once), a hash in the stored
`pbkdf2_sha256$210000$…` format, a base32 TOTP secret, and an `otpauth://` URI
for an authenticator app. It writes nothing anywhere. Pipe each value into
Wrangler from `worker/`:

```bash
cd worker
npx wrangler secret put ADMIN_PASSWORD_HASH
npx wrangler secret put TOTP_SECRET
```

`SESSION_SECRET`, `LICENSE_SALT`, and `IP_HASH_SALT` are random 32-byte
base64url values; generate them with `openssl rand -base64 48` and set each the
same way. Rotating `LICENSE_SALT` requires re-issuing every active licence
(see §8); do not rotate it casually.

The price, wallet addresses, STIX rate limit, support address, and order
retention are settings in D1, editable in **Settings** in the admin panel. Each
change is audited and takes effect immediately; no deploy is needed.

---

## 3. Daily order review

1. Sign in at `https://threats.top/admin/` with the password and the current
   6-digit authenticator code. The session lasts 8 hours.
2. Open **Orders** and filter to `pending`. Each row shows the order code,
   buyer name and email, months paid for, amount, method, and transaction
   reference.
3. Open the order and verify the transfer on-chain (§4 or §5).
4. If the transfer matches, choose **Approve**. Confirm the month count. The
   Worker extends or creates the subscription and, for a new subscriber,
   issues one licence key.
5. Copy the licence message shown after approval and send it to the buyer from
   the support address. **The key is shown once.** Only its hash and an
   8-character prefix are stored.
6. If the transfer does not match, choose **Reject** and give a short reason
   (for example "no matching transfer", "amount short by 12 USDT", "wrong
   network"). The buyer can submit a corrected order; a rejected order can be
   reviewed again.

A buyer can check their own status at `subscribe.html` with the order code and
the email they used. That lookup never reveals the licence key.

### What "approve" does automatically

- Starts a new subscription at `max(now, existing active expiry)` and adds the
  ordered months. Renewals never lose paid days.
- Issues a licence only when the customer did not already have an active
  subscription. For a renewal, the existing key keeps working.
- Marks the order `approved`, records the reviewer and note, and appends an
  `order.approve` entry to the audit log.
- Duplicate `(method, transaction reference)` pairs are refused at order time,
  so the same transfer cannot back two orders.

---

## 4. Verify a USDT (TRC20) payment

The checkout shows the address `TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2`. Confirm
all of the following before approving:

- **Network is TRON (TRC20).** A transfer on Ethereum, BSC, or any other chain
  to the same-looking address is a different asset and is not recoverable by
  us. The order form records the method the buyer selected; if they sent on the
  wrong network, reject and explain.
- **Token contract is the canonical USDT TRC20 contract**
  (`TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`). Scam tokens reuse the ticker; check
  the contract, not the symbol.
- **Recipient is the address above**, character for character.
- **Status is success and the transaction is confirmed.** Tronscan shows
  confirmations; wait for the transfer to be solid before issuing a key.
- **Amount covers the invoice.** The invoice is in USD cents; the buyer sends
  the equivalent in USDT. There is no price oracle, so a materially short
  transfer is a human decision: reject with the shortfall in the note, or
  approve with a note explaining the accepted amount. Do not silently approve a
  large shortfall.
- **Timestamp is after the order was created.** An older transfer used for a
  new order is a duplicate attempt; reject it.

Useful explorer: `https://tronscan.org/#/transaction/<txid>`.

---

## 5. Verify a BTC payment

The checkout shows the native SegWit address
`bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq`. Confirm all of the following:

- **Network is Bitcoin mainnet**, and the address starts `bc1q`. A transfer on
  another chain or to a wrapped asset is not a BTC payment.
- **Recipient is the address above**, character for character. SegWit
  addresses are case-insensitive but checksummed; copy and compare the whole
  string.
- **The transaction is confirmed.** One confirmation is normally enough for a
  small order; wait for more before issuing a long term or an unusually large
  order. An unconfirmed transaction can still be replaced.
- **Amount covers the invoice at the rate the buyer accepted.** The buyer sees
  a USD price, not a BTC amount. Volatility is the owner's call at review
  time: approve at the value received, or reject and ask the buyer to make up
  the difference.
- **Timestamp is after the order was created**, and the receiving output is
  the wallet above (not an internal change address).

Useful explorer: `https://mempool.space/tx/<txid>`.

### Edge cases

| Case | Action |
|---|---|
| Buyer reports a transfer with no order | Ask them to submit the order form with the transaction reference first; approve that order |
| Amount short | Reject with the shortfall; ask for a corrected order for the difference |
| Amount over | Approve and note the overpayment; refund the difference only if the buyer asks (§9) |
| Same transaction submitted twice | The API refuses it (`duplicate_tx`). If it appears as a second order under a different reference, reject the second |
| Wrong network or wrong token | Reject; explain that we cannot recover it |
| Suspicious or sanctioned origin | Reject, keep the note factual, and do not engage further |
| Buyer claims a licence was never received | Check **Customers** and the audit log for the approval; if the key was issued, rotate it (§8) and send the new key |

---

## 6. Subscriptions

Open **Subscriptions** to see every entitlement with its customer, status,
start, expiry, licence prefix, and source order.

- **Extend** — adds 1–24 months from the later of now and the current expiry.
  Use this for a renewal whose order you approved, or to correct a month count.
- **Rotate key** — revokes every active licence on the subscription and issues
  one new key, shown once. Use it when the buyer lost the key, suspects it
  leaked, or the key appeared in a public place. Access does not lapse: the
  subscription is unchanged.
- **Revoke** — sets the subscription to `revoked` and revokes its licences
  immediately. A required note is stored in the audit log. Use it for a
  confirmed non-payment, a fraud reversal, or an abuse report. Revocation is
  not deletion; the history stays visible.
- **Grant Pro** — creates a subscription and licence without an order, for a
  comp, a refund-in-kind, or a support correction. A note is recommended. One
  active subscription per customer: extend an existing one instead of stacking.

Live keys are bearer credentials for `/api/pro/me` and `/api/stix`. Revocation
takes effect on the next request; there is no cache to wait out.

---

## 7. Licence handling

- Shape: `THREATS-PRO-` plus 20 Crockford base32 characters (100 bits).
- Stored: a salted SHA-256 hash plus the 8-character display prefix. The full
  key cannot be recovered from D1.
- Shown once, at approval, rotation, or comp grant. If it is lost before it is
  delivered, rotate it.
- The Pro console stores a key on the device only when the buyer ticks
  **Remember this device**; otherwise it lives in `sessionStorage` and is
  cleared when the tab closes. **Forget this device** clears both.
- `/api/pro/me` reports plan, expiry, days left, masked prefix, and the STIX
  rate limit. `/api/stix` returns a STIX 2.1 bundle and is rate-limited per
  licence.

---

## 8. Rotating the licence salt

Rotating `LICENSE_SALT` invalidates every stored hash at once. Only do it if
the salt is suspected compromised.

1. Export the subscription list (§10) so you have the customer emails.
2. Set the new `LICENSE_SALT` and deploy the secret.
3. Rotate the licence for each active subscription in the admin panel, one at
   a time, and send each buyer the new key.
4. Each rotation is recorded in the audit log, but the action takes no note;
   keep a short operations note outside git if the reason matters.

There is no bulk re-issue API on purpose: rotation is a deliberate, auditable
action per subscription.

---

## 9. Refunds

Crypto transfers are irreversible. A refund is a discretionary transfer from
the owner's wallet to the address the buyer paid from, and is never automatic.

- Refund only after the entitlement has been revoked and only if the licence
  was not used to export. The panel does not show usage; query
  `licenses.last_used_at` in D1 before deciding.
- Send to the original sending address; ask the buyer to confirm it in
  writing. Do not send to a new address on the strength of an email change.
- The network fee is deducted from the refund, or paid on top by the owner;
  state which in the message.
- Record the decision (order code, amount, transaction reference of the
  refund, reason) in the order note or audit log. Keep the buyer's confirmation
  outside git with the rest of the operational correspondence.
- Chargebacks do not exist for these transfers; a refund is a courtesy and a
  risk decision, not a consumer right we can adjudicate.

---

## 10. Data, backup, retention

D1 is the system of record for orders, customers, subscriptions, licences,
sessions metadata, and the audit log. Nothing here is committed to git.

### Export before risky work

```bash
cd worker
npx wrangler d1 export threats-platform --remote --output ./threats-$(date +%F).sql
```

Treat the file as sensitive: it contains names, emails, phone numbers, and
order history. Do not commit it, attach it to a public issue, or leave it in a
shared directory. `.gitignore` does not cover arbitrary filenames, so keep it
outside the repository or delete it after use.

### Inspect without the panel

```bash
npx wrangler d1 execute threats-platform --remote \
  --command "SELECT code, status, created_at FROM orders ORDER BY created_at DESC LIMIT 20"
```

### Restore

D1 Time Travel keeps a rolling 30-day history of the database. Find a
bookmark, then restore it:

```bash
npx wrangler d1 time-travel info threats-platform --remote --timestamp 2026-10-28T12:00:00Z
npx wrangler d1 time-travel restore threats-platform --remote --bookmark <bookmark>
```

A restore replaces the whole database at that point in time; anything written
after the bookmark is lost. For a single bad row, prefer a targeted `UPDATE`
or a correction through the panel over a whole-database restore.

To rebuild an empty database, apply migrations and then load an export:

```bash
npx wrangler d1 migrations apply threats-platform --remote
npx wrangler d1 execute threats-platform --remote --file ./threats-2026-10-29.sql
```

### Retention

The Worker runs a daily cron at 03:17 UTC:

- unpaid pending orders older than `order_retention_days` (default 180) are
  deleted;
- login attempts older than 30 days are deleted;
- rate-limit windows older than one day are deleted.

The retention window is a setting (31–3650 days). Shortening it deletes older
unpaid orders on the next run; export first if the history matters. Approved,
rejected, and subscription-linked orders are not touched by the cron.

Subscription and licence records are not pruned by the cron. Remove them only
through the panel (revoke) unless you are deliberately rebuilding the database.

---

## 11. Monitoring

- `https://api.threats.top/api/health` returns
  `{"status":"ok","schema":1,"time":"…"}`. It is unauthenticated and cheap.
- The admin **Overview** shows pending orders, active Pro count, MRR,
  subscriptions expiring within 7 days, orders and revenue over 30 days, and
  the customer count.
- Cloudflare observability is on for the Worker. A 5xx in the dashboard is a
  Worker or D1 fault, not a buyer error; the static site is unaffected and the
  checkout reports that orders are unavailable.
- A 503 `admin_unconfigured` means one of `ADMIN_PASSWORD_HASH`, `TOTP_SECRET`,
  or `SESSION_SECRET` is missing. Set the secret and retry.
- A 401 `session_expired` in the panel is normal after 8 hours or a
  `SESSION_SECRET` rotation; sign in again.

---

## 12. Incident steps

### Suspected admin compromise

1. Rotate `SESSION_SECRET` (all sessions end), then rotate
   `ADMIN_PASSWORD_HASH` and `TOTP_SECRET`.
2. Read the **Audit** tab and export the orders. Look for unexpected
   `settings.update`, `subscription.comp`, `subscription.rotate`, or
   `subscription.revoke` entries and unusual source IP hashes (the panel does
   not show raw IPs; use `login_attempts` only through a targeted query if
   needed).
3. Revoke subscriptions or rotate licences created during the window.
4. Restore the database to a pre-incident bookmark only if the audit log and
   data are both suspect; a restore discards later legitimate orders.

### Licence leaked publicly

Rotate that subscription's licence. Do not revoke the subscription unless the
buyer is also the leaker; access is the same subscription with a new key.
Search the audit log and `last_used_at` for unexpected export volume.

### Buyers report checkout failures

Check `/api/health`, then the Worker logs. The static site stays up. If D1 is
unavailable, orders fail with a 5xx and the page shows the support address; do
not ask buyers to pay by message without an order, because there will be no
record to approve.

### Accidental approval with the wrong term

Extend again for the shortfall, or revoke and re-approve a corrected order.
Never edit D1 rows by hand for a term change that the panel can do; the audit
log is the evidence that the change was deliberate.

---

## 13. Deployment checklist

```bash
cd worker
npx wrangler d1 create threats-platform          # first time only; copy the id
# put the id in wrangler.toml `database_id`
npx wrangler d1 migrations apply threats-platform --remote
npx wrangler secret put SESSION_SECRET
npx wrangler secret put LICENSE_SALT
npx wrangler secret put IP_HASH_SALT
npx wrangler secret put ADMIN_PASSWORD_HASH      # from ../scripts/admin-credentials.mjs
npx wrangler secret put TOTP_SECRET              # from the same script
npx wrangler deploy
curl -fsS https://api.threats.top/api/health
```

Local rehearsal, with a throwaway database:

```bash
cd worker
npx wrangler d1 migrations apply threats-platform --local
npx wrangler dev --local
# in another shell, with the same vars in worker/.dev.vars:
node scripts/smoke.mjs http://127.0.0.1:8787
```

The smoke script creates an order, signs in with a generated TOTP, approves the
order, checks `/api/pro/me` and `/api/stix`, revokes the subscription, and
confirms the licence is rejected. It uses a disposable local database only.

The deploy comment in `worker/wrangler.toml` lists the same steps; keep the two
in sync when the secret set changes.
