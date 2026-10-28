/**
 * Admin API: login, lockout, CSRF, approvals, licence lifecycle, settings,
 * exports, and audit.
 *
 *     node --test worker/test/admin-api.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { hashPassword, totpCode } from "../src/auth.mjs";
import { createApp } from "../src/index.mjs";
import { createFakeRepo } from "./fake-repo.mjs";

const NOW = "2026-10-28T12:00:00Z";
const NOW_MS = Date.parse(NOW);
const PASSWORD = "correct horse battery";
const TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const TOTP_CODE = totpCode(TOTP_SECRET, NOW_MS);

async function setup() {
  const repo = createFakeRepo();
  const env = {
    ALLOWED_ORIGINS: "https://threats.top,http://localhost:8080",
    SITE_ORIGIN: "https://threats.top",
    IP_HASH_SALT: "ip-salt",
    LICENSE_SALT: "license-salt",
    SESSION_SECRET: "session-secret",
    ADMIN_PASSWORD_HASH: await hashPassword(PASSWORD, { iterations: 1000 }),
    TOTP_SECRET,
  };
  const app = createApp({ repo, env, now: () => NOW_MS });
  return { repo, env, app };
}

function login(app, { password = PASSWORD, code = TOTP_CODE, ip = "203.0.113.7" } = {}) {
  return app.handle(
    new Request("https://api.threats.top/api/admin/login", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": ip },
      body: JSON.stringify({ password, code }),
    }),
  );
}

async function signIn(app) {
  const response = await login(app);
  assert.equal(response.status, 200, await response.clone().text());
  const body = await response.json();
  return { cookie: response.headers.get("set-cookie").split(";")[0], csrf: body.csrf, body };
}

function call(app, path, { method = "GET", session, body, headers = {} } = {}) {
  return app.handle(
    new Request(`https://api.threats.top${path}`, {
      method,
      headers: {
        ...(session ? { cookie: session.cookie, "x-csrf-token": session.csrf } : {}),
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        "cf-connecting-ip": "203.0.113.7",
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

async function seedOrder(repo, overrides = {}) {
  await repo.upsertCustomer({
    id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: "+44 20 7946 0958",
    now: NOW,
  });
  const order = {
    id: "ord_1",
    code: "TH-ABCDE-23456",
    customer_id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: null,
    plan: "pro",
    months: 3,
    amount_cents: 11700,
    currency: "USD",
    method: "usdt_trc20",
    tx_ref: "tx-ref-0001",
    note: null,
    status: "pending",
    created_at: NOW,
    updated_at: NOW,
    ip_hash: "a".repeat(64),
    user_agent_hash: "b".repeat(64),
    ...overrides,
  };
  await repo.insertOrder(order);
  return order;
}

test("login needs both the password and the authenticator code", async () => {
  const { app } = await setup();

  const wrongPassword = await login(app, { password: "nope" });
  assert.equal(wrongPassword.status, 401);
  assert.equal((await wrongPassword.json()).error.code, "invalid_credentials");

  const wrongCode = await login(app, { code: "000000" });
  assert.equal(wrongCode.status, 401);

  const ok = await login(app);
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.admin.sub, "admin");
  assert.match(body.csrf, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(body.expires_at, "2026-10-28T20:00:00Z");
  const cookie = ok.headers.get("set-cookie");
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=28800/);

  const replay = await login(app);
  assert.equal(replay.status, 401, "a used TOTP step must not work twice");
});

test("ten failures lock the address for fifteen minutes", async () => {
  const { app } = await setup();

  for (let i = 0; i < 10; i += 1) {
    assert.equal((await login(app, { password: `wrong-${i}` })).status, 401);
  }

  const locked = await login(app);
  assert.equal(locked.status, 429);
  assert.equal((await locked.json()).error.code, "login_locked");
  assert.equal(locked.headers.get("retry-after"), "900");

  const otherAddress = await login(app, { ip: "198.51.100.9" });
  assert.equal(otherAddress.status, 200);
});

test("admin sessions round-trip and expire", async () => {
  const { repo, env, app } = await setup();
  const session = await signIn(app);

  const info = await call(app, "/api/admin/session", { session });
  assert.equal(info.status, 200);
  assert.equal((await info.json()).csrf, session.csrf);

  assert.equal((await call(app, "/api/admin/session")).status, 401);

  const tampered = await call(app, "/api/admin/session", {
    headers: { cookie: `${session.cookie}x` },
  });
  assert.equal(tampered.status, 401);

  const later = createApp({ repo, env, now: () => NOW_MS + 9 * 3600 * 1000 });
  const expired = await call(later, "/api/admin/session", { session });
  assert.equal(expired.status, 401);
});

test("admin reads require a session", async () => {
  const { app } = await setup();
  for (const path of ["/api/admin/orders", "/api/admin/stats", "/api/admin/settings", "/api/admin/export"]) {
    assert.equal((await call(app, path)).status, 401, path);
  }
});

test("mutations need the CSRF token and an allowed origin", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo);
  const session = await signIn(app);
  const path = "/api/admin/orders/ord_1/approve";

  const noToken = await call(app, path, {
    method: "POST",
    headers: { cookie: session.cookie, "content-type": "application/json" },
    body: {},
  });
  assert.equal(noToken.status, 403);
  assert.equal((await noToken.json()).error.code, "csrf_failed");

  const wrongToken = await call(app, path, {
    method: "POST",
    session,
    body: {},
    headers: { "x-csrf-token": "x".repeat(22) },
  });
  assert.equal(wrongToken.status, 403);

  const foreign = await call(app, path, {
    method: "POST",
    session,
    body: {},
    headers: { origin: "https://evil.example" },
  });
  assert.equal(foreign.status, 403);
  assert.equal((await foreign.json()).error.code, "origin_rejected");
});

test("approving creates the subscription, one licence, and an audit entry", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo);
  const session = await signIn(app);

  const response = await call(app, "/api/admin/orders/ord_1/approve", {
    method: "POST",
    session,
    body: { months: 3 },
  });
  assert.equal(response.status, 200);
  const body = await response.json();

  assert.equal(body.order.status, "approved");
  assert.equal(body.order.reviewed_by, "admin");
  assert.equal(body.subscription.expires_at, "2027-01-28T12:00:00Z");
  assert.match(body.license, /^THREATS-PRO-[0-9A-HJKMNP-TV-Z]{20}$/);
  assert.equal(body.key_prefix, body.license.slice(12, 20));
  assert.equal((await repo.findOrderByCode("TH-ABCDE-23456")).status, "approved");
  assert.equal((await repo.listSubscriptions()).total, 1);

  const me = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${body.license}` },
    }),
  );
  assert.equal(me.status, 200);

  const again = await call(app, "/api/admin/orders/ord_1/approve", {
    method: "POST",
    session,
    body: {},
  });
  assert.equal(again.status, 409);

  const detail = await call(app, "/api/admin/orders/ord_1", { session });
  const stored = (await detail.json()).order;
  assert.equal(stored.tx_ref, "tx-ref-0001");
  assert.equal("ip_hash" in stored, false);

  const audit = await call(app, "/api/admin/audit", { session });
  const actions = (await audit.json()).items.map((row) => row.action);
  assert.ok(actions.includes("order.approve"));
});

test("a renewal extends from the later paid expiry", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo);
  const session = await signIn(app);

  const first = await (await call(app, "/api/admin/orders/ord_1/approve", { method: "POST", session, body: {} })).json();
  await repo.insertOrder({
    id: "ord_2",
    code: "TH-ABCDE-23457",
    customer_id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: null,
    plan: "pro",
    months: 1,
    amount_cents: 3900,
    currency: "USD",
    method: "btc",
    tx_ref: "btc-ref-0002",
    note: null,
    status: "pending",
    created_at: NOW,
    updated_at: NOW,
    ip_hash: null,
    user_agent_hash: null,
  });

  const second = await call(app, "/api/admin/orders/ord_2/approve", {
    method: "POST",
    session,
    body: { months: 1 },
  });
  assert.equal(second.status, 200);
  const body = await second.json();
  assert.equal(body.subscription.id, first.subscription.id);
  assert.equal(body.subscription.expires_at, "2027-02-28T12:00:00Z");
  assert.equal(body.license, null);
});

test("rejecting requires a note and a still-open order", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo);
  const session = await signIn(app);

  const noNote = await call(app, "/api/admin/orders/ord_1/reject", {
    method: "POST",
    session,
    body: { note: "  " },
  });
  assert.equal(noNote.status, 400);
  assert.equal((await noNote.json()).error.code, "invalid_note");

  const rejected = await call(app, "/api/admin/orders/ord_1/reject", {
    method: "POST",
    session,
    body: { note: "No matching transfer on chain" },
  });
  assert.equal(rejected.status, 200);
  assert.equal((await rejected.json()).order.status, "rejected");

  const approved = await call(app, "/api/admin/orders/ord_1/approve", {
    method: "POST",
    session,
    body: {},
  });
  assert.equal(approved.status, 200, "a rejected order can be re-reviewed");

  const tooLate = await call(app, "/api/admin/orders/ord_1/reject", {
    method: "POST",
    session,
    body: { note: "changed my mind" },
  });
  assert.equal(tooLate.status, 409);
  assert.equal((await tooLate.json()).error.code, "order_approved");
});

test("a comp grant creates a subscription without an order", async () => {
  const { repo, app } = await setup();
  const session = await signIn(app);

  const response = await call(app, "/api/admin/subscriptions", {
    method: "POST",
    session,
    body: { email: "New@Example.com", name: "New Customer", months: 6, note: "beta partner" },
  });
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.subscription.source_order_id, null);
  assert.equal(body.subscription.status, "active");
  assert.equal(body.subscription.expires_at, "2027-04-28T12:00:00Z");
  assert.equal(body.customer.email, "new@example.com");
  assert.match(body.license, /^THREATS-PRO-/);

  const me = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${body.license}` },
    }),
  );
  assert.equal(me.status, 200);

  const duplicate = await call(app, "/api/admin/subscriptions", {
    method: "POST",
    session,
    body: { email: "new@example.com", months: 1 },
  });
  assert.equal(duplicate.status, 409);

  assert.equal((await repo.listOrders()).total, 0);
});

test("revoking a subscription kills its licence immediately", async () => {
  const { repo, app } = await setup();
  const session = await signIn(app);

  const granted = await (
    await call(app, "/api/admin/subscriptions", {
      method: "POST",
      session,
      body: { email: "ada@example.com", months: 1 },
    })
  ).json();

  const before = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${granted.license}` },
    }),
  );
  assert.equal(before.status, 200);

  const noNote = await call(app, `/api/admin/subscriptions/${granted.subscription.id}/revoke`, {
    method: "POST",
    session,
    body: {},
  });
  assert.equal(noNote.status, 400);

  const revoked = await call(app, `/api/admin/subscriptions/${granted.subscription.id}/revoke`, {
    method: "POST",
    session,
    body: { note: "Refunded in full" },
  });
  assert.equal(revoked.status, 200);
  assert.equal((await revoked.json()).licenses_revoked, 1);

  const after = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${granted.license}` },
    }),
  );
  assert.equal(after.status, 401);
  assert.equal((await after.json()).error.code, "license_revoked");

  const again = await call(app, `/api/admin/subscriptions/${granted.subscription.id}/revoke`, {
    method: "POST",
    session,
    body: { note: "second attempt" },
  });
  assert.equal(again.status, 409);

  assert.equal((await repo.listSubscriptions({ status: "revoked" })).total, 1);
});

test("rotating replaces the key and revokes the old one", async () => {
  const { app } = await setup();
  const session = await signIn(app);

  const granted = await (
    await call(app, "/api/admin/subscriptions", {
      method: "POST",
      session,
      body: { email: "ada@example.com", months: 1 },
    })
  ).json();

  const rotated = await call(app, `/api/admin/subscriptions/${granted.subscription.id}/license`, {
    method: "POST",
    session,
    body: {},
  });
  assert.equal(rotated.status, 200);
  const { license } = await rotated.json();
  assert.notEqual(license, granted.license);

  const oldKey = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${granted.license}` },
    }),
  );
  assert.equal(oldKey.status, 401);

  const newKey = await app.handle(
    new Request("https://api.threats.top/api/pro/me", {
      headers: { authorization: `Bearer ${license}` },
    }),
  );
  assert.equal(newKey.status, 200);
});

test("extending reactivates an expired subscription", async () => {
  const { repo, app } = await setup();
  await repo.upsertCustomer({
    id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: null,
    now: NOW,
  });
  await repo.insertSubscription({
    id: "sub_old",
    customer_id: "cus_1",
    plan: "pro",
    status: "expired",
    started_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-09-01T00:00:00Z",
    source_order_id: null,
    note: null,
    created_at: NOW,
    updated_at: NOW,
  });
  const session = await signIn(app);

  const response = await call(app, "/api/admin/subscriptions/sub_old/extend", {
    method: "POST",
    session,
    body: { months: 2 },
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.subscription.status, "active");
  assert.equal(body.subscription.expires_at, "2026-12-28T12:00:00Z");

  const bad = await call(app, "/api/admin/subscriptions/sub_old/extend", {
    method: "POST",
    session,
    body: { months: 25 },
  });
  assert.equal(bad.status, 400);
});

test("settings are whitelisted, persisted, and audited", async () => {
  const { repo, app } = await setup();
  const session = await signIn(app);

  const initial = await (await call(app, "/api/admin/settings", { session })).json();
  assert.equal(initial.settings.pro_monthly_cents, 3900);
  assert.equal("admin_totp_step" in initial.settings, false);

  const updated = await call(app, "/api/admin/settings", {
    method: "PUT",
    session,
    body: { key: "pro_monthly_cents", value: 4900 },
  });
  assert.equal(updated.status, 200);
  assert.equal((await updated.json()).settings.pro_monthly_cents, 4900);
  assert.equal((await repo.getSettings()).pro_monthly_cents, 4900);
  assert.equal((await (await call(app, "/api/config")).json()).pro_monthly_cents, 4900);

  const unknown = await call(app, "/api/admin/settings", {
    method: "PUT",
    session,
    body: { key: "admin_totp_step", value: 1 },
  });
  assert.equal(unknown.status, 400);

  const invalidWallet = await call(app, "/api/admin/settings", {
    method: "PUT",
    session,
    body: { key: "btc_address", value: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" },
  });
  assert.equal(invalidWallet.status, 400);

  const audit = await (await call(app, "/api/admin/audit", { session })).json();
  assert.ok(audit.items.some((row) => row.action === "settings.update"));
});

test("CSV export neutralises formulas and switches type", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo, { name: "=SUM(A1)" });
  const session = await signIn(app);

  const orders = await call(app, "/api/admin/export?type=orders", { session });
  assert.equal(orders.status, 200);
  assert.match(orders.headers.get("content-type"), /^text\/csv/);
  const csv = await orders.text();
  assert.match(csv, /^Code,Created,Status,Name/);
  assert.match(csv, /'=SUM\(A1\)/);

  const subscriptions = await call(app, "/api/admin/export?type=subscriptions", { session });
  assert.match(await subscriptions.text(), /^Subscription,Email,Plan,Status/);
});

test("stats reflect approvals and money", async () => {
  const { repo, app } = await setup();
  await seedOrder(repo);
  const session = await signIn(app);
  await call(app, "/api/admin/orders/ord_1/approve", { method: "POST", session, body: {} });

  const response = await call(app, "/api/admin/stats", { session });
  const { stats } = await response.json();
  assert.equal(stats.pending_orders, 0);
  assert.equal(stats.active_subscriptions, 1);
  assert.equal(stats.customers, 1);
  assert.equal(stats.orders_30d, 1);
  assert.equal(stats.revenue_cents_30d, 11700);
  assert.equal(stats.mrr_cents, 3900);
});

test("logout clears the session cookie", async () => {
  const { app } = await setup();
  const session = await signIn(app);

  const response = await call(app, "/api/admin/logout", { method: "POST", session, body: {} });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie"), /Max-Age=0/);
});
