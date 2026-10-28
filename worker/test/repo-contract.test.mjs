/**
 * Repository contract. These expectations run against the in-memory fake here;
 * the D1 adapter that must mirror them is exercised by the Task 12 integration.
 *
 *     node --test worker/test/repo-contract.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { createFakeRepo } from "./fake-repo.mjs";

const NOW = "2026-10-28T12:00:00Z";
const HOUR = 3_600_000;

async function seedCustomer(repo, email = "ada@example.com") {
  return repo.upsertCustomer({
    id: "cus_1",
    email,
    name: "Ada Lovelace",
    phone: null,
    now: NOW,
  });
}

async function seedOrder(repo, overrides = {}) {
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
    tx_ref: "0xabc123:def-456",
    note: null,
    status: "pending",
    created_at: NOW,
    updated_at: NOW,
    reviewed_at: null,
    reviewed_by: null,
    review_note: null,
    ip_hash: "a".repeat(64),
    user_agent_hash: "b".repeat(64),
    ...overrides,
  };
  await repo.insertOrder(order);
  return order;
}

async function seedSubscription(repo, overrides = {}) {
  const subscription = {
    id: "sub_1",
    customer_id: "cus_1",
    plan: "pro",
    status: "active",
    started_at: NOW,
    expires_at: "2027-01-28T12:00:00Z",
    source_order_id: "ord_1",
    note: null,
    created_at: NOW,
    updated_at: NOW,
    ...overrides,
  };
  await repo.insertSubscription(subscription);
  return subscription;
}

test("settings round-trip with typed numbers", async () => {
  const repo = createFakeRepo();
  const settings = await repo.getSettings();
  assert.equal(settings.pro_monthly_cents, 3900);
  assert.equal(settings.stix_rate_per_min, 600);
  assert.equal(settings.support_email, "nestho@icloud.com");

  await repo.putSetting("pro_monthly_cents", 4900);
  assert.equal((await repo.getSettings()).pro_monthly_cents, 4900);
});

test("customers upsert case-insensitively and keep their id", async () => {
  const repo = createFakeRepo();
  const first = await seedCustomer(repo);
  const second = await repo.upsertCustomer({
    id: "cus_2",
    email: "ADA@Example.com",
    name: "Ada L.",
    phone: "+44 20 7946 0958",
    now: "2026-10-29T12:00:00Z",
  });

  assert.equal(second.id, first.id);
  assert.equal(second.name, "Ada L.");
  assert.equal(second.phone, "+44 20 7946 0958");
  assert.equal(second.created_at, NOW);
  assert.equal(second.updated_at, "2026-10-29T12:00:00Z");
  assert.equal((await repo.findCustomerByEmail("ada@EXAMPLE.com")).id, first.id);
  assert.equal(await repo.findCustomerByEmail("nobody@example.com"), null);
  assert.equal((await repo.getCustomer(first.id)).email, "ada@example.com");
});

test("customers list and search by name or email", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await repo.upsertCustomer({
    id: "cus_2",
    email: "grace@example.com",
    name: "Grace Hopper",
    phone: null,
    now: NOW,
  });

  const all = await repo.listCustomers({ limit: 10, offset: 0 });
  assert.equal(all.total, 2);
  assert.equal(all.items.length, 2);

  const found = await repo.listCustomers({ search: "grace", limit: 10, offset: 0 });
  assert.equal(found.total, 1);
  assert.equal(found.items[0].email, "grace@example.com");
});

test("orders insert, look up, and reject duplicates", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  const order = await seedOrder(repo);

  assert.equal((await repo.findOrderByCode(order.code)).id, order.id);
  assert.equal((await repo.findOrderByTx("usdt_trc20", order.tx_ref)).id, order.id);
  assert.equal((await repo.getOrder(order.id)).status, "pending");
  assert.equal(await repo.findOrderByCode("TH-XXXXX-XXXXX"), null);

  await assert.rejects(
    seedOrder(repo, { id: "ord_2", code: "TH-ABCDE-23457" }),
    (error) => error.code === "DUPLICATE_TX",
  );
  await assert.rejects(
    seedOrder(repo, { id: "ord_3", tx_ref: "another-ref-1" }),
    (error) => error.code === "DUPLICATE_CODE",
  );
});

test("orders filter, search, and paginate", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);
  await seedOrder(repo, {
    id: "ord_2",
    code: "TH-ABCDE-23457",
    tx_ref: "second-ref-01",
    status: "approved",
    created_at: "2026-10-29T12:00:00Z",
    updated_at: "2026-10-29T12:00:00Z",
  });
  await repo.upsertCustomer({
    id: "cus_2",
    email: "grace@example.com",
    name: "Grace Hopper",
    phone: null,
    now: NOW,
  });
  await seedOrder(repo, {
    id: "ord_3",
    code: "TH-ABCDE-23458",
    tx_ref: "third-ref-001",
    customer_id: "cus_2",
    email: "grace@example.com",
    created_at: "2026-10-30T12:00:00Z",
    updated_at: "2026-10-30T12:00:00Z",
  });

  const pending = await repo.listOrders({ status: "pending", limit: 10, offset: 0 });
  assert.equal(pending.total, 2);
  assert.deepEqual(pending.items.map((row) => row.id), ["ord_3", "ord_1"]);

  const searched = await repo.listOrders({ search: "grace", limit: 10, offset: 0 });
  assert.equal(searched.total, 1);
  assert.equal(searched.items[0].id, "ord_3");

  const page = await repo.listOrders({ limit: 1, offset: 1 });
  assert.equal(page.total, 3);
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0].id, "ord_2");

  const mine = await repo.listOrders({ customer_id: "cus_1", limit: 10, offset: 0 });
  assert.equal(mine.total, 2);
});

test("marking an order records the review", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);

  const approved = await repo.markOrder("ord_1", {
    status: "approved",
    reviewed_at: "2026-10-29T09:00:00Z",
    reviewed_by: "admin",
    review_note: "Seen on Tronscan",
    updated_at: "2026-10-29T09:00:00Z",
  });

  assert.equal(approved.status, "approved");
  assert.equal(approved.reviewed_by, "admin");
  assert.equal(approved.review_note, "Seen on Tronscan");
  assert.equal((await repo.getOrder("ord_1")).reviewed_at, "2026-10-29T09:00:00Z");
});

test("the active subscription is the latest unexpired one", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);
  await seedSubscription(repo, {
    id: "sub_old",
    status: "expired",
    expires_at: "2026-09-01T00:00:00Z",
  });
  await seedSubscription(repo, {
    id: "sub_revoked",
    status: "revoked",
    expires_at: "2027-06-01T00:00:00Z",
  });
  await seedSubscription(repo);

  const active = await repo.activeSubscriptionFor("cus_1", NOW);
  assert.equal(active.id, "sub_1");
  assert.equal(await repo.activeSubscriptionFor("cus_1", "2027-02-01T00:00:00Z"), null);
});

test("subscriptions list joins the customer and licence prefix", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);
  await seedSubscription(repo);
  await repo.insertLicense({
    id: "lic_1",
    subscription_id: "sub_1",
    customer_id: "cus_1",
    key_hash: "c".repeat(64),
    key_prefix: "ABCD1234",
    status: "active",
    created_at: NOW,
    last_used_at: null,
    revoked_at: null,
  });

  const listed = await repo.listSubscriptions({ limit: 10, offset: 0 });
  assert.equal(listed.total, 1);
  assert.equal(listed.items[0].customer_email, "ada@example.com");
  assert.equal(listed.items[0].license_prefix, "ABCD1234");

  const active = await repo.listSubscriptions({ status: "active", limit: 10, offset: 0 });
  assert.equal(active.total, 1);
  const revoked = await repo.listSubscriptions({ status: "revoked", limit: 10, offset: 0 });
  assert.equal(revoked.total, 0);
});

test("licences are found by hash, rotated, and revoked", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);
  await seedSubscription(repo);

  const license = await repo.insertLicense({
    id: "lic_1",
    subscription_id: "sub_1",
    customer_id: "cus_1",
    key_hash: "c".repeat(64),
    key_prefix: "ABCD1234",
    status: "active",
    created_at: NOW,
    last_used_at: null,
    revoked_at: null,
  });

  assert.equal((await repo.findLicenseByHash(license.key_hash)).id, "lic_1");
  assert.equal(await repo.findLicenseByHash("d".repeat(64)), null);
  assert.equal((await repo.licenseForSubscription("sub_1")).id, "lic_1");

  await repo.touchLicense("lic_1", "2026-10-29T12:00:00Z");
  assert.equal((await repo.findLicenseByHash(license.key_hash)).last_used_at, "2026-10-29T12:00:00Z");

  assert.equal(await repo.revokeLicenses("sub_1", "2026-10-30T12:00:00Z"), 1);
  const revoked = await repo.findLicenseByHash(license.key_hash);
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.revoked_at, "2026-10-30T12:00:00Z");
  assert.equal(await repo.revokeLicenses("sub_1", "2026-10-30T12:00:00Z"), 0);
  assert.equal(await repo.licenseForSubscription("sub_1"), null);
});

test("audit entries append and list newest first", async () => {
  const repo = createFakeRepo();
  await repo.audit({ at: "2026-10-28T10:00:00Z", actor: "admin", action: "login", target: "admin", detail: null });
  await repo.audit({ at: "2026-10-28T11:00:00Z", actor: "admin", action: "approve", target: "ord_1", detail: "3 months" });

  const page = await repo.listAudit({ limit: 1, offset: 0 });
  assert.equal(page.total, 2);
  assert.equal(page.items[0].action, "approve");
  const older = await repo.listAudit({ limit: 1, offset: 1 });
  assert.equal(older.items[0].action, "login");
});

test("rate limits are fixed windows", async () => {
  const repo = createFakeRepo();
  const window = 1_700_000_000;

  assert.equal(await repo.hitRate("order:ip", window, 3), true);
  assert.equal(await repo.hitRate("order:ip", window, 3), true);
  assert.equal(await repo.hitRate("order:ip", window, 3), true);
  assert.equal(await repo.hitRate("order:ip", window, 3), false);
  assert.equal(await repo.hitRate("order:ip", window + 3600, 3), true);
});

test("login failures are counted only inside the window", async () => {
  const repo = createFakeRepo();
  await repo.recordLogin({ at: "2026-10-28T11:50:00Z", ip_hash: "a".repeat(64), ok: false });
  await repo.recordLogin({ at: "2026-10-28T11:55:00Z", ip_hash: "a".repeat(64), ok: true });
  await repo.recordLogin({ at: "2026-10-28T11:58:00Z", ip_hash: "a".repeat(64), ok: false });
  await repo.recordLogin({ at: "2026-10-28T10:00:00Z", ip_hash: "a".repeat(64), ok: false });
  await repo.recordLogin({ at: "2026-10-28T11:58:00Z", ip_hash: "b".repeat(64), ok: false });

  assert.equal(await repo.recentFailures("a".repeat(64), "2026-10-28T11:45:00Z"), 2);
  assert.equal(await repo.recentFailures("a".repeat(64), "2026-10-28T09:00:00Z"), 3);
  assert.equal(await repo.recentFailures("c".repeat(64), "2026-09-01T00:00:00Z"), 0);
});

test("stats reflect orders, entitlement, and monthly revenue", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo);
  await seedOrder(repo, {
    id: "ord_2",
    code: "TH-ABCDE-23457",
    tx_ref: "second-ref-01",
    status: "approved",
    months: 1,
    amount_cents: 3900,
    reviewed_at: "2026-10-20T12:00:00Z",
    updated_at: "2026-10-20T12:00:00Z",
  });
  await seedSubscription(repo);
  await seedSubscription(repo, {
    id: "sub_soon",
    status: "active",
    expires_at: "2026-11-02T12:00:00Z",
    started_at: "2026-10-02T12:00:00Z",
    source_order_id: "ord_2",
  });

  const stats = await repo.stats(NOW, Date.parse(NOW) - 30 * 24 * HOUR);
  assert.equal(stats.pending_orders, 1);
  assert.equal(stats.active_subscriptions, 2);
  assert.equal(stats.expiring_soon, 1);
  assert.equal(stats.customers, 1);
  assert.equal(stats.orders_30d, 2);
  assert.equal(stats.revenue_cents_30d, 3900);
  assert.equal(stats.mrr_cents, 7800);
});

test("pruning removes abandoned orders, old attempts, and old windows", async () => {
  const repo = createFakeRepo();
  await seedCustomer(repo);
  await seedOrder(repo, { created_at: "2026-01-01T00:00:00Z" });
  await seedOrder(repo, {
    id: "ord_2",
    code: "TH-ABCDE-23457",
    tx_ref: "second-ref-01",
    status: "approved",
    created_at: "2026-01-02T00:00:00Z",
  });
  await repo.recordLogin({ at: "2026-01-01T00:00:00Z", ip_hash: "a".repeat(64), ok: false });
  await repo.hitRate("order:ip", 1_600_000_000, 5);

  await repo.prune({
    ordersBefore: "2026-06-01T00:00:00Z",
    attemptsBefore: "2026-06-01T00:00:00Z",
    windowsBefore: 1_700_000_000,
  });

  const { total } = await repo.listOrders({ limit: 10, offset: 0 });
  assert.equal(total, 1);
  assert.equal(await repo.recentFailures("a".repeat(64), "2020-01-01T00:00:00Z"), 0);
  assert.equal(await repo.hitRate("order:ip", 1_600_000_000, 5), true);
});
