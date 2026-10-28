/**
 * Public API and router behaviour, including CORS, limits, and licence auth.
 *
 *     node --test worker/test/public-api.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { licensePrefix } from "../src/codes.mjs";
import { createApp } from "../src/index.mjs";
import { hashLicense } from "../src/license.mjs";
import { createFakeRepo } from "./fake-repo.mjs";

const NOW = "2026-10-28T12:00:00Z";
const NOW_MS = Date.parse(NOW);
const IP_SALT = "ip-salt";
const LICENSE_SALT = "license-salt";

function makeApp(repo, overrides = {}) {
  return createApp({
    repo,
    env: {
      ALLOWED_ORIGINS: "https://threats.top,http://localhost:8080",
      SITE_ORIGIN: "https://threats.top",
      IP_HASH_SALT: IP_SALT,
      LICENSE_SALT,
      ...overrides,
    },
    now: () => NOW_MS,
  });
}

const request = (path, init) => new Request(`https://api.threats.top${path}`, init);

function post(path, body, headers = {}) {
  return request(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cf-connecting-ip": "203.0.113.7",
      "user-agent": "QA/1.0",
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const orderBody = (overrides = {}) => ({
  name: "Ada Lovelace",
  email: "Ada@Example.COM",
  phone: "+44 20 7946 0958",
  method: "usdt_trc20",
  months: 3,
  tx_ref: "0xabc123:def-456",
  note: "",
  company: "",
  ...overrides,
});

async function seedLicense(repo, { licenseStatus = "active", subscriptionStatus = "active", expiresAt = "2026-11-28T12:00:00Z" } = {}) {
  await repo.upsertCustomer({
    id: "cus_1",
    email: "ada@example.com",
    name: "Ada Lovelace",
    phone: null,
    now: NOW,
  });
  await repo.insertSubscription({
    id: "sub_1",
    customer_id: "cus_1",
    plan: "pro",
    status: subscriptionStatus,
    started_at: NOW,
    expires_at: expiresAt,
    source_order_id: null,
    note: null,
    created_at: NOW,
    updated_at: NOW,
  });
  const key = "THREATS-PRO-0123456789ABCDEFGHJK";
  await repo.insertLicense({
    id: "lic_1",
    subscription_id: "sub_1",
    customer_id: "cus_1",
    key_hash: await hashLicense(key, LICENSE_SALT),
    key_prefix: licensePrefix(key),
    status: licenseStatus,
    created_at: NOW,
    last_used_at: null,
    revoked_at: licenseStatus === "revoked" ? NOW : null,
  });
  return key;
}

test("health reports schema version", async () => {
  const response = await makeApp(createFakeRepo()).handle(request("/api/health"));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, "ok");
  assert.equal(body.schema, 1);
});

test("config exposes the wallets and price but no internals", async () => {
  const response = await makeApp(createFakeRepo()).handle(request("/api/config"));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.pro_monthly_cents, 3900);
  assert.deepEqual(body.plan_months, [1, 3, 12]);
  assert.deepEqual(body.methods, ["usdt_trc20", "btc"]);
  assert.equal(body.wallets.usdt_trc20, "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2");
  assert.equal(body.wallets.btc, "bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq");
  assert.equal("order_retention_days" in body, false);
  assert.equal("stix_rate_per_min" in body, false);
});

test("CORS allows the site, refuses strangers, and answers preflight", async () => {
  const app = makeApp(createFakeRepo());

  const allowed = await app.handle(request("/api/config", { headers: { origin: "https://threats.top" } }));
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://threats.top");
  assert.equal(allowed.headers.get("access-control-allow-credentials"), "true");

  const blocked = await app.handle(request("/api/config", { headers: { origin: "https://evil.example" } }));
  assert.equal(blocked.status, 403);
  assert.equal(blocked.headers.get("access-control-allow-origin"), null);

  const preflight = await app.handle(
    request("/api/orders", {
      method: "OPTIONS",
      headers: {
        origin: "http://localhost:8080",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    }),
  );
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-origin"), "http://localhost:8080");
  assert.match(preflight.headers.get("access-control-allow-methods"), /POST/);

  const noOrigin = await app.handle(request("/api/config"));
  assert.equal(noOrigin.status, 200);
  assert.equal(noOrigin.headers.get("access-control-allow-origin"), null);
});

test("creating an order stores a claim and returns payment details", async () => {
  const repo = createFakeRepo();
  const response = await makeApp(repo).handle(post("/api/orders", orderBody()));

  assert.equal(response.status, 201);
  const body = await response.json();
  assert.match(body.order.code, /^TH-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
  assert.equal(body.order.status, "pending");
  assert.equal(body.order.amount_cents, 11700);
  assert.equal(body.order.method, "usdt_trc20");
  assert.equal(body.order.wallet, "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2");
  assert.equal(body.order.months, 3);

  const stored = await repo.findOrderByCode(body.order.code);
  assert.equal(stored.email, "ada@example.com");
  assert.equal(stored.ip_hash.length, 64);
  assert.equal(stored.user_agent_hash.length, 64);
  assert.notEqual(stored.ip_hash, "203.0.113.7");
  assert.equal(stored.ip_hash, (await repo.listOrders()).items[0].ip_hash);
});

test("the honeypot is accepted and never stored", async () => {
  const repo = createFakeRepo();
  const response = await makeApp(repo).handle(post("/api/orders", orderBody({ company: "Spam Corp" })));

  assert.equal(response.status, 201);
  const body = await response.json();
  assert.match(body.order.code, /^TH-/);
  assert.equal((await repo.listOrders()).total, 0);
});

test("the same transaction cannot claim two orders", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);

  assert.equal((await app.handle(post("/api/orders", orderBody()))).status, 201);
  const duplicate = await app.handle(post("/api/orders", orderBody({ email: "grace@example.com" })));

  assert.equal(duplicate.status, 409);
  assert.equal((await duplicate.json()).error.code, "duplicate_tx");
});

test("six orders in an hour from one address are refused", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);

  for (let i = 0; i < 5; i += 1) {
    const response = await app.handle(post("/api/orders", orderBody({ tx_ref: `ref-000${i}-abcdef` })));
    assert.equal(response.status, 201);
  }

  const limited = await app.handle(post("/api/orders", orderBody({ tx_ref: "ref-999999-abcdef" })));
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).error.code, "rate_limited");
  assert.ok(limited.headers.get("retry-after"));

  const other = await app.handle(
    post("/api/orders", orderBody({ tx_ref: "ref-other-abcdef" }), { "cf-connecting-ip": "198.51.100.9" }),
  );
  assert.equal(other.status, 201);
});

test("invalid orders list the offending fields", async () => {
  const app = makeApp(createFakeRepo());
  const response = await app.handle(post("/api/orders", orderBody({ name: "A", method: "card", tx_ref: "x" })));

  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error.code, "invalid");
  assert.ok(body.error.fields.name);
  assert.ok(body.error.fields.method);
  assert.ok(body.error.fields.tx_ref);
});

test("malformed and oversized bodies are refused", async () => {
  const app = makeApp(createFakeRepo());

  const bad = await app.handle(post("/api/orders", "{"));
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, "invalid_json");

  const big = await app.handle(post("/api/orders", orderBody({ note: "x".repeat(20_000) })));
  assert.equal(big.status, 413);

  const wrongType = await app.handle(
    request("/api/orders", {
      method: "POST",
      headers: { "content-type": "text/plain", "cf-connecting-ip": "203.0.113.7" },
      body: "hello",
    }),
  );
  assert.equal(wrongType.status, 415);
});

test("order lookup needs the matching email", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);
  const created = await (await app.handle(post("/api/orders", orderBody()))).json();

  const found = await app.handle(
    post("/api/orders/lookup", { code: created.order.code.toLowerCase(), email: "ADA@example.com" }),
  );
  assert.equal(found.status, 200);
  const body = await found.json();
  assert.equal(body.order.code, created.order.code);
  assert.equal(body.order.status, "pending");
  assert.equal(body.order.amount_cents, 11700);

  const wrong = await app.handle(
    post("/api/orders/lookup", { code: created.order.code, email: "grace@example.com" }),
  );
  assert.equal(wrong.status, 404);

  const missing = await app.handle(post("/api/orders/lookup", { code: "TH-ABCDE-23456", email: "ada@example.com" }));
  assert.equal(missing.status, 404);
});

test("licence endpoints reject missing, malformed, revoked, and expired keys", async () => {
  const repo = createFakeRepo();
  const app = makeApp(repo);
  const key = await seedLicense(repo);

  const missing = await app.handle(request("/api/pro/me"));
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).error.code, "license_missing");

  const malformed = await app.handle(
    request("/api/pro/me", { headers: { authorization: "Bearer THREATS-PRO-short" } }),
  );
  assert.equal(malformed.status, 401);
  assert.equal((await malformed.json()).error.code, "license_invalid");

  const revoked = await app.handle(
    request("/api/pro/me", { headers: { authorization: `Bearer ${key}` } }),
  );
  assert.equal(revoked.status, 200);

  await repo.revokeLicenses("sub_1", NOW);
  const afterRevoke = await app.handle(
    request("/api/pro/me", { headers: { authorization: `Bearer ${key}` } }),
  );
  assert.equal(afterRevoke.status, 401);
  assert.equal((await afterRevoke.json()).error.code, "license_revoked");

  const expiredRepo = createFakeRepo();
  const expiredKey = await seedLicense(expiredRepo, { expiresAt: "2026-10-01T00:00:00Z" });
  const expired = await makeApp(expiredRepo).handle(
    request("/api/pro/me", { headers: { authorization: `Bearer ${expiredKey}` } }),
  );
  assert.equal(expired.status, 401);
  assert.equal((await expired.json()).error.code, "license_expired");
});

test("a valid licence reports plan, expiry, and limits", async () => {
  const repo = createFakeRepo();
  const key = await seedLicense(repo);

  const response = await makeApp(repo).handle(
    request("/api/pro/me", { headers: { authorization: `Bearer ${key.toLowerCase()}` } }),
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.plan, "pro");
  assert.equal(body.status, "active");
  assert.equal(body.expires_at, "2026-11-28T12:00:00Z");
  assert.equal(body.days_left, 31);
  assert.equal(body.key_prefix, "01234567");
  assert.equal(body.limits.stix_rate_per_min, 600);
  assert.equal((await repo.findLicenseByHash(await hashLicense(key, LICENSE_SALT))).last_used_at, NOW);
});

test("STIX is not served without a licence", async () => {
  const response = await makeApp(createFakeRepo()).handle(request("/api/stix"));
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("www-authenticate"), "Bearer");
});

test("unknown routes and methods are refused", async () => {
  const app = makeApp(createFakeRepo());

  const missing = await app.handle(request("/api/nope"));
  assert.equal(missing.status, 404);

  const wrong = await app.handle(request("/api/config", { method: "DELETE" }));
  assert.equal(wrong.status, 405);
  assert.ok(wrong.headers.get("allow"));
});

test("internal failures do not leak details", async () => {
  const repo = createFakeRepo();
  repo.getSettings = async () => {
    throw new Error("D1_ERROR: secret table name");
  };
  const response = await makeApp(repo).handle(request("/api/config"));

  assert.equal(response.status, 500);
  const body = await response.json();
  assert.equal(body.error.code, "server_error");
  assert.doesNotMatch(JSON.stringify(body), /D1_ERROR|secret table/);
});
