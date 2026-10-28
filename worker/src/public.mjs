/**
 * Public and licence-authenticated handlers.
 *
 * Each handler receives `{request, env, repo, url, now, ip}` and returns a
 * Response. Validation lives in `validation.mjs`; this file maps domain
 * results onto HTTP and never echoes storage errors.
 */

import { hashIp, randomToken } from "./auth.mjs";
import { orderCode } from "./codes.mjs";
import { bodyFailure, fail, json, readJsonBody } from "./http.mjs";
import { hashLicense, isLicenseShape, parseBearer } from "./license.mjs";
import { publicConfig } from "./settings.mjs";
import { daysLeft, subscriptionStatus, toIso } from "./subscriptions.mjs";
import { buildBundle, fetchFeed } from "./stix.mjs";
import { parseLookup, parseOrder } from "./validation.mjs";

const ORDERS_PER_HOUR = 5;

const publicOrder = (order) => ({
  code: order.code,
  status: order.status,
  months: order.months,
  amount_cents: order.amount_cents,
  method: order.method,
  created_at: order.created_at,
  reviewed_at: order.reviewed_at,
  updated_at: order.updated_at,
});

export async function health(ctx) {
  return json({ status: "ok", schema: 1, time: toIso(ctx.now()) });
}

export async function config(ctx) {
  return json(publicConfig(await ctx.repo.getSettings()));
}

export async function createOrder(ctx) {
  const body = await readJsonBody(ctx.request);
  if (!body.ok) return bodyFailure(body);

  const settings = await ctx.repo.getSettings();
  const input = body.value && typeof body.value === "object" ? body.value : {};

  if (typeof input.company === "string" && input.company.trim()) {
    return json(
      {
        order: {
          code: orderCode(),
          status: "pending",
          months: Number(input.months) || 1,
          amount_cents: settings.pro_monthly_cents,
          method: input.method === "btc" ? "btc" : "usdt_trc20",
          created_at: toIso(ctx.now()),
        },
      },
      { status: 201 },
    );
  }

  const ipHash = await hashIp(ctx.ip, ctx.env.IP_HASH_SALT ?? "");
  const windowStart = Math.floor(ctx.now() / 3_600_000);
  if (!(await ctx.repo.hitRate(`order:${ipHash}`, windowStart, ORDERS_PER_HOUR))) {
    const retryAfter = 3600 - (Math.floor(ctx.now() / 1000) % 3600);
    return fail(429, "rate_limited", "Too many orders from this network. Try again later.", {
      headers: { "retry-after": String(retryAfter) },
    });
  }

  const parsed = parseOrder(input, settings, ctx.now());
  if (!parsed.ok) {
    return fail(400, "invalid", "Check the highlighted fields.", { fields: parsed.errors });
  }

  const value = parsed.value;
  const existing = await ctx.repo.findOrderByTx(value.method, value.tx_ref);
  if (existing) {
    return fail(409, "duplicate_tx", "That transaction is already attached to an order.");
  }

  const customer = await ctx.repo.upsertCustomer({
    id: `cus_${randomToken(12)}`,
    email: value.email,
    name: value.name,
    phone: value.phone,
    now: value.created_at,
  });

  const order = {
    id: `ord_${randomToken(12)}`,
    code: orderCode(),
    customer_id: customer.id,
    email: value.email,
    name: value.name,
    phone: value.phone,
    plan: "pro",
    months: value.months,
    amount_cents: value.amount_cents,
    currency: "USD",
    method: value.method,
    tx_ref: value.tx_ref,
    note: value.note,
    status: "pending",
    created_at: value.created_at,
    updated_at: value.created_at,
    ip_hash: ipHash,
    user_agent_hash: await hashIp(ctx.request.headers.get("user-agent") ?? "", ctx.env.IP_HASH_SALT ?? ""),
  };

  try {
    await ctx.repo.insertOrder(order);
  } catch (error) {
    if (error.code === "DUPLICATE_TX") {
      return fail(409, "duplicate_tx", "That transaction is already attached to an order.");
    }
    throw error;
  }

  return json(
    {
      order: {
        code: order.code,
        status: order.status,
        months: order.months,
        amount_cents: order.amount_cents,
        method: order.method,
        wallet: value.method === "btc" ? settings.btc_address : settings.usdt_trc20_address,
        created_at: order.created_at,
      },
    },
    { status: 201 },
  );
}

export async function lookupOrder(ctx) {
  const body = await readJsonBody(ctx.request);
  if (!body.ok) return bodyFailure(body);

  const parsed = parseLookup(body.value);
  if (!parsed.ok) {
    return fail(400, "invalid", "Check the order code and email.", { fields: parsed.errors });
  }

  const order = await ctx.repo.findOrderByCode(parsed.value.code);
  if (!order || order.email.toLowerCase() !== parsed.value.email) {
    return fail(404, "order_not_found", "No order matches that code and email.");
  }
  return json({ order: publicOrder(order) });
}

async function authenticate(ctx) {
  const key = parseBearer(ctx.request.headers.get("authorization"));
  if (key === null) {
    return { response: fail(401, "license_missing", "Send the licence key as a Bearer token.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  if (!isLicenseShape(key)) {
    return { response: fail(401, "license_invalid", "That licence key is not valid.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  const license = await ctx.repo.findLicenseByHash(await hashLicense(key, ctx.env.LICENSE_SALT ?? ""));
  if (!license) {
    return { response: fail(401, "license_invalid", "That licence key is not valid.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  if (license.status !== "active") {
    return { response: fail(401, "license_revoked", "This licence has been revoked.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  const subscription = await ctx.repo.getSubscription(license.subscription_id);
  const status = subscription
    ? subscriptionStatus(subscription.expires_at, toIso(ctx.now()), subscription.status)
    : "expired";
  if (status === "revoked") {
    return { response: fail(401, "license_revoked", "This licence has been revoked.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  if (status !== "active") {
    return { response: fail(401, "license_expired", "This licence has expired. Renew to keep access.", { headers: { "www-authenticate": "Bearer" } }) };
  }
  return { license, subscription };
}

export async function proMe(ctx) {
  const auth = await authenticate(ctx);
  if (auth.response) return auth.response;

  const settings = await ctx.repo.getSettings();
  const now = toIso(ctx.now());
  await ctx.repo.touchLicense(auth.license.id, now);

  return json({
    plan: auth.subscription.plan,
    status: "active",
    expires_at: auth.subscription.expires_at,
    days_left: daysLeft(auth.subscription.expires_at, now),
    key_prefix: auth.license.key_prefix,
    limits: { stix_rate_per_min: settings.stix_rate_per_min },
  });
}

export async function stixDownload(ctx) {
  const auth = await authenticate(ctx);
  if (auth.response) return auth.response;

  const settings = await ctx.repo.getSettings();
  const windowStart = Math.floor(ctx.now() / 60_000);
  if (!(await ctx.repo.hitRate(`stix:${auth.license.id}`, windowStart, settings.stix_rate_per_min))) {
    return fail(429, "rate_limited", "The export limit for this licence was reached. Try again in a minute.", {
      headers: { "retry-after": "60" },
    });
  }

  const origin = ctx.env.SITE_ORIGIN ?? "https://threats.top";
  const fetchImpl = ctx.env.feedFetch ?? fetch;
  const cache = ctx.env.feedFetch ? null : globalThis.caches?.default;

  let bundle;
  try {
    const [cves, iocs] = await Promise.all([
      fetchFeed(origin, "/data/cves.json", fetchImpl, cache),
      fetchFeed(origin, "/data/iocs.json", fetchImpl, cache),
    ]);
    bundle = await buildBundle({ cves, iocs, origin });
  } catch {
    return fail(502, "feed_unavailable", "The public feeds are temporarily unavailable.");
  }

  const day = toIso(ctx.now()).slice(0, 10);
  return json(bundle, {
    headers: {
      "content-type": "application/stix+json;version=2.1",
      "content-disposition": `attachment; filename="threats-stix-${day}.json"`,
    },
  });
}

