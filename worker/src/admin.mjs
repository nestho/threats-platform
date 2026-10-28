/**
 * Admin handlers: login, session, orders, subscriptions, customers, audit,
 * settings, and CSV export.
 *
 * Reads need a signed session cookie. Mutations additionally need the CSRF
 * token issued with that session; the router has already refused any foreign
 * Origin before a handler runs.
 */

import {
  buildCookie,
  hashIp,
  parseCookies,
  randomToken,
  signSession,
  timingSafeEqual,
  verifyPassword,
  verifySession,
  verifyTotp,
} from "./auth.mjs";
import { licenseKey, licensePrefix } from "./codes.mjs";
import { toCsv } from "./csv.mjs";
import { bodyFailure, fail, json, readJsonBody } from "./http.mjs";
import { hashLicense } from "./license.mjs";
import { defaultSettings, validateSetting } from "./settings.mjs";
import { extendExpiry, toIso } from "./subscriptions.mjs";
import { normalizeEmail, parseMonths } from "./validation.mjs";

const SESSION_COOKIE = "admin_session";
const SESSION_TTL_SECONDS = 8 * 3600;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LIMIT = 10;
const ACTOR = "admin";

const ORDER_STATUSES = new Set(["pending", "approved", "rejected", "expired"]);
const SUBSCRIPTION_STATUSES = new Set(["active", "expired", "revoked"]);

function pageParams(url) {
  const page = Math.max(1, Math.floor(Number(url.searchParams.get("page")) || 1));
  const size = Math.min(100, Math.max(1, Math.floor(Number(url.searchParams.get("page_size")) || 20)));
  return { page, size, offset: (page - 1) * size };
}

function filterValue(url, allowed) {
  const value = url.searchParams.get("status");
  return value && allowed.has(value) ? value : undefined;
}

function adminOrder(order) {
  const { ip_hash, user_agent_hash, ...rest } = order;
  return rest;
}

function noteFrom(value, { required = false } = {}) {
  const note = typeof value === "string" ? value.trim() : "";
  if (required && !note) return { ok: false, error: "Add a short note explaining the decision." };
  if (note.length > 500) return { ok: false, error: "Keep the note under 500 characters." };
  return { ok: true, value: note || null };
}

async function requireSession(ctx) {
  if (!ctx.env.SESSION_SECRET) {
    return { response: fail(503, "admin_unconfigured", "Admin access is not configured yet.") };
  }
  const cookies = parseCookies(ctx.request.headers.get("cookie"));
  const payload = await verifySession(cookies[SESSION_COOKIE], ctx.env.SESSION_SECRET, ctx.now());
  if (!payload || payload.sub !== ACTOR) {
    return { response: fail(401, "session_expired", "Sign in again.") };
  }
  return { payload };
}

function requireCsrf(ctx, payload) {
  const token = ctx.request.headers.get("x-csrf-token");
  if (!token || !timingSafeEqual(token, payload.csrf)) {
    return fail(403, "csrf_failed", "Refresh the page and try again.");
  }
  return null;
}

async function guarded(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return { response: auth.response };
  const csrf = requireCsrf(ctx, auth.payload);
  if (csrf) return { response: csrf };
  return { payload: auth.payload };
}

async function readBody(ctx) {
  const body = await readJsonBody(ctx.request);
  if (!body.ok) return { response: bodyFailure(body) };
  return { value: body.value && typeof body.value === "object" ? body.value : {} };
}

function settingsView(settings) {
  const out = {};
  for (const key of Object.keys(defaultSettings)) out[key] = settings[key] ?? defaultSettings[key];
  return out;
}

export async function login(ctx) {
  const { env, repo } = ctx;
  if (!env.ADMIN_PASSWORD_HASH || !env.TOTP_SECRET || !env.SESSION_SECRET) {
    return fail(503, "admin_unconfigured", "Admin access is not configured yet.");
  }

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const ipHash = await hashIp(ctx.ip, env.IP_HASH_SALT ?? "");
  const nowIso = toIso(ctx.now());
  const failures = await repo.recentFailures(ipHash, toIso(ctx.now() - LOGIN_WINDOW_MS));
  if (failures >= LOGIN_LIMIT) {
    return fail(429, "login_locked", "Too many attempts. Try again in 15 minutes.", {
      headers: { "retry-after": "900" },
    });
  }

  const password = typeof body.value.password === "string" ? body.value.password : "";
  const code = typeof body.value.code === "string" ? body.value.code : "";
  const passwordOk = await verifyPassword(password, env.ADMIN_PASSWORD_HASH);

  const settings = await repo.getSettings();
  const storedStep = Number(settings.admin_totp_step);
  const lastStep = Number.isFinite(storedStep) ? storedStep : -1;
  const totp = passwordOk
    ? verifyTotp(env.TOTP_SECRET, code, lastStep, ctx.now())
    : { ok: false, step: null };

  if (!passwordOk || !totp.ok) {
    await repo.recordLogin({ at: nowIso, ip_hash: ipHash, ok: false });
    return fail(401, "invalid_credentials", "Password or authenticator code is wrong.");
  }

  await repo.recordLogin({ at: nowIso, ip_hash: ipHash, ok: true });
  await repo.putSetting("admin_totp_step", totp.step);

  const csrf = randomToken(16);
  const iat = Math.floor(ctx.now() / 1000);
  const exp = iat + SESSION_TTL_SECONDS;
  const token = await signSession({ sub: ACTOR, iat, exp, csrf }, env.SESSION_SECRET);
  await repo.audit({ at: nowIso, actor: ACTOR, action: "admin.login", target: ACTOR, detail: null });

  return json(
    {
      admin: { sub: ACTOR },
      csrf,
      expires_at: new Date(exp * 1000).toISOString().replace(".000Z", "Z"),
    },
    {
      headers: {
        "set-cookie": buildCookie(SESSION_COOKIE, token, { maxAge: SESSION_TTL_SECONDS }),
      },
    },
  );
}

export async function logout(ctx) {
  return json(
    { ok: true },
    { headers: { "set-cookie": buildCookie(SESSION_COOKIE, "", { maxAge: 0 }) } },
  );
}

export async function sessionInfo(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;
  return json({
    admin: { sub: auth.payload.sub },
    csrf: auth.payload.csrf,
    expires_at: toIso(auth.payload.exp * 1000),
  });
}

export async function listOrders(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const { page, size, offset } = pageParams(ctx.url);
  const result = await ctx.repo.listOrders({
    status: filterValue(ctx.url, ORDER_STATUSES),
    search: ctx.url.searchParams.get("q")?.trim() ?? "",
    limit: size,
    offset,
  });
  return json({ items: result.items.map(adminOrder), total: result.total, page, page_size: size });
}

export async function getOrder(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const order = await ctx.repo.getOrder(ctx.params[0]);
  if (!order) return fail(404, "order_not_found", "No order with that id.");
  return json({ order: adminOrder(order) });
}

export async function approveOrder(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const order = await ctx.repo.getOrder(ctx.params[0]);
  if (!order) return fail(404, "order_not_found", "No order with that id.");
  if (order.status === "approved") return fail(409, "already_approved", "This order is already approved.");
  if (order.status === "expired") return fail(409, "order_expired", "This order has expired.");

  let months = order.months;
  if (body.value.months !== undefined) {
    const parsed = parseMonths(body.value.months, { min: 1, max: 24 });
    if (parsed === null) return fail(400, "invalid_months", "Months must be between 1 and 24.");
    months = parsed;
  }

  const note = noteFrom(body.value.note);
  if (!note.ok) return fail(400, "invalid_note", note.error);

  const now = toIso(ctx.now());
  const customer = await ctx.repo.getCustomer(order.customer_id);
  if (!customer) return fail(404, "customer_not_found", "The customer record is missing.");

  const existing = await ctx.repo.activeSubscriptionFor(customer.id, now);
  let subscription;
  let license = null;

  if (existing) {
    subscription = await ctx.repo.updateSubscription(existing.id, {
      expires_at: extendExpiry(now, existing.expires_at, months),
      status: "active",
      updated_at: now,
    });
  } else {
    subscription = await ctx.repo.insertSubscription({
      id: `sub_${randomToken(12)}`,
      customer_id: customer.id,
      plan: "pro",
      status: "active",
      started_at: now,
      expires_at: extendExpiry(now, null, months),
      source_order_id: order.id,
      note: null,
      created_at: now,
      updated_at: now,
    });
    const key = licenseKey();
    await ctx.repo.insertLicense({
      id: `lic_${randomToken(12)}`,
      subscription_id: subscription.id,
      customer_id: customer.id,
      key_hash: await hashLicense(key, ctx.env.LICENSE_SALT ?? ""),
      key_prefix: licensePrefix(key),
      status: "active",
      created_at: now,
      last_used_at: null,
      revoked_at: null,
    });
    license = key;
  }

  const updated = await ctx.repo.markOrder(order.id, {
    status: "approved",
    reviewed_at: now,
    reviewed_by: ACTOR,
    review_note: note.value,
    updated_at: now,
  });

  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "order.approve",
    target: order.id,
    detail: JSON.stringify({
      months,
      subscription_id: subscription.id,
      extended: Boolean(existing),
      license_issued: Boolean(license),
    }),
  });

  return json({
    order: adminOrder(updated),
    subscription,
    license,
    key_prefix: license ? licensePrefix(license) : null,
  });
}

export async function rejectOrder(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const order = await ctx.repo.getOrder(ctx.params[0]);
  if (!order) return fail(404, "order_not_found", "No order with that id.");
  if (order.status === "approved") return fail(409, "order_approved", "Revoke the subscription instead.");
  if (order.status === "expired") return fail(409, "order_expired", "This order has expired.");

  const note = noteFrom(body.value.note, { required: true });
  if (!note.ok) return fail(400, "invalid_note", note.error);

  const now = toIso(ctx.now());
  const updated = await ctx.repo.markOrder(order.id, {
    status: "rejected",
    reviewed_at: now,
    reviewed_by: ACTOR,
    review_note: note.value,
    updated_at: now,
  });
  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "order.reject",
    target: order.id,
    detail: note.value,
  });
  return json({ order: adminOrder(updated) });
}

export async function listSubscriptions(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const { page, size, offset } = pageParams(ctx.url);
  const result = await ctx.repo.listSubscriptions({
    status: filterValue(ctx.url, SUBSCRIPTION_STATUSES),
    search: ctx.url.searchParams.get("q")?.trim() ?? "",
    limit: size,
    offset,
  });
  return json({ items: result.items, total: result.total, page, page_size: size });
}

async function issueLicense(ctx, subscription) {
  const now = toIso(ctx.now());
  const key = licenseKey();
  await ctx.repo.insertLicense({
    id: `lic_${randomToken(12)}`,
    subscription_id: subscription.id,
    customer_id: subscription.customer_id,
    key_hash: await hashLicense(key, ctx.env.LICENSE_SALT ?? ""),
    key_prefix: licensePrefix(key),
    status: "active",
    created_at: now,
    last_used_at: null,
    revoked_at: null,
  });
  return key;
}

export async function grantSubscription(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const email = normalizeEmail(body.value.email);
  if (!email || email.length > 254) return fail(400, "invalid_email", "Enter a customer email.");
  const months = parseMonths(body.value.months, { min: 1, max: 24 });
  if (months === null) return fail(400, "invalid_months", "Months must be between 1 and 24.");
  const note = noteFrom(body.value.note);
  if (!note.ok) return fail(400, "invalid_note", note.error);

  const now = toIso(ctx.now());
  let customer = await ctx.repo.findCustomerByEmail(email);
  if (!customer) {
    customer = await ctx.repo.upsertCustomer({
      id: `cus_${randomToken(12)}`,
      email,
      name: typeof body.value.name === "string" && body.value.name.trim() ? body.value.name.trim().slice(0, 80) : email.split("@")[0],
      phone: null,
      now,
    });
  }
  if (await ctx.repo.activeSubscriptionFor(customer.id, now)) {
    return fail(409, "already_subscribed", "That customer already has an active subscription. Extend it instead.");
  }

  const subscription = await ctx.repo.insertSubscription({
    id: `sub_${randomToken(12)}`,
    customer_id: customer.id,
    plan: "pro",
    status: "active",
    started_at: now,
    expires_at: extendExpiry(now, null, months),
    source_order_id: null,
    note: note.value,
    created_at: now,
    updated_at: now,
  });
  const license = await issueLicense(ctx, subscription);
  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "subscription.comp",
    target: subscription.id,
    detail: JSON.stringify({ email, months }),
  });
  return json({ subscription, customer, license, key_prefix: licensePrefix(license) }, { status: 201 });
}

async function findSubscription(ctx) {
  const subscription = await ctx.repo.getSubscription(ctx.params[0]);
  if (!subscription) return { response: fail(404, "subscription_not_found", "No subscription with that id.") };
  if (subscription.status === "revoked") {
    return { response: fail(409, "subscription_revoked", "This subscription is revoked.") };
  }
  return { subscription };
}

export async function extendSubscription(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const found = await findSubscription(ctx);
  if (found.response) return found.response;

  const months = parseMonths(body.value.months, { min: 1, max: 24 });
  if (months === null) return fail(400, "invalid_months", "Months must be between 1 and 24.");

  const now = toIso(ctx.now());
  const subscription = await ctx.repo.updateSubscription(found.subscription.id, {
    status: "active",
    expires_at: extendExpiry(now, found.subscription.expires_at, months),
    updated_at: now,
  });
  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "subscription.extend",
    target: found.subscription.id,
    detail: JSON.stringify({ months }),
  });
  return json({ subscription });
}

export async function revokeSubscription(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const found = await findSubscription(ctx);
  if (found.response) return found.response;

  const note = noteFrom(body.value.note, { required: true });
  if (!note.ok) return fail(400, "invalid_note", note.error);

  const now = toIso(ctx.now());
  const subscription = await ctx.repo.updateSubscription(found.subscription.id, {
    status: "revoked",
    updated_at: now,
  });
  const revoked = await ctx.repo.revokeLicenses(found.subscription.id, now);
  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "subscription.revoke",
    target: found.subscription.id,
    detail: JSON.stringify({ note: note.value, licenses: revoked }),
  });
  return json({ subscription, licenses_revoked: revoked });
}

export async function rotateLicense(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const found = await findSubscription(ctx);
  if (found.response) return found.response;

  const now = toIso(ctx.now());
  const revoked = await ctx.repo.revokeLicenses(found.subscription.id, now);
  const license = await issueLicense(ctx, found.subscription);
  await ctx.repo.audit({
    at: now,
    actor: ACTOR,
    action: "subscription.rotate",
    target: found.subscription.id,
    detail: JSON.stringify({ licenses_revoked: revoked }),
  });
  return json({ license, key_prefix: licensePrefix(license) });
}

export async function listCustomers(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const { page, size, offset } = pageParams(ctx.url);
  const result = await ctx.repo.listCustomers({
    search: ctx.url.searchParams.get("q")?.trim() ?? "",
    limit: size,
    offset,
  });
  return json({ items: result.items, total: result.total, page, page_size: size });
}

export async function listAudit(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const { page, size, offset } = pageParams(ctx.url);
  const result = await ctx.repo.listAudit({ limit: size, offset });
  return json({ items: result.items, total: result.total, page, page_size: size });
}

export async function stats(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const value = await ctx.repo.stats(toIso(ctx.now()), toIso(ctx.now() - 30 * 86_400_000));
  return json({ stats: value });
}

export async function getSettings(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const settings = await ctx.repo.getSettings();
  return json({ settings: settingsView(settings) });
}

export async function putSetting(ctx) {
  const auth = await guarded(ctx);
  if (auth.response) return auth.response;

  const body = await readBody(ctx);
  if (body.response) return body.response;

  const key = typeof body.value.key === "string" ? body.value.key : "";
  const result = validateSetting(key, body.value.value);
  if (!result.ok) return fail(400, "invalid_setting", result.error);

  await ctx.repo.putSetting(key, result.value);
  await ctx.repo.audit({
    at: toIso(ctx.now()),
    actor: ACTOR,
    action: "settings.update",
    target: key,
    detail: null,
  });
  return json({ settings: settingsView(await ctx.repo.getSettings()) });
}

const EXPORTS = {
  orders: {
    columns: [
      { key: "code", label: "Code" },
      { key: "created_at", label: "Created" },
      { key: "status", label: "Status" },
      { key: "name", label: "Name" },
      { key: "email", label: "Email" },
      { key: "phone", label: "Phone" },
      { key: "months", label: "Months" },
      { key: "amount_cents", label: "Amount (cents)" },
      { key: "method", label: "Method" },
      { key: "tx_ref", label: "Transaction" },
    ],
    load: (repo) => repo.listOrders({ limit: 5000, offset: 0 }),
  },
  subscriptions: {
    columns: [
      { key: "id", label: "Subscription" },
      { key: "customer_email", label: "Email" },
      { key: "plan", label: "Plan" },
      { key: "status", label: "Status" },
      { key: "started_at", label: "Started" },
      { key: "expires_at", label: "Expires" },
      { key: "license_prefix", label: "Licence prefix" },
    ],
    load: (repo) => repo.listSubscriptions({ limit: 5000, offset: 0 }),
  },
};

export async function exportCsv(ctx) {
  const auth = await requireSession(ctx);
  if (auth.response) return auth.response;

  const type = ctx.url.searchParams.get("type") === "subscriptions" ? "subscriptions" : "orders";
  const spec = EXPORTS[type];
  const { items } = await spec.load(ctx.repo);
  const day = toIso(ctx.now()).slice(0, 10);

  return new Response(toCsv(items, spec.columns), {
    status: 200,
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="threats-${type}-${day}.csv"`,
      "cache-control": "no-store",
    },
  });
}
