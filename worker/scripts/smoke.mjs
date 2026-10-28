#!/usr/bin/env node
/**
 * End-to-end smoke run against a local `wrangler dev --local` instance.
 *
 * Exercises the real handlers and real D1 SQL: health, order creation, admin
 * sign-in with a generated TOTP, order approval, licence activation, the STIX
 * bundle, revocation, and the post-revocation rejection.
 *
 *   npx wrangler d1 migrations apply threats-platform --local
 *   npx wrangler dev --local
 *   node scripts/smoke.mjs
 *
 * Reads ADMIN_PASSWORD and TOTP_SECRET from the environment or from
 * ../.dev.vars. It never prints either value.
 */

import { readFileSync } from "node:fs";
import { randomInt } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { totpCode } from "../src/auth.mjs";

const here = dirname(fileURLToPath(import.meta.url));

// This script drives a Developer-mode Worker only. Refuse anything that is not
// a loopback address so a copied command cannot post test orders to a real host.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

function loopbackBase(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`SMOKE_BASE_URL is not a URL: ${raw}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("SMOKE_BASE_URL must be http or https");
  }
  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new Error(`SMOKE_BASE_URL must be loopback, got ${url.hostname}`);
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

const base = loopbackBase(process.env.SMOKE_BASE_URL || process.argv[2] || "http://127.0.0.1:8787");

function loadDevVars() {
  const file = join(here, "..", ".dev.vars");
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return {};
  }
  const out = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

const vars = { ...loadDevVars(), ...process.env };
const password = vars.ADMIN_PASSWORD;
const totpSecret = vars.TOTP_SECRET;

if (!password || !totpSecret || /replace/i.test(totpSecret)) {
  console.error("Set ADMIN_PASSWORD and TOTP_SECRET in worker/.dev.vars (see .dev.vars.example).");
  process.exit(1);
}

// Fixed-window limits persist in --local D1. A fresh test IP per run keeps a
// repeated smoke from tripping the order or login limit on the previous run.
const testIp = `198.51.100.${randomInt(1, 251)}`;

let subscriptionId = null;
let revoked = false;
let session = null;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

async function call(path, { method = "GET", body, headers = {} } = {}) {
  const init = { method, headers: { "cf-connecting-ip": testIp, ...headers } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch(`${base}${path}`, init);
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  return { response, data, text };
}

function cookieOf(response) {
  const header = response.headers.get("set-cookie") ?? "";
  const pair = header.split(";")[0]?.trim();
  check(pair?.startsWith("admin_session="), "login did not set the session cookie");
  return pair;
}

async function signIn() {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const code = totpCode(totpSecret, Date.now());
    const { response, data } = await call("/api/admin/login", {
      method: "POST",
      body: { password, code },
    });
    if (response.status === 200) return { cookie: cookieOf(response), csrf: data.csrf };
    if (response.status === 429) throw new Error("login is rate-limited; wait 15 minutes");
    if (response.status !== 401) {
      throw new Error(`login failed with ${response.status}: ${data?.error?.code ?? "unknown"}`);
    }
    // A code from the same 30-second step was already accepted by an earlier
    // run; wait for the next step instead of replaying it.
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error("login rejected three generated codes; check TOTP_SECRET and ADMIN_PASSWORD_HASH");
}

async function main() {
  console.log(`smoke: ${base}`);

  const health = await call("/api/health");
  check(health.response.status === 200 && health.data?.status === "ok", "health is not ok");
  console.log("ok  health");

  const stamp = Date.now();
  const order = await call("/api/orders", {
    method: "POST",
    body: {
      name: "Smoke Test",
      email: `smoke+${stamp}@example.com`,
      phone: "+10000000000",
      plan: "pro",
      months: 1,
      method: "btc",
      tx_ref: `smoke_${stamp}`,
      note: "automated local smoke run",
      company: "",
    },
  });
  check(order.response.status === 201, `order failed with ${order.response.status}: ${order.data?.error?.code}`);
  const code = order.data.order.code;
  check(code.startsWith("TH-"), "order code has the wrong shape");
  console.log(`ok  order ${code}`);

  session = await signIn();
  console.log("ok  admin sign-in");
  const adminHeaders = { cookie: session.cookie };
  const writeHeaders = { ...adminHeaders, "x-csrf-token": session.csrf };

  const lookup = await call(`/api/admin/orders?q=${encodeURIComponent(code)}&status=pending`, {
    headers: adminHeaders,
  });
  check(lookup.response.status === 200, "admin order search failed");
  const found = lookup.data.items.find((item) => item.code === code);
  check(found, "created order is not visible to the admin");

  const approval = await call(`/api/admin/orders/${found.id}/approve`, {
    method: "POST",
    headers: writeHeaders,
    body: { months: 1 },
  });
  check(approval.response.status === 200, `approve failed with ${approval.response.status}: ${approval.data?.error?.code}`);
  const license = approval.data.license;
  subscriptionId = approval.data.subscription?.id ?? null;
  check(license, "approval did not return a licence key");
  check(subscriptionId, "approval did not return a subscription");
  console.log("ok  approval issued a licence");

  const bearer = { authorization: `Bearer ${license}` };
  const me = await call("/api/pro/me", { headers: bearer });
  check(me.response.status === 200, `pro/me failed with ${me.response.status}`);
  check(me.data.plan === "pro" && me.data.status === "active", "pro/me reports the wrong plan");
  check(me.data.key_prefix.length === 8, "pro/me returned a malformed key prefix");
  const daysLeft = Number(me.data.days_left);
  check(Number.isInteger(daysLeft) && daysLeft > 0, "pro/me returned a bad days_left");
  console.log(`ok  licence active, ${daysLeft} days left`);

  const stix = await call("/api/stix", { headers: bearer });
  check(stix.response.status === 200, `stix failed with ${stix.response.status}: ${stix.data?.error?.code}`);
  check((stix.response.headers.get("content-type") ?? "").includes("application/stix+json"), "stix content type is wrong");
  check(stix.data?.type === "bundle" && Array.isArray(stix.data.objects), "stix body is not a bundle");
  console.log(`ok  stix bundle with ${stix.data.objects.length} objects`);

  const revoke = await call(`/api/admin/subscriptions/${subscriptionId}/revoke`, {
    method: "POST",
    headers: writeHeaders,
    body: { note: "automated local smoke cleanup" },
  });
  check(revoke.response.status === 200, `revoke failed with ${revoke.response.status}`);
  revoked = true;
  console.log("ok  subscription revoked");

  const after = await call("/api/pro/me", { headers: bearer });
  check(after.response.status === 401, "revoked licence is still accepted");
  check(after.data?.error?.code === "license_revoked", `expected license_revoked, got ${after.data?.error?.code}`);
  console.log("ok  revoked licence rejected");

  console.log("smoke: pass");
}

try {
  await main();
} catch (error) {
  console.error(`smoke: FAIL — ${error.message}`);
  if (subscriptionId && !revoked) {
    try {
      if (!session) session = await signIn();
      await call(`/api/admin/subscriptions/${subscriptionId}/revoke`, {
        method: "POST",
        headers: { cookie: session.cookie, "x-csrf-token": session.csrf },
        body: { note: "smoke cleanup after failure" },
      });
      console.error("smoke: cleaned up the test subscription");
    } catch {
      console.error("smoke: cleanup failed; revoke the test subscription in the local admin panel");
    }
  }
  process.exitCode = 1;
}
