/**
 * Domain rules: order validation, codes, subscription math, settings, CSV.
 *
 *     node --test worker/test/domain.test.mjs
 */
import assert from "node:assert/strict";
import test from "node:test";

import { licenseKey, licensePrefix, orderCode } from "../src/codes.mjs";
import { toCsv } from "../src/csv.mjs";
import { defaultSettings, publicConfig, validateSetting } from "../src/settings.mjs";
import { daysLeft, extendExpiry, subscriptionStatus } from "../src/subscriptions.mjs";
import { normalizeEmail, parseLookup, parseMonths, parseOrder } from "../src/validation.mjs";

const SETTINGS = { ...defaultSettings, pro_monthly_cents: 3900 };
const NOW = Date.parse("2026-10-28T12:00:00Z");

const validOrder = (overrides = {}) => ({
  name: "Ada Lovelace",
  email: "Ada@Example.COM ",
  phone: "+44 20 7946 0958",
  method: "usdt_trc20",
  months: 3,
  tx_ref: "0xabc123:def-456",
  note: "Paid from the office wallet",
  company: "",
  ...overrides,
});

test("email normalisation trims and lowercases", () => {
  assert.equal(normalizeEmail("  Ada@Example.COM "), "ada@example.com");
  assert.equal(normalizeEmail(42), "");
  assert.equal(normalizeEmail(null), "");
});

test("a valid order normalises and prices itself", () => {
  const result = parseOrder(validOrder(), SETTINGS, NOW);
  assert.equal(result.ok, true);
  assert.equal(result.value.email, "ada@example.com");
  assert.equal(result.value.phone, "+44 20 7946 0958");
  assert.equal(result.value.note, "Paid from the office wallet");
  assert.equal(result.value.amount_cents, 11700);
  assert.equal(result.value.created_at, "2026-10-28T12:00:00Z");
});

test("phone and note are optional", () => {
  const result = parseOrder(validOrder({ phone: "", note: undefined }), SETTINGS, NOW);
  assert.equal(result.ok, true);
  assert.equal(result.value.phone, null);
  assert.equal(result.value.note, "");
});

test("order fields are bounded and shaped", () => {
  const cases = [
    [{ name: "A" }, "name"],
    [{ name: "x".repeat(81) }, "name"],
    [{ email: "not-an-email" }, "email"],
    [{ email: `${"a".repeat(250)}@x.io` }, "email"],
    [{ phone: "12" }, "phone"],
    [{ phone: "+++ +++ +++" }, "phone"],
    [{ months: 2 }, "months"],
    [{ months: "3" }, "months"],
    [{ method: "card" }, "method"],
    [{ tx_ref: "short" }, "tx_ref"],
    [{ tx_ref: "has space here" }, "tx_ref"],
    [{ tx_ref: "x".repeat(129) }, "tx_ref"],
    [{ note: "n".repeat(501) }, "note"],
  ];
  for (const [overrides, field] of cases) {
    const result = parseOrder(validOrder(overrides), SETTINGS, NOW);
    assert.equal(result.ok, false, `${field} should be rejected`);
    assert.ok(result.errors[field], `${field} should carry an error`);
  }
});

test("the honeypot is reported as a field error", () => {
  const result = parseOrder(validOrder({ company: "Spam Corp" }), SETTINGS, NOW);
  assert.equal(result.ok, false);
  assert.ok(result.errors.company);
});

test("a lookup needs the order code and the matching email shape", () => {
  const good = parseLookup({ code: "th-abcde-23456", email: " Ada@Example.com " });
  assert.equal(good.ok, true);
  assert.equal(good.value.code, "TH-ABCDE-23456");
  assert.equal(good.value.email, "ada@example.com");

  assert.equal(parseLookup({ code: "nope", email: "ada@example.com" }).ok, false);
  assert.equal(parseLookup({ code: "TH-ABCDE-23456", email: "" }).ok, false);
});

test("months are whitelisted for orders and ranged for admin actions", () => {
  assert.equal(parseMonths(1), 1);
  assert.equal(parseMonths("12"), 12);
  assert.equal(parseMonths(2), null);
  assert.equal(parseMonths(0), null);
  assert.equal(parseMonths(24, { min: 1, max: 24 }), 24);
  assert.equal(parseMonths(25, { min: 1, max: 24 }), null);
});

test("order codes use the unambiguous Crockford alphabet", () => {
  assert.equal(orderCode(() => 0), "TH-00000-00000");
  assert.match(orderCode(Math.random), /^TH-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
  const seen = new Set();
  for (let i = 0; i < 50; i += 1) seen.add(orderCode(Math.random));
  assert.equal(seen.size, 50);
});

test("licence keys carry 100 bits and a short display prefix", () => {
  const key = licenseKey(() => 0);
  assert.equal(key, "THREATS-PRO-00000000000000000000");
  assert.match(licenseKey(Math.random), /^THREATS-PRO-[0-9A-HJKMNP-TV-Z]{20}$/);
  assert.equal(licensePrefix(key), "00000000");
  assert.match(licensePrefix(licenseKey(Math.random)), /^[0-9A-HJKMNP-TV-Z]{8}$/);
  const seen = new Set();
  for (let i = 0; i < 50; i += 1) seen.add(licenseKey(Math.random));
  assert.equal(seen.size, 50);
});

test("renewals extend from the later of now and the paid expiry", () => {
  const fresh = extendExpiry("2026-10-28T12:00:00Z", null, 1);
  assert.equal(fresh, "2026-11-28T12:00:00Z");

  const renewed = extendExpiry("2026-10-28T12:00:00Z", "2026-12-31T12:00:00Z", 1);
  assert.equal(renewed, "2027-01-31T12:00:00Z");

  const lapsed = extendExpiry("2026-10-28T12:00:00Z", "2026-01-01T00:00:00Z", 1);
  assert.equal(lapsed, "2026-11-28T12:00:00Z");
});

test("month arithmetic clamps to the end of short months", () => {
  assert.equal(extendExpiry("2026-01-31T00:00:00Z", null, 1), "2026-02-28T00:00:00Z");
  assert.equal(extendExpiry("2024-01-31T00:00:00Z", null, 1), "2024-02-29T00:00:00Z");
  assert.equal(extendExpiry("2026-03-31T00:00:00Z", null, 12), "2027-03-31T00:00:00Z");
});

test("status and days left follow the expiry", () => {
  const now = Date.parse("2026-10-28T12:00:00Z");
  assert.equal(subscriptionStatus("2026-11-28T12:00:00Z", now), "active");
  assert.equal(subscriptionStatus("2026-10-28T12:00:00Z", now), "expired");
  assert.equal(subscriptionStatus("2026-11-28T12:00:00Z", now, "revoked"), "revoked");
  assert.equal(daysLeft("2026-11-28T12:00:00Z", now), 31);
  assert.equal(daysLeft("2026-10-28T12:00:00Z", now), 0);
});

test("settings accept only the documented keys and shapes", () => {
  assert.equal(validateSetting("pro_monthly_cents", "4900").value, 4900);
  assert.equal(validateSetting("pro_monthly_cents", 99).ok, false);
  assert.equal(validateSetting("pro_monthly_cents", 39.5).ok, false);
  assert.equal(validateSetting("order_retention_days", 30).ok, false);
  assert.equal(validateSetting("order_retention_days", 365).value, 365);
  assert.equal(validateSetting("stix_rate_per_min", 0).ok, false);
  assert.equal(validateSetting("stix_rate_per_min", 600).value, 600);
  assert.equal(validateSetting("support_email", "SOC@Example.com").value, "soc@example.com");
  assert.equal(validateSetting("support_email", "nope").ok, false);
  assert.equal(validateSetting("usdt_trc20_address", "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2").ok, true);
  assert.equal(validateSetting("usdt_trc20_address", "0x1234").ok, false);
  assert.equal(validateSetting("btc_address", "bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq").ok, true);
  assert.equal(validateSetting("btc_address", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT").ok, false);
  assert.equal(validateSetting("unknown_key", "x").ok, false);
});

test("default settings match the migration seeds", () => {
  assert.deepEqual(defaultSettings, {
    pro_monthly_cents: 3900,
    usdt_trc20_address: "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2",
    btc_address: "bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq",
    stix_rate_per_min: 600,
    support_email: "nestho@icloud.com",
    order_retention_days: 180,
  });
});

test("public config exposes only what a buyer needs", () => {
  const config = publicConfig(SETTINGS);
  assert.equal(config.pro_monthly_cents, 3900);
  assert.deepEqual(config.plan_months, [1, 3, 12]);
  assert.deepEqual(config.methods, ["usdt_trc20", "btc"]);
  assert.equal(config.wallets.usdt_trc20, defaultSettings.usdt_trc20_address);
  assert.equal(config.wallets.btc, defaultSettings.btc_address);
  assert.equal(config.support_email, "nestho@icloud.com");
  assert.equal("order_retention_days" in config, false);
  assert.equal("stix_rate_per_min" in config, false);
});

test("csv quoting and formula neutralisation", () => {
  const rows = [
    { name: "=1+1", note: 'hello, "world"', phone: null, days: 30 },
    { name: "+SUM(A1)", note: "@cmd", phone: "-5", days: 0 },
  ];
  const columns = [
    { key: "name", label: "Name" },
    { key: "note", label: "Note" },
    { key: "phone", label: "Phone" },
    { key: "days", label: "Days" },
  ];
  assert.equal(
    toCsv(rows, columns),
    [
      "Name,Note,Phone,Days",
      "'=1+1,\"hello, \"\"world\"\"\",,30",
      "'+SUM(A1),'@cmd,'-5,0",
    ].join("\n"),
  );
});
