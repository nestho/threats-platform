/**
 * Tests for assets/pro.js
 *
 *     node --test assets/pro.test.mjs
 *
 * The Pro console turns a pasted licence key into an entitlement check, a
 * masked identity, an expiry sentence, and a download filename. A wrong mask
 * leaks a key, a wrong filename produces a confusing save, and a raw error code
 * leaves the customer with nothing to do -- so each of those is a pure function
 * with a test.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  curlExample,
  daysLabel,
  filenameFromDisposition,
  formatDay,
  isKeyShape,
  licenseMessage,
  maskKey,
  needsNewKey,
  normalizeKey,
} from "./pro.js";

const KEY = "THREATS-PRO-A1B2C3D4E5F6G7H8J9K0";

test("normalizeKey: accepts the whitespace and casing people paste", () => {
  assert.equal(normalizeKey(`  ${KEY.toLowerCase()}  `), KEY);
  assert.equal(normalizeKey("THREATS-PRO- A1B2C3D4 E5F6G7H8 J9K0"), KEY);
  assert.equal(normalizeKey("THREATS-PRO-\nA1B2C3D4E5F6G7H8J9K0"), KEY);
  assert.equal(normalizeKey(null), "");
  assert.equal(normalizeKey(undefined), "");
});

test("isKeyShape: mirrors the server's 20-character Crockford suffix", () => {
  assert.equal(isKeyShape(KEY), true);
  assert.equal(isKeyShape(KEY.toLowerCase()), true);
  assert.equal(isKeyShape("THREATS-PRO-A1B2C3D4E5F6G7H8J9K"), false, "nineteen characters");
  assert.equal(isKeyShape("THREATS-PRO-A1B2C3D4E5F6G7H8J9K0X"), false, "twenty-one characters");
  assert.equal(isKeyShape("THREATS-A1B2C3D4E5F6G7H8J9K0"), false, "wrong prefix");
  assert.equal(isKeyShape("THREATS-PRO-A1B2C3D4E5F6G7H8J9KI"), false, "I is not Crockford");
  assert.equal(isKeyShape("THREATS-PRO-A1B2C3D4E5F6G7H8J9KL"), false, "L is not Crockford");
  assert.equal(isKeyShape(""), false);
  assert.equal(isKeyShape(null), false);
});

test("maskKey: keeps the eight-character prefix the server records", () => {
  assert.equal(maskKey(KEY), "THREATS-PRO-A1B2C3D4••••••••••••");
  assert.equal(maskKey(KEY.toLowerCase()), "THREATS-PRO-A1B2C3D4••••••••••••");
  assert.equal(maskKey("nonsense"), "—");
  assert.equal(maskKey(null), "—");
});

test("maskKey: never reveals more than the stored prefix", () => {
  const masked = maskKey(KEY);
  assert.equal(masked.includes("E5F6"), false);
  assert.equal(masked.includes("J9K0"), false);
});

test("formatDay: renders the UTC day, not the viewer's timezone", () => {
  assert.equal(formatDay("2027-01-01T00:30:00Z"), "1 Jan 2027");
  assert.equal(formatDay("2026-10-28T23:59:59Z"), "28 Oct 2026");
  assert.equal(formatDay(null), "—");
  assert.equal(formatDay("not a date"), "—");
});

test("daysLabel: reads like a sentence", () => {
  assert.equal(daysLabel(12), "12 days left");
  assert.equal(daysLabel(2), "2 days left");
  assert.equal(daysLabel(1), "1 day left");
  assert.equal(daysLabel(0), "Expires today");
  assert.equal(daysLabel(-3), "Expired");
  assert.equal(daysLabel(null), "—");
  assert.equal(daysLabel(NaN), "—");
  assert.equal(daysLabel("12"), "—");
});

test("licenseMessage: every rejection tells the customer what to do", () => {
  assert.match(licenseMessage("license_invalid"), /check|typo/i);
  assert.match(licenseMessage("license_invalid"), /THREATS-PRO-/);
  assert.match(licenseMessage("license_revoked"), /revoked/i);
  assert.match(licenseMessage("license_revoked"), /support/i);
  assert.match(licenseMessage("license_expired"), /expired/i);
  assert.match(licenseMessage("license_expired"), /renew|new order|subscribe/i);
  assert.match(licenseMessage("network"), /connection|reach/i);
  assert.match(licenseMessage("server"), /try again/i);
});

test("licenseMessage: prefers server copy for unknown codes", () => {
  assert.equal(licenseMessage("some_new_code", "Server said this"), "Server said this");
  assert.equal(licenseMessage("some_new_code"), "That licence could not be checked. Try again.");
  assert.equal(licenseMessage(null), "That licence could not be checked. Try again.");
});

test("needsNewKey: only an expired or revoked term sends the buyer to checkout", () => {
  assert.equal(needsNewKey("license_expired"), true);
  assert.equal(needsNewKey("license_revoked"), true);
  assert.equal(needsNewKey("license_invalid"), false);
  assert.equal(needsNewKey(null), false);
});

test("filenameFromDisposition: reads the API's suggested name", () => {
  assert.equal(
    filenameFromDisposition('attachment; filename="threats-stix-2026-10-28.json"', "fallback.json"),
    "threats-stix-2026-10-28.json",
  );
  assert.equal(filenameFromDisposition("attachment; filename=stix.json", "fallback.json"), "stix.json");
  assert.equal(filenameFromDisposition("", "fallback.json"), "fallback.json");
  assert.equal(filenameFromDisposition(null, "fallback.json"), "fallback.json");
});

test("filenameFromDisposition: keeps only a safe basename", () => {
  assert.equal(
    filenameFromDisposition('attachment; filename="../../etc/passwd"', "fallback.json"),
    "passwd",
  );
  assert.equal(
    filenameFromDisposition('attachment; filename="my stix.json"', "fallback.json"),
    "my-stix.json",
  );
});

test("curlExample: authenticates with the key when the shape is known", () => {
  const command = curlExample("https://api.threats.top", KEY);
  assert.match(command, /^curl -H "Authorization: Bearer THREATS-PRO-A1B2C3D4E5F6G7H8J9K0"/);
  assert.match(command, /https:\/\/api\.threats\.top\/api\/stix/);
  assert.match(command, /threats-stix\.json/);
});

test("curlExample: falls back to a placeholder instead of a broken header", () => {
  const command = curlExample("https://api.threats.top", "nonsense");
  assert.match(command, /Authorization: Bearer <licence key>/);
  assert.doesNotMatch(command, /nonsense/);
});
