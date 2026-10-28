/**
 * Tests for the admin panel's pure helpers.
 *
 *     node --test assets/admin.test.mjs
 *
 * The panel itself is DOM wiring. These cover the parts where a silent mistake
 * would be expensive: an entitlement that looks active after it expired, a
 * filter that drops a query parameter, or a licence message with the wrong
 * expiry or key.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  actionLabel,
  buildQuery,
  daysLeft,
  effectiveStatus,
  licenseMessage,
  parseDetail,
  statusTone,
} from "./admin.js";

const NOW = new Date("2026-10-28T12:00:00Z").getTime();

test("effectiveStatus: an active row past its expiry reads expired", () => {
  assert.equal(effectiveStatus("active", "2026-11-04T12:00:00Z", NOW), "active");
  assert.equal(effectiveStatus("active", "2026-10-28T11:59:59Z", NOW), "expired");
  assert.equal(effectiveStatus("active", "2026-10-28T12:00:00Z", NOW), "expired");
});

test("effectiveStatus: revoked stays revoked and invalid dates do not read active", () => {
  assert.equal(effectiveStatus("revoked", "2027-01-01T00:00:00Z", NOW), "revoked");
  assert.equal(effectiveStatus("active", "not a date", NOW), "expired");
  assert.equal(effectiveStatus("active", null, NOW), "expired");
});

test("daysLeft: rounds up partial days and never reports negative time", () => {
  assert.equal(daysLeft("2026-10-28T13:00:00Z", NOW), 1);
  assert.equal(daysLeft("2026-11-04T12:00:00Z", NOW), 7);
  assert.equal(daysLeft("2026-10-27T12:00:00Z", NOW), 0);
  assert.equal(daysLeft("not a date", NOW), 0);
});

test("buildQuery: carries filters, search, and pagination", () => {
  assert.equal(
    buildQuery({ status: "pending", q: "ada@example.com", page: 2, pageSize: 50 }),
    "?status=pending&q=ada%40example.com&page=2&page_size=50",
  );
  assert.equal(buildQuery({ page: 1, pageSize: 20 }), "?page=1&page_size=20");
  assert.equal(buildQuery({ status: "", q: "   ", page: 1, pageSize: 20 }), "?page=1&page_size=20");
});

test("buildQuery: clamps page and size to the API's limits", () => {
  assert.equal(buildQuery({ page: 0, pageSize: 0 }), "?page=1&page_size=1");
  assert.equal(buildQuery({ page: 3.7, pageSize: 500 }), "?page=3&page_size=100");
});

test("statusTone: maps each state to an existing badge tone", () => {
  assert.equal(statusTone("active"), "ok");
  assert.equal(statusTone("approved"), "ok");
  assert.equal(statusTone("pending"), "med");
  assert.equal(statusTone("rejected"), "crit");
  assert.equal(statusTone("revoked"), "crit");
  assert.equal(statusTone("expired"), "muted");
  assert.equal(statusTone("mystery"), "muted");
});

test("actionLabel: audit actions read like sentences", () => {
  assert.equal(actionLabel("order.approve"), "Order approved");
  assert.equal(actionLabel("order.reject"), "Order rejected");
  assert.equal(actionLabel("subscription.comp"), "Pro granted");
  assert.equal(actionLabel("subscription.extend"), "Subscription extended");
  assert.equal(actionLabel("subscription.revoke"), "Subscription revoked");
  assert.equal(actionLabel("subscription.rotate"), "Licence rotated");
  assert.equal(actionLabel("settings.update"), "Setting updated");
  assert.equal(actionLabel("admin.login"), "Signed in");
});

test("actionLabel: an unknown action is shown verbatim, never blank", () => {
  assert.equal(actionLabel("order.refund"), "order.refund");
  assert.equal(actionLabel(null), "—");
});

test("parseDetail: renders JSON details inline and leaves plain notes alone", () => {
  assert.equal(parseDetail('{"months":3,"extended":false}'), "months: 3 · extended: false");
  assert.equal(parseDetail("wrong network"), "wrong network");
  assert.equal(parseDetail(null), "—");
  assert.equal(parseDetail(""), "—");
  assert.equal(parseDetail("{not json"), "{not json");
});

test("licenseMessage: includes the key, the expiry, and both activation paths", () => {
  const message = licenseMessage({
    name: "Ada Lovelace",
    email: "ada@example.com",
    key: "THREATS-PRO-ABCDEFGHJKMNPQRSTVWX",
    expiresAt: "2027-01-28T00:00:00Z",
  });

  assert.match(message, /Hi Ada Lovelace,/);
  assert.match(message, /active until 28 Jan 2027/);
  assert.match(message, /THREATS-PRO-ABCDEFGHJKMNPQRSTVWX/);
  assert.match(message, /https:\/\/threats\.top\/pro\.html/);
  assert.match(message, /curl -H "Authorization: Bearer THREATS-PRO-ABCDEFGHJKMNPQRSTVWX"/);
  assert.match(message, /https:\/\/api\.threats\.top\/api\/stix/);
  assert.match(message, /shown once/i);
});

test("licenseMessage: falls back to the email when no name was captured", () => {
  const message = licenseMessage({
    name: "",
    email: "ada@example.com",
    key: "THREATS-PRO-ABCDEFGHJKMNPQRSTVWX",
    expiresAt: "2027-01-28T00:00:00Z",
  });
  assert.match(message, /Hi ada@example\.com,/);
});

test("licenseMessage: an unparseable expiry is stated, not silently dropped", () => {
  const message = licenseMessage({
    name: "Ada", email: "ada@example.com", key: "THREATS-PRO-ABCDEFGHJKMNPQRSTVWX", expiresAt: null,
  });
  assert.match(message, /expiry date is on the subscription record/i);
  assert.ok(!message.includes("Invalid Date"));
});
