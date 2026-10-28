/**
 * Tests for assets/checkout.js
 *
 *     node --test assets/checkout.test.mjs
 *
 * The checkout page formats money, maps API error codes to human copy, and
 * links transaction ids to a block explorer. Each of those is a place where a
 * wrong value is plausible and silent -- "$3900", a raw `rate_limited`, or a
 * Tron txid sent to mempool.space -- so they are plain functions with tests
 * instead of inline DOM code.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  apiOrigin,
  amountFor,
  badgeClass,
  cleanTxRef,
  errorMessage,
  explorerUrl,
  formatUsd,
  isTxRefShape,
  methodLabel,
  orderStatusLabel,
  planLabel,
  walletExplorerUrl,
} from "./checkout.js";

test("formatUsd: renders whole dollars without trailing cents", () => {
  assert.equal(formatUsd(3900), "$39");
  assert.equal(formatUsd(11700), "$117");
  assert.equal(formatUsd(46800), "$468");
  assert.equal(formatUsd(0), "$0");
});

test("formatUsd: keeps cents only when they exist", () => {
  assert.equal(formatUsd(3950), "$39.50");
  assert.equal(formatUsd(5), "$0.05");
  assert.equal(formatUsd(3999), "$39.99");
});

test("formatUsd: groups thousands", () => {
  assert.equal(formatUsd(123456789), "$1,234,567.89");
  assert.equal(formatUsd(100000), "$1,000");
});

test("formatUsd: refuses nonsense rather than printing NaN", () => {
  for (const value of [null, undefined, "", "3900", NaN, -1, Infinity]) {
    assert.equal(formatUsd(value), "—", `failed for ${String(value)}`);
  }
});

test("amountFor: multiplies the monthly price by the term", () => {
  assert.equal(amountFor(3900, 1), 3900);
  assert.equal(amountFor(3900, 3), 11700);
  assert.equal(amountFor(3900, 12), 46800);
});

test("amountFor: rejects terms it cannot price", () => {
  for (const months of [null, undefined, 0, -3, 1.5, "3", NaN]) {
    assert.equal(amountFor(3900, months), null, `failed for ${String(months)}`);
  }
  assert.equal(amountFor(null, 3), null);
});

test("planLabel: singular and plural terms", () => {
  assert.equal(planLabel(1), "1 month");
  assert.equal(planLabel(3), "3 months");
  assert.equal(planLabel(12), "12 months");
  assert.equal(planLabel(2), "2 months");
});

test("planLabel: returns a dash for invalid input", () => {
  for (const months of [null, undefined, 0, -1, 1.5, "3", NaN]) {
    assert.equal(planLabel(months), "—", `failed for ${String(months)}`);
  }
});

test("methodLabel: names the network, not just the coin", () => {
  assert.equal(methodLabel("usdt_trc20"), "USDT · TRON (TRC20)");
  assert.equal(methodLabel("btc"), "Bitcoin · native SegWit");
  assert.equal(methodLabel("eth"), "Unknown method");
  assert.equal(methodLabel(null), "Unknown method");
});

test("explorerUrl: routes each transaction to its own chain", () => {
  const usdt = explorerUrl("usdt_trc20", "a1b2c3d4e5f6");
  assert.equal(usdt, "https://tronscan.org/#/transaction/a1b2c3d4e5f6");
  const btc = explorerUrl("btc", "deadbeef00112233");
  assert.equal(btc, "https://mempool.space/tx/deadbeef00112233");
});

test("explorerUrl: returns null when the reference is empty or unknown", () => {
  assert.equal(explorerUrl("usdt_trc20", ""), null);
  assert.equal(explorerUrl("usdt_trc20", "   "), null);
  assert.equal(explorerUrl("usdt_trc20", null), null);
  assert.equal(explorerUrl("eth", "abc12345"), null);
});

test("explorerUrl: encodes the reference instead of trusting it", () => {
  const url = explorerUrl("usdt_trc20", "ab/cd?x=1");
  assert.equal(url, "https://tronscan.org/#/transaction/ab%2Fcd%3Fx%3D1");
});

test("walletExplorerUrl: links an address so a buyer can verify it independently", () => {
  assert.equal(
    walletExplorerUrl("usdt_trc20", "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2"),
    "https://tronscan.org/#/address/TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2",
  );
  assert.equal(
    walletExplorerUrl("btc", "bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq"),
    "https://mempool.space/address/bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq",
  );
  assert.equal(walletExplorerUrl("usdt_trc20", ""), null);
  assert.equal(walletExplorerUrl("eth", "0xabc"), null);
});

test("errorMessage: maps the API's codes to copy a buyer can act on", () => {
  assert.match(errorMessage("duplicate_tx"), /already attached to an order/i);
  assert.match(errorMessage("rate_limited"), /too many|wait/i);
  assert.match(errorMessage("order_not_found"), /code and email/i);
  assert.match(errorMessage("invalid"), /check/i);
  assert.match(errorMessage("network"), /connection|offline/i);
  assert.match(errorMessage("server"), /nothing was charged|try again/i);
});

test("errorMessage: prefers the server message for codes it does not know", () => {
  assert.equal(errorMessage("some_new_code", "Server said this"), "Server said this");
  assert.equal(errorMessage("some_new_code"), "Something went wrong. Nothing was charged — try again.");
  assert.equal(errorMessage(null), "Something went wrong. Nothing was charged — try again.");
});

test("orderStatusLabel and badgeClass: every state has readable copy", () => {
  assert.equal(orderStatusLabel("pending"), "Awaiting verification");
  assert.equal(orderStatusLabel("approved"), "Approved");
  assert.equal(orderStatusLabel("rejected"), "Rejected");
  assert.equal(orderStatusLabel("expired"), "Expired");
  assert.equal(orderStatusLabel("mystery"), "Unknown");

  assert.equal(badgeClass("pending"), "med");
  assert.equal(badgeClass("approved"), "ok");
  assert.equal(badgeClass("rejected"), "crit");
  assert.equal(badgeClass("expired"), "muted");
  assert.equal(badgeClass("mystery"), "muted");
});

test("cleanTxRef: strips the whitespace people paste along with a hash", () => {
  assert.equal(cleanTxRef("  abc12345 \n"), "abc12345");
  assert.equal(cleanTxRef("ab\tcd ef"), "abcdef");
  assert.equal(cleanTxRef(null), "");
});

test("isTxRefShape: mirrors the server's 8-128 character reference rule", () => {
  assert.equal(isTxRefShape("a1b2c3d4"), true);
  assert.equal(isTxRefShape("0xabc_DEF-123:456"), true);
  assert.equal(isTxRefShape("a1b2c3d"), false, "seven characters is too short");
  assert.equal(isTxRefShape("a".repeat(128)), true);
  assert.equal(isTxRefShape("a".repeat(129)), false);
  assert.equal(isTxRefShape("abc 12345"), false, "spaces are not part of a hash");
  assert.equal(isTxRefShape("абвгдежз"), false, "non-ASCII is not a hash");
  assert.equal(isTxRefShape(null), false);
});

test("apiOrigin: localhost talks to the local Worker, production to the API host", () => {
  assert.equal(apiOrigin("localhost"), "http://localhost:8787");
  assert.equal(apiOrigin("127.0.0.1"), "http://localhost:8787");
  assert.equal(apiOrigin("::1"), "http://localhost:8787");
  assert.equal(apiOrigin("threats.top"), "https://api.threats.top");
  assert.equal(apiOrigin("nestho.github.io"), "https://api.threats.top");
  assert.equal(apiOrigin(""), "https://api.threats.top");
});

test("apiOrigin: an explicit override wins, for staging or a tunnel", () => {
  assert.equal(apiOrigin("threats.top", "https://api.staging.test"), "https://api.staging.test");
  assert.equal(apiOrigin("localhost", "https://api.staging.test"), "https://api.staging.test");
});
