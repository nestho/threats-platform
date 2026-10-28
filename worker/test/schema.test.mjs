/**
 * Applies the real migration with the sqlite3 CLI, so a syntax error or a
 * missing constraint fails here instead of in production D1.
 *
 *     node --test worker/test/schema.test.mjs
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATION = join(HERE, "..", "migrations", "0001_init.sql");

function sqlite(db, sql) {
  return execFileSync("sqlite3", [db], { input: sql, encoding: "utf8" });
}

function freshDatabase() {
  const dir = mkdtempSync(join(tmpdir(), "threats-schema-"));
  const db = join(dir, "test.sqlite");
  sqlite(db, readFileSync(MIGRATION, "utf8"));
  return { db, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("the migration creates every table and index", () => {
  const { db, cleanup } = freshDatabase();
  try {
    const tables = sqlite(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
      .trim().split("\n");
    for (const table of [
      "audit_log", "customers", "licenses", "login_attempts",
      "orders", "rate_limit", "settings", "subscriptions",
    ]) {
      assert.ok(tables.includes(table), `missing table ${table}`);
    }
    const indexes = sqlite(db, "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
      .trim().split("\n");
    for (const index of [
      "audit_at", "licenses_subscription", "login_attempts_ip_at",
      "orders_customer", "orders_email", "orders_status_created",
      "subscriptions_customer", "subscriptions_status_expires",
    ]) {
      assert.ok(indexes.includes(index), `missing index ${index}`);
    }
  } finally {
    cleanup();
  }
});

test("settings ship with the real wallets and price", () => {
  const { db, cleanup } = freshDatabase();
  try {
    const rows = sqlite(db, "SELECT key || '=' || value FROM settings ORDER BY key;").trim().split("\n");
    assert.ok(rows.includes("pro_monthly_cents=3900"));
    assert.ok(rows.includes("usdt_trc20_address=TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2"));
    assert.ok(rows.includes("btc_address=bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq"));
  } finally {
    cleanup();
  }
});

test("a transaction hash cannot back two orders", () => {
  const { db, cleanup } = freshDatabase();
  try {
    const insert = (id) => `
      INSERT INTO customers (id, email, name, created_at, updated_at)
      VALUES ('c1', 'a@example.com', 'A', '2026-10-28T00:00:00Z', '2026-10-28T00:00:00Z');
      INSERT INTO orders (id, code, customer_id, email, name, months, amount_cents,
        method, tx_ref, status, created_at, updated_at)
      VALUES ('${id}', '${id}', 'c1', 'a@example.com', 'A', 1, 3900,
        'btc', 'tx-abc-123', 'pending', '2026-10-28T00:00:00Z', '2026-10-28T00:00:00Z');
    `;
    sqlite(db, insert("o1"));
    assert.throws(() => sqlite(db, insert("o2")), /UNIQUE constraint failed/);
  } finally {
    cleanup();
  }
});
