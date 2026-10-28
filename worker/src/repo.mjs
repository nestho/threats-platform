/**
 * D1 adapter: the only place in the Worker that knows SQL.
 *
 * The in-memory fake in `worker/test/fake-repo.mjs` mirrors this surface so
 * handler tests never need a database. Column names are returned as-is.
 */

const NUMERIC_SETTINGS = new Set([
  "pro_monthly_cents",
  "stix_rate_per_min",
  "order_retention_days",
]);

function translate(error) {
  const message = String(error?.message ?? "");
  if (message.includes("orders.code")) return Object.assign(error, { code: "DUPLICATE_CODE" });
  if (message.includes("orders.method") || message.includes("orders.tx_ref")) {
    return Object.assign(error, { code: "DUPLICATE_TX" });
  }
  if (message.includes("licenses.key_hash")) {
    return Object.assign(error, { code: "DUPLICATE_LICENSE" });
  }
  return error;
}

export async function createRepo(db) {
  const first = async (sql, ...params) => (await db.prepare(sql).bind(...params).first()) ?? null;
  const all = async (sql, ...params) => (await db.prepare(sql).bind(...params).all()).results ?? [];
  const run = async (sql, ...params) => (await db.prepare(sql).bind(...params).run()).meta ?? {};

  return {
    async getSettings() {
      const rows = await all("SELECT key, value FROM settings");
      const out = {};
      for (const row of rows) {
        out[row.key] = NUMERIC_SETTINGS.has(row.key) ? Number(row.value) : row.value;
      }
      return out;
    },

    async putSetting(key, value) {
      await run(
        `INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
        key,
        String(value),
      );
    },

    async upsertCustomer({ id, email, name, phone, now }) {
      const existing = await first("SELECT * FROM customers WHERE email = ?", email);
      if (existing) {
        await run(
          "UPDATE customers SET name = ?, phone = ?, updated_at = ? WHERE id = ?",
          name,
          phone,
          now,
          existing.id,
        );
        return { ...existing, name, phone, updated_at: now };
      }
      await run(
        "INSERT INTO customers (id, email, name, phone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        id,
        email,
        name,
        phone,
        now,
        now,
      );
      return { id, email, name, phone, created_at: now, updated_at: now };
    },

    async findCustomerByEmail(email) {
      return first("SELECT * FROM customers WHERE email = ?", email);
    },

    async getCustomer(id) {
      return first("SELECT * FROM customers WHERE id = ?", id);
    },

    async listCustomers({ search = "", limit = 50, offset = 0 } = {}) {
      const like = `%${search}%`;
      const filter = search ? "WHERE email LIKE ? OR name LIKE ?" : "";
      const params = search ? [like, like] : [];
      const [{ total }] = await all(`SELECT COUNT(*) AS total FROM customers ${filter}`, ...params);
      const items = await all(
        `SELECT * FROM customers ${filter} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
        ...params,
        limit,
        offset,
      );
      return { items, total };
    },

    async insertOrder(input) {
      const order = {
        plan: "pro",
        currency: "USD",
        status: "pending",
        phone: null,
        note: null,
        reviewed_at: null,
        reviewed_by: null,
        review_note: null,
        ip_hash: null,
        user_agent_hash: null,
        ...input,
      };
      try {
        await run(
          `INSERT INTO orders (
             id, code, customer_id, email, name, phone, plan, months, amount_cents,
             currency, method, tx_ref, note, status, created_at, updated_at,
             reviewed_at, reviewed_by, review_note, ip_hash, user_agent_hash
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          order.id,
          order.code,
          order.customer_id,
          order.email,
          order.name,
          order.phone,
          order.plan,
          order.months,
          order.amount_cents,
          order.currency,
          order.method,
          order.tx_ref,
          order.note,
          order.status,
          order.created_at,
          order.updated_at,
          order.reviewed_at,
          order.reviewed_by,
          order.review_note,
          order.ip_hash,
          order.user_agent_hash,
        );
      } catch (error) {
        throw translate(error);
      }
      return order;
    },

    async findOrderByCode(code) {
      return first("SELECT * FROM orders WHERE code = ?", code);
    },

    async findOrderByTx(method, txRef) {
      return first("SELECT * FROM orders WHERE method = ? AND tx_ref = ?", method, txRef);
    },

    async getOrder(id) {
      return first("SELECT * FROM orders WHERE id = ?", id);
    },

    async listOrders({ status, search = "", customer_id, limit = 50, offset = 0 } = {}) {
      const clauses = [];
      const params = [];
      if (status) {
        clauses.push("status = ?");
        params.push(status);
      }
      if (customer_id) {
        clauses.push("customer_id = ?");
        params.push(customer_id);
      }
      if (search) {
        clauses.push("(code LIKE ? OR email LIKE ? OR tx_ref LIKE ? OR name LIKE ?)");
        const like = `%${search}%`;
        params.push(like, like, like, like);
      }
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      const [{ total }] = await all(`SELECT COUNT(*) AS total FROM orders ${where}`, ...params);
      const items = await all(
        `SELECT * FROM orders ${where} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
        ...params,
        limit,
        offset,
      );
      return { items, total };
    },

    async markOrder(id, fields) {
      const allowed = ["status", "reviewed_at", "reviewed_by", "review_note", "updated_at"];
      const sets = [];
      const params = [];
      for (const key of allowed) {
        if (key in fields) {
          sets.push(`${key} = ?`);
          params.push(fields[key]);
        }
      }
      if (!sets.length) return first("SELECT * FROM orders WHERE id = ?", id);
      await run(`UPDATE orders SET ${sets.join(", ")} WHERE id = ?`, ...params, id);
      return first("SELECT * FROM orders WHERE id = ?", id);
    },

    async insertSubscription(input) {
      const subscription = {
        plan: "pro",
        status: "active",
        source_order_id: null,
        note: null,
        ...input,
      };
      await run(
        `INSERT INTO subscriptions (
           id, customer_id, plan, status, started_at, expires_at,
           source_order_id, note, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        subscription.id,
        subscription.customer_id,
        subscription.plan,
        subscription.status,
        subscription.started_at,
        subscription.expires_at,
        subscription.source_order_id,
        subscription.note,
        subscription.created_at,
        subscription.updated_at,
      );
      return subscription;
    },

    async getSubscription(id) {
      return first("SELECT * FROM subscriptions WHERE id = ?", id);
    },

    async activeSubscriptionFor(customerId, now) {
      return first(
        `SELECT * FROM subscriptions
         WHERE customer_id = ? AND status = 'active' AND expires_at > ?
         ORDER BY expires_at DESC LIMIT 1`,
        customerId,
        now,
      );
    },

    async listSubscriptions({ status, search = "", limit = 50, offset = 0 } = {}) {
      const clauses = [];
      const params = [];
      if (status) {
        clauses.push("s.status = ?");
        params.push(status);
      }
      if (search) {
        clauses.push("(c.email LIKE ? OR s.id LIKE ?)");
        params.push(`%${search}%`, `%${search}%`);
      }
      const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
      const [{ total }] = await all(
        `SELECT COUNT(*) AS total FROM subscriptions s JOIN customers c ON c.id = s.customer_id ${where}`,
        ...params,
      );
      const items = await all(
        `SELECT s.*, c.email AS customer_email, active.key_prefix AS license_prefix
         FROM subscriptions s
         JOIN customers c ON c.id = s.customer_id
         LEFT JOIN licenses active ON active.id = (
           SELECT id FROM licenses
           WHERE subscription_id = s.id AND status = 'active'
           ORDER BY created_at DESC LIMIT 1
         )
         ${where}
         ORDER BY s.created_at DESC, s.id DESC
         LIMIT ? OFFSET ?`,
        ...params,
        limit,
        offset,
      );
      return { items, total };
    },

    async updateSubscription(id, fields) {
      const allowed = ["status", "expires_at", "updated_at", "note"];
      const sets = [];
      const params = [];
      for (const key of allowed) {
        if (key in fields) {
          sets.push(`${key} = ?`);
          params.push(fields[key]);
        }
      }
      if (!sets.length) return first("SELECT * FROM subscriptions WHERE id = ?", id);
      await run(`UPDATE subscriptions SET ${sets.join(", ")} WHERE id = ?`, ...params, id);
      return first("SELECT * FROM subscriptions WHERE id = ?", id);
    },

    async insertLicense(input) {
      const license = { status: "active", last_used_at: null, revoked_at: null, ...input };
      try {
        await run(
          `INSERT INTO licenses (
             id, subscription_id, customer_id, key_hash, key_prefix,
             status, created_at, last_used_at, revoked_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          license.id,
          license.subscription_id,
          license.customer_id,
          license.key_hash,
          license.key_prefix,
          license.status,
          license.created_at,
          license.last_used_at,
          license.revoked_at,
        );
      } catch (error) {
        throw translate(error);
      }
      return license;
    },

    async findLicenseByHash(hash) {
      return first("SELECT * FROM licenses WHERE key_hash = ?", hash);
    },

    async licenseForSubscription(subscriptionId) {
      return first(
        `SELECT * FROM licenses WHERE subscription_id = ? AND status = 'active'
         ORDER BY created_at DESC LIMIT 1`,
        subscriptionId,
      );
    },

    async revokeLicenses(subscriptionId, now) {
      const meta = await run(
        `UPDATE licenses SET status = 'revoked', revoked_at = ?
         WHERE subscription_id = ? AND status = 'active'`,
        now,
        subscriptionId,
      );
      return meta.changes ?? 0;
    },

    async touchLicense(id, now) {
      await run("UPDATE licenses SET last_used_at = ? WHERE id = ?", now, id);
    },

    async audit({ at, actor, action, target, detail = null }) {
      await run(
        "INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
        at,
        actor,
        action,
        target,
        detail,
      );
    },

    async listAudit({ limit = 50, offset = 0 } = {}) {
      const [{ total }] = await all("SELECT COUNT(*) AS total FROM audit_log");
      const items = await all(
        "SELECT * FROM audit_log ORDER BY at DESC, id DESC LIMIT ? OFFSET ?",
        limit,
        offset,
      );
      return { items, total };
    },

    async stats(now, since) {
      const soon = new Date(Date.parse(now) + 7 * 86_400_000).toISOString().replace(".000Z", "Z");
      const sinceIso =
        typeof since === "number" ? new Date(since).toISOString().replace(".000Z", "Z") : since;
      const row = await first(
        `SELECT
           (SELECT COUNT(*) FROM orders WHERE status = 'pending') AS pending_orders,
           (SELECT COUNT(*) FROM subscriptions
             WHERE status = 'active' AND expires_at > ?1) AS active_subscriptions,
           (SELECT COUNT(*) FROM subscriptions
             WHERE status = 'active' AND expires_at > ?1 AND expires_at <= ?2) AS expiring_soon,
           (SELECT COALESCE(SUM(o.amount_cents / o.months), 0)
             FROM subscriptions s JOIN orders o ON o.id = s.source_order_id
             WHERE s.status = 'active' AND s.expires_at > ?1) AS mrr_cents,
           (SELECT COUNT(*) FROM orders WHERE created_at >= ?3) AS orders_30d,
           (SELECT COALESCE(SUM(amount_cents), 0) FROM orders
             WHERE status = 'approved' AND reviewed_at >= ?3) AS revenue_cents_30d,
           (SELECT COUNT(*) FROM customers) AS customers`,
        now,
        soon,
        sinceIso,
      );
      return row;
    },

    async hitRate(key, windowStart, limit) {
      const row = await first(
        `INSERT INTO rate_limit (key, window_start, count) VALUES (?, ?, 1)
         ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1
         RETURNING count`,
        key,
        windowStart,
      );
      return (row?.count ?? 0) <= limit;
    },

    async recordLogin({ at, ip_hash, ok }) {
      await run("INSERT INTO login_attempts (at, ip_hash, ok) VALUES (?, ?, ?)", at, ip_hash, ok ? 1 : 0);
    },

    async recentFailures(ipHash, sinceIso) {
      const row = await first(
        "SELECT COUNT(*) AS total FROM login_attempts WHERE ip_hash = ? AND ok = 0 AND at >= ?",
        ipHash,
        sinceIso,
      );
      return row?.total ?? 0;
    },

    async prune({ ordersBefore, attemptsBefore, windowsBefore }) {
      const orders = await run("DELETE FROM orders WHERE status = 'pending' AND created_at < ?", ordersBefore);
      const logins = await run("DELETE FROM login_attempts WHERE at < ?", attemptsBefore);
      const windows = await run("DELETE FROM rate_limit WHERE window_start < ?", windowsBefore);
      return {
        orders: orders.changes ?? 0,
        logins: logins.changes ?? 0,
        windows: windows.changes ?? 0,
      };
    },
  };
}
