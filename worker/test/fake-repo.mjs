/**
 * In-memory repository used by handler tests.
 *
 * It mirrors `worker/src/repo.mjs` method for method: same shapes, same
 * filters, same unique constraints. Keep the two files in step.
 */

import { defaultSettings } from "../src/settings.mjs";

const NUMERIC_SETTINGS = new Set([
  "pro_monthly_cents",
  "stix_rate_per_min",
  "order_retention_days",
]);

const clone = (value) => (value === null || value === undefined ? value : structuredClone(value));

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

const lower = (value) => String(value ?? "").toLowerCase();

const byNewest = (a, b) => (a.created_at === b.created_at ? String(b.id).localeCompare(String(a.id)) : b.created_at.localeCompare(a.created_at));

export function createFakeRepo(seed = {}) {
  const state = {
    settings: new Map(
      Object.entries({ ...defaultSettings, ...(seed.settings ?? {}) }).map(([key, value]) => [key, String(value)]),
    ),
    customers: [],
    orders: [],
    subscriptions: [],
    licenses: [],
    audit: [],
    logins: [],
    windows: new Map(),
    auditSeq: 0,
  };

  for (const customer of seed.customers ?? []) state.customers.push(clone(customer));
  for (const order of seed.orders ?? []) state.orders.push(clone(order));
  for (const subscription of seed.subscriptions ?? []) state.subscriptions.push(clone(subscription));
  for (const license of seed.licenses ?? []) state.licenses.push(clone(license));

  const repo = {
    async getSettings() {
      const out = {};
      for (const [key, value] of state.settings) {
        out[key] = NUMERIC_SETTINGS.has(key) ? Number(value) : value;
      }
      return out;
    },

    async putSetting(key, value) {
      state.settings.set(key, String(value));
    },

    async upsertCustomer({ id, email, name, phone, now }) {
      const existing = state.customers.find((row) => lower(row.email) === lower(email));
      if (existing) {
        existing.name = name;
        existing.phone = phone;
        existing.updated_at = now;
        return clone(existing);
      }
      const customer = { id, email, name, phone, created_at: now, updated_at: now };
      state.customers.push(customer);
      return clone(customer);
    },

    async findCustomerByEmail(email) {
      return clone(state.customers.find((row) => lower(row.email) === lower(email)) ?? null);
    },

    async getCustomer(id) {
      return clone(state.customers.find((row) => row.id === id) ?? null);
    },

    async listCustomers({ search = "", limit = 50, offset = 0 } = {}) {
      const needle = lower(search);
      const rows = state.customers
        .filter((row) => !needle || lower(row.email).includes(needle) || lower(row.name).includes(needle))
        .sort(byNewest);
      return { items: clone(rows.slice(offset, offset + limit)), total: rows.length };
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
      if (state.orders.some((row) => row.code === order.code)) {
        throw fail("DUPLICATE_CODE", `order code ${order.code} already exists`);
      }
      if (state.orders.some((row) => row.method === order.method && row.tx_ref === order.tx_ref)) {
        throw fail("DUPLICATE_TX", `transaction ${order.tx_ref} already has an order`);
      }
      state.orders.push(order);
      return clone(order);
    },

    async findOrderByCode(code) {
      return clone(state.orders.find((row) => row.code === code) ?? null);
    },

    async findOrderByTx(method, txRef) {
      return clone(state.orders.find((row) => row.method === method && row.tx_ref === txRef) ?? null);
    },

    async getOrder(id) {
      return clone(state.orders.find((row) => row.id === id) ?? null);
    },

    async listOrders({ status, search = "", customer_id, limit = 50, offset = 0 } = {}) {
      const needle = lower(search);
      const rows = state.orders
        .filter((row) => !status || row.status === status)
        .filter((row) => !customer_id || row.customer_id === customer_id)
        .filter(
          (row) =>
            !needle ||
            lower(row.code).includes(needle) ||
            lower(row.email).includes(needle) ||
            lower(row.tx_ref).includes(needle) ||
            lower(row.name).includes(needle),
        )
        .sort(byNewest);
      return { items: clone(rows.slice(offset, offset + limit)), total: rows.length };
    },

    async markOrder(id, fields) {
      const order = state.orders.find((row) => row.id === id);
      if (!order) return null;
      for (const key of ["status", "reviewed_at", "reviewed_by", "review_note", "updated_at"]) {
        if (key in fields) order[key] = fields[key];
      }
      return clone(order);
    },

    async insertSubscription(input) {
      const subscription = {
        plan: "pro",
        status: "active",
        source_order_id: null,
        note: null,
        ...input,
      };
      state.subscriptions.push(subscription);
      return clone(subscription);
    },

    async getSubscription(id) {
      return clone(state.subscriptions.find((row) => row.id === id) ?? null);
    },

    async activeSubscriptionFor(customerId, now) {
      const rows = state.subscriptions
        .filter((row) => row.customer_id === customerId && row.status === "active" && row.expires_at > now)
        .sort((a, b) => b.expires_at.localeCompare(a.expires_at));
      return clone(rows[0] ?? null);
    },

    async listSubscriptions({ status, search = "", limit = 50, offset = 0 } = {}) {
      const needle = lower(search);
      const activeLicense = (subscriptionId) =>
        state.licenses
          .filter((row) => row.subscription_id === subscriptionId && row.status === "active")
          .sort(byNewest)[0];
      const rows = state.subscriptions
        .map((row) => {
          const customer = state.customers.find((entry) => entry.id === row.customer_id);
          const license = activeLicense(row.id);
          return { ...row, customer_email: customer?.email ?? "", license_prefix: license?.key_prefix ?? null };
        })
        .filter((row) => !status || row.status === status)
        .filter((row) => !needle || lower(row.customer_email).includes(needle) || lower(row.id).includes(needle))
        .sort(byNewest);
      return { items: clone(rows.slice(offset, offset + limit)), total: rows.length };
    },

    async updateSubscription(id, fields) {
      const subscription = state.subscriptions.find((row) => row.id === id);
      if (!subscription) return null;
      for (const key of ["status", "expires_at", "updated_at", "note"]) {
        if (key in fields) subscription[key] = fields[key];
      }
      return clone(subscription);
    },

    async insertLicense(input) {
      if (state.licenses.some((row) => row.key_hash === input.key_hash)) {
        throw fail("DUPLICATE_LICENSE", "licence hash already exists");
      }
      const license = { status: "active", last_used_at: null, revoked_at: null, ...input };
      state.licenses.push(license);
      return clone(license);
    },

    async findLicenseByHash(hash) {
      return clone(state.licenses.find((row) => row.key_hash === hash) ?? null);
    },

    async licenseForSubscription(subscriptionId) {
      const license = state.licenses
        .filter((row) => row.subscription_id === subscriptionId && row.status === "active")
        .sort(byNewest)[0];
      return clone(license ?? null);
    },

    async revokeLicenses(subscriptionId, now) {
      let count = 0;
      for (const license of state.licenses) {
        if (license.subscription_id === subscriptionId && license.status === "active") {
          license.status = "revoked";
          license.revoked_at = now;
          count += 1;
        }
      }
      return count;
    },

    async touchLicense(id, now) {
      const license = state.licenses.find((row) => row.id === id);
      if (license) license.last_used_at = now;
    },

    async audit({ at, actor, action, target, detail = null }) {
      state.auditSeq += 1;
      state.audit.push({ id: state.auditSeq, at, actor, action, target, detail });
    },

    async listAudit({ limit = 50, offset = 0 } = {}) {
      const rows = [...state.audit].sort((a, b) => (a.at === b.at ? b.id - a.id : b.at.localeCompare(a.at)));
      return { items: clone(rows.slice(offset, offset + limit)), total: rows.length };
    },

    async stats(now, since = Date.parse(now) - 30 * 86_400_000) {
      const sinceIso = typeof since === "number" ? new Date(since).toISOString().replace(".000Z", "Z") : since;
      const soon = new Date(Date.parse(now) + 7 * 86_400_000).toISOString().replace(".000Z", "Z");
      const active = state.subscriptions.filter((row) => row.status === "active" && row.expires_at > now);
      const mrr = active.reduce((sum, row) => {
        const order = state.orders.find((entry) => entry.id === row.source_order_id);
        return order ? sum + Math.floor(order.amount_cents / order.months) : sum;
      }, 0);
      const approved = state.orders.filter(
        (row) => row.status === "approved" && row.reviewed_at && row.reviewed_at >= sinceIso,
      );
      return {
        pending_orders: state.orders.filter((row) => row.status === "pending").length,
        active_subscriptions: active.length,
        expiring_soon: active.filter((row) => row.expires_at <= soon).length,
        mrr_cents: mrr,
        orders_30d: state.orders.filter((row) => row.created_at >= sinceIso).length,
        revenue_cents_30d: approved.reduce((sum, row) => sum + row.amount_cents, 0),
        customers: state.customers.length,
      };
    },

    async hitRate(key, windowStart, limit) {
      const windowKey = `${key}:${windowStart}`;
      const count = (state.windows.get(windowKey) ?? 0) + 1;
      state.windows.set(windowKey, count);
      return count <= limit;
    },

    async recordLogin({ at, ip_hash, ok }) {
      state.logins.push({ at, ip_hash, ok: ok ? 1 : 0 });
    },

    async recentFailures(ipHash, sinceIso) {
      return state.logins.filter((row) => row.ip_hash === ipHash && row.ok === 0 && row.at >= sinceIso).length;
    },

    async prune({ ordersBefore, attemptsBefore, windowsBefore }) {
      state.orders = state.orders.filter(
        (row) => !(row.status === "pending" && row.created_at < ordersBefore),
      );
      state.logins = state.logins.filter((row) => row.at >= attemptsBefore);
      for (const windowKey of [...state.windows.keys()]) {
        const windowStart = Number(windowKey.slice(windowKey.lastIndexOf(":") + 1));
        if (windowStart < windowsBefore) state.windows.delete(windowKey);
      }
      return { orders: 0, logins: 0, windows: 0 };
    },
  };

  return repo;
}
