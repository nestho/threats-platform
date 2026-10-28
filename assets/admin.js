/*
 * Admin panel helpers and wiring.
 *
 * Pure helpers at the top are imported by admin.test.mjs under Node; nothing
 * here touches `document` until initAdmin() runs. Every value rendered into the
 * DOM goes through textContent -- no innerHTML in this file.
 */

import { initTabs, showToast, timeAgo } from "./app.js";
import {
  apiOrigin,
  explorerUrl,
  formatUsd,
  methodLabel,
  orderStatusLabel,
  planLabel,
} from "./checkout.js";

/* ── Pure helpers ───────────────────────────────────────────────────── */

export function effectiveStatus(status, expiresAt, now = Date.now()) {
  if (status === "revoked") return "revoked";
  const time = new Date(expiresAt).getTime();
  if (Number.isNaN(time)) return "expired";
  return time > now ? "active" : "expired";
}

export function daysLeft(expiresAt, now = Date.now()) {
  const time = new Date(expiresAt).getTime();
  if (Number.isNaN(time)) return 0;
  const remaining = time - now;
  return remaining > 0 ? Math.ceil(remaining / 86_400_000) : 0;
}

export function buildQuery({ status, q, page = 1, pageSize = 20 } = {}) {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (q && String(q).trim()) params.set("q", String(q).trim());
  params.set("page", String(Math.max(1, Math.trunc(Number(page) || 1))));
  params.set("page_size", String(Math.min(100, Math.max(1, Math.trunc(Number(pageSize) || 1)))));
  return `?${params}`;
}

const STATUS_TONES = {
  active: "ok",
  approved: "ok",
  pending: "med",
  rejected: "crit",
  revoked: "crit",
  expired: "muted",
};

export function statusTone(status) {
  return STATUS_TONES[status] ?? "muted";
}

const ACTION_LABELS = {
  "admin.login": "Signed in",
  "order.approve": "Order approved",
  "order.reject": "Order rejected",
  "subscription.comp": "Pro granted",
  "subscription.extend": "Subscription extended",
  "subscription.revoke": "Subscription revoked",
  "subscription.rotate": "Licence rotated",
  "settings.update": "Setting updated",
};

export function actionLabel(action) {
  if (!action) return "—";
  return ACTION_LABELS[action] ?? action;
}

export function parseDetail(detail) {
  if (!detail) return "—";
  try {
    const value = JSON.parse(detail);
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return Object.entries(value).map(([key, item]) => `${key}: ${item}`).join(" · ");
    }
    return String(value);
  } catch {
    return String(detail);
  }
}

function formatDay(iso) {
  if (!iso) return null;
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return null;
  return new Date(time).toLocaleDateString("en-GB", {
    day: "2-digit", month: "short", year: "numeric", timeZone: "UTC",
  });
}

export function licenseMessage({ name, email, key, expiresAt }) {
  const who = String(name ?? "").trim() || String(email ?? "").trim() || "there";
  const day = formatDay(expiresAt);
  const expiry = day ? `active until ${day}` : "expiry date is on the subscription record";
  return [
    `Hi ${who},`,
    "",
    `Your Threats Pro licence is ${expiry}.`,
    "",
    "Key:",
    key,
    "",
    "Activate and download STIX: https://threats.top/pro.html",
    `API: curl -H "Authorization: Bearer ${key}" https://api.threats.top/api/stix -o threats-stix.json`,
    "",
    "The key is shown once. Rotating it invalidates this one.",
  ].join("\n");
}

/* ── Page wiring ────────────────────────────────────────────────────── */

const SETTING_KEYS = [
  "pro_monthly_cents",
  "usdt_trc20_address",
  "btc_address",
  "stix_rate_per_min",
  "support_email",
  "order_retention_days",
];

const NUMERIC_SETTINGS = new Set([
  "pro_monthly_cents",
  "stix_rate_per_min",
  "order_retention_days",
]);

const SUB_LABELS = {
  active: "Active",
  expired: "Expired",
  revoked: "Revoked",
};

function formatDate(iso) {
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  return new Date(time).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

function timeOfDay(iso) {
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  return new Date(time).toISOString().slice(11, 16) + "Z";
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

export function initAdmin({ hostname, origin, fetchImpl = fetch } = {}) {
  const api = origin ?? apiOrigin(hostname ?? location.hostname);
  const $ = (id) => document.getElementById(id);

  const state = {
    authed: false,
    csrf: null,
    expiresAt: 0,
    view: "overview",
    tabsReady: false,
    timer: null,
    order: null,
    orderMode: null,
    orderCanReview: false,
    sub: null,
    subMode: null,
    settings: null,
    orders: { page: 1, status: "", q: "" },
    subscriptions: { page: 1, status: "", q: "" },
    customers: { page: 1, q: "" },
    audit: { page: 1 },
  };

  /* Session and transport */

  function expireSession() {
    if (!state.authed) return;
    showLogin("Session expired. Sign in again.");
  }

  async function request(path, { method = "GET", body, mutate = false } = {}) {
    try {
      const response = await fetchImpl(api + path, {
        method,
        credentials: "include",
        headers: {
          ...(body ? { "content-type": "application/json" } : {}),
          ...(mutate && state.csrf ? { "x-csrf-token": state.csrf } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      let data = null;
      try { data = await response.json(); } catch { /* empty body */ }
      if (response.status === 401 && path !== "/api/admin/login") expireSession();
      return { ok: response.ok, status: response.status, data };
    } catch {
      return { ok: false, status: 0, data: { error: { code: "network", message: "Could not reach the admin API." } } };
    }
  }

  function errorText(result, fallback = "Something went wrong. Try again.") {
    return result?.data?.error?.message || fallback;
  }

  function setAlert(element, message) {
    if (!element) return;
    element.hidden = !message;
    element.textContent = message ?? "";
  }

  function updateSessionMeta() {
    const meta = $("session-meta");
    if (!meta || !state.expiresAt) return;
    meta.textContent = `Session · expires ${timeOfDay(state.expiresAt)}`;
  }

  function clearSession(message) {
    state.authed = false;
    state.csrf = null;
    state.expiresAt = 0;
    clearInterval(state.timer);
    state.timer = null;
    state.settings = null;
    $("app-view").hidden = true;
    $("login-view").hidden = false;
    $("login-password").value = "";
    $("login-code").value = "";
    setAlert($("login-alert"), message ?? "");
    $("login-password").focus();
  }

  function showLogin(message) {
    clearSession(message);
  }

  function showApp(session) {
    state.authed = true;
    state.csrf = session.csrf;
    state.expiresAt = new Date(session.expires_at).getTime();
    $("login-view").hidden = true;
    $("app-view").hidden = false;
    setAlert($("login-alert"), "");
    updateSessionMeta();

    if (!state.tabsReady) {
      initTabs("#admin-tabs", (view) => activateView(view));
      state.tabsReady = true;
    }
    activateView("overview");
    $("app-title").focus();

    clearInterval(state.timer);
    state.timer = setInterval(() => {
      if (!state.authed) return;
      if (Date.now() >= state.expiresAt) {
        expireSession();
        return;
      }
      updateSessionMeta();
    }, 30_000);
  }

  /* Views */

  function activateView(view) {
    state.view = view;
    for (const panel of document.querySelectorAll(".admin-panel")) {
      panel.hidden = panel.id !== `panel-${view}`;
    }
    if (view === "overview") loadOverview();
    else if (view === "orders") loadOrders();
    else if (view === "subscriptions") loadSubscriptions();
    else if (view === "customers") loadCustomers();
    else if (view === "audit") loadAudit();
    else if (view === "settings") loadSettings();
  }

  function selectView(view) {
    const tab = document.querySelector(`#admin-tabs [data-view="${view}"]`);
    if (tab) tab.click();
    else activateView(view);
  }

  function rowMessage(text, columns) {
    const tr = node("tr");
    const td = node("td", "table-message", text);
    td.colSpan = columns;
    tr.append(td);
    return tr;
  }

  function statusBadge(status, label) {
    return node("span", `badge ${statusTone(status)}`, label);
  }

  function money(cents) {
    return formatUsd(cents);
  }

  function renderPager(container, { page, pageSize, total }, onPage) {
    container.replaceChildren();
    const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, total);
    container.append(node("span", "pager-info", `${start}–${end} of ${total}`));

    const actions = node("div", "pager-actions");
    const prev = node("button", "btn btn-sm", "← Prev");
    prev.type = "button";
    prev.disabled = page <= 1;
    prev.addEventListener("click", () => onPage(page - 1));
    const next = node("button", "btn btn-sm", "Next →");
    next.type = "button";
    next.disabled = page * pageSize >= total;
    next.addEventListener("click", () => onPage(page + 1));
    actions.append(prev, next);
    container.append(actions);
  }

  /* Overview */

  async function loadOverview() {
    setAlert($("overview-alert"), "");
    const [statsResult, pendingResult] = await Promise.all([
      request("/api/admin/stats"),
      request(`/api/admin/orders${buildQuery({ status: "pending", page: 1, pageSize: 6 })}`),
    ]);

    if (!statsResult.ok) {
      setAlert($("overview-alert"), errorText(statsResult, "Could not load the dashboard."));
    } else {
      const stats = statsResult.data.stats;
      $("stat-pending").textContent = String(stats.pending_orders ?? 0);
      $("stat-active").textContent = String(stats.active_subscriptions ?? 0);
      $("stat-mrr").textContent = money(stats.mrr_cents ?? 0);
      $("stat-expiring").textContent = String(stats.expiring_soon ?? 0);
      $("stat-orders30").textContent = String(stats.orders_30d ?? 0);
      $("stat-revenue30").textContent = money(stats.revenue_cents_30d ?? 0);
      $("stat-customers").textContent = String(stats.customers ?? 0);
    }

    const body = $("overview-pending-body");
    body.replaceChildren();
    if (!pendingResult.ok) {
      body.append(rowMessage(errorText(pendingResult, "Could not load pending orders."), 6));
      return;
    }
    const { items } = pendingResult.data;
    if (!items.length) {
      body.append(rowMessage("No orders are waiting for review.", 6));
      return;
    }
    for (const order of items) {
      const tr = node("tr");
      tr.append(
        node("td", "mono", order.code),
        buyerCell(order),
        node("td", null, planLabel(order.months)),
        node("td", "money", money(order.amount_cents)),
        node("td", null, timeAgo(order.created_at)),
      );
      const actions = node("td");
      const review = node("button", "btn btn-sm", "Review");
      review.type = "button";
      review.addEventListener("click", () => openOrder(order.id));
      actions.append(review);
      tr.append(actions);
      body.append(tr);
    }
  }

  function buyerCell(order) {
    const td = node("td");
    td.append(node("div", null, order.name), node("div", "subline", order.email));
    return td;
  }

  /* Orders */

  async function loadOrders() {
    const body = $("orders-body");
    body.replaceChildren(rowMessage("Loading…", 8));
    const result = await request(
      `/api/admin/orders${buildQuery({ ...state.orders, pageSize: 20 })}`,
    );
    body.replaceChildren();
    if (!result.ok) {
      body.append(rowMessage(errorText(result, "Could not load orders."), 8));
      return;
    }
    const { items, total, page, page_size } = result.data;
    if (!items.length) {
      body.append(rowMessage("No orders match these filters.", 8));
    }
    for (const order of items) {
      const tr = node("tr");
      tr.append(
        node("td", "mono", order.code),
        buyerCell(order),
        node("td", null, planLabel(order.months)),
        node("td", "money", money(order.amount_cents)),
        node("td", null, methodLabel(order.method)),
        node("td", null, timeAgo(order.created_at)),
      );
      const status = node("td");
      status.append(statusBadge(order.status, orderStatusLabel(order.status)));
      tr.append(status);

      const actions = node("td");
      const review = node("button", "btn btn-sm", "Review");
      review.type = "button";
      review.addEventListener("click", () => openOrder(order.id));
      actions.append(review);
      tr.append(actions);
      body.append(tr);
    }
    renderPager($("orders-pager"), { page, pageSize: page_size, total }, (next) => {
      state.orders.page = next;
      loadOrders();
    });
  }

  async function openOrder(id) {
    const result = await request(`/api/admin/orders/${encodeURIComponent(id)}`);
    if (!result.ok) {
      showToast(errorText(result, "Could not open the order."));
      return;
    }
    state.order = result.data.order;
    state.orderCanReview = ["pending", "rejected"].includes(state.order.status);

    $("order-title-code").textContent = state.order.code;
    const badge = $("order-status");
    badge.className = `badge ${statusTone(state.order.status)}`;
    badge.textContent = orderStatusLabel(state.order.status);

    const details = $("order-details");
    details.replaceChildren();
    addDetail(details, "Buyer", state.order.name);
    addDetail(details, "Email", state.order.email);
    addDetail(details, "Phone", state.order.phone || "—");
    addDetail(details, "Term", planLabel(state.order.months));
    addDetail(details, "Amount", money(state.order.amount_cents));
    addDetail(details, "Paid with", methodLabel(state.order.method));
    addDetail(details, "Submitted", formatDate(state.order.created_at));
    if (state.order.reviewed_at) addDetail(details, "Reviewed", formatDate(state.order.reviewed_at));
    if (state.order.note) addDetail(details, "Buyer note", state.order.note);

    const tx = node("dd");
    const url = explorerUrl(state.order.method, state.order.tx_ref);
    if (url) {
      const link = node("a", "inline-link mono", state.order.tx_ref);
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener";
      tx.append(link);
    } else {
      tx.textContent = state.order.tx_ref;
    }
    const txRow = node("div");
    txRow.append(node("dt", null, "Transaction"), tx);
    details.append(txRow);

    const reviewNote = $("order-review-note");
    reviewNote.hidden = !state.order.review_note;
    reviewNote.textContent = state.order.review_note ? `Review note: ${state.order.review_note}` : "";

    $("order-months").value = String(state.order.months);
    $("order-approve-note").value = "";
    $("order-reject-note").value = "";
    setOrderMode(null);
    $("order-dialog").showModal();
  }

  function addDetail(list, term, value) {
    const row = node("div");
    row.append(node("dt", null, term), node("dd", null, value));
    list.append(row);
  }

  function setOrderMode(mode) {
    state.orderMode = mode;
    const status = state.order?.status;
    $("order-approve").hidden = mode !== "approve";
    $("order-reject").hidden = mode !== "reject";
    $("order-default-actions").hidden = mode !== null;
    $("order-approve-open").hidden = !(status === "pending" || status === "rejected");
    $("order-reject-open").hidden = status !== "pending";
    $("order-approve-actions").hidden = mode !== "approve";
    $("order-reject-actions").hidden = mode !== "reject";
    setAlert($("order-approve-alert"), "");
    setAlert($("order-reject-alert"), "");
    if (mode === "approve") $("order-months").focus();
    if (mode === "reject") $("order-reject-note").focus();
  }

  async function confirmApprove() {
    if (!state.order) return;
    const months = Number($("order-months").value);
    if (!Number.isInteger(months) || months < 1 || months > 24) {
      setAlert($("order-approve-alert"), "Months must be a whole number between 1 and 24.");
      $("order-months").focus();
      return;
    }
    const note = $("order-approve-note").value.trim();
    const button = $("order-approve-confirm");
    button.disabled = true;
    button.textContent = "Approving…";

    const result = await request(
      `/api/admin/orders/${encodeURIComponent(state.order.id)}/approve`,
      { method: "POST", mutate: true, body: note ? { months, note } : { months } },
    );

    button.disabled = false;
    button.textContent = "Approve and issue licence";

    if (!result.ok) {
      setAlert($("order-approve-alert"), errorText(result, "Could not approve the order."));
      return;
    }

    const order = state.order;
    $("order-dialog").close();
    if (result.data.license) {
      showLicense({
        key: result.data.license,
        name: order.name,
        email: order.email,
        expiresAt: result.data.subscription.expires_at,
      });
    } else {
      showToast(`Subscription extended to ${formatDate(result.data.subscription.expires_at)}`);
    }
    loadOrders();
  }

  async function confirmReject() {
    if (!state.order) return;
    const note = $("order-reject-note").value.trim();
    if (!note) {
      setAlert($("order-reject-alert"), "Add a short note explaining the decision.");
      $("order-reject-note").focus();
      return;
    }
    const button = $("order-reject-confirm");
    button.disabled = true;
    button.textContent = "Rejecting…";

    const result = await request(
      `/api/admin/orders/${encodeURIComponent(state.order.id)}/reject`,
      { method: "POST", mutate: true, body: { note } },
    );

    button.disabled = false;
    button.textContent = "Reject order";

    if (!result.ok) {
      setAlert($("order-reject-alert"), errorText(result, "Could not reject the order."));
      return;
    }
    $("order-dialog").close();
    showToast("Order rejected");
    loadOrders();
  }

  /* Subscriptions */

  async function loadSubscriptions() {
    const body = $("subscriptions-body");
    body.replaceChildren(rowMessage("Loading…", 8));
    const result = await request(
      `/api/admin/subscriptions${buildQuery({ ...state.subscriptions, pageSize: 20 })}`,
    );
    body.replaceChildren();
    if (!result.ok) {
      body.append(rowMessage(errorText(result, "Could not load subscriptions."), 8));
      return;
    }

    const { items, total, page, page_size } = result.data;
    if (!items.length) body.append(rowMessage("No subscriptions match these filters.", 8));

    for (const subscription of items) {
      const status = effectiveStatus(subscription.status, subscription.expires_at);
      const termText =
        status === "active" ? `Pro · ${daysLeft(subscription.expires_at)}d left` : "Pro";
      const tr = node("tr");
      tr.append(
        node("td", null, subscription.customer_email),
        node("td", null, termText),
        node("td", null, formatDate(subscription.started_at)),
        node("td", null, formatDate(subscription.expires_at)),
      );

      const statusCell = node("td");
      statusCell.append(statusBadge(status, SUB_LABELS[status] ?? status));
      tr.append(statusCell);

      tr.append(node("td", "mono", subscription.license_prefix ? `${subscription.license_prefix}…` : "—"));
      tr.append(node("td", "mono subline", subscription.source_order_id ? "order" : "comp"));

      const actions = node("td", "row-actions");
      const extend = node("button", "btn btn-sm", "Extend");
      extend.type = "button";
      extend.disabled = status === "revoked";
      extend.addEventListener("click", () => openSubAction(subscription, "extend"));

      const rotate = node("button", "btn btn-sm", "Rotate");
      rotate.type = "button";
      rotate.disabled = status === "revoked";
      rotate.addEventListener("click", () => openSubAction(subscription, "rotate"));

      const revoke = node("button", "btn btn-sm btn-danger", "Revoke");
      revoke.type = "button";
      revoke.disabled = status === "revoked";
      revoke.addEventListener("click", () => openSubAction(subscription, "revoke"));

      actions.append(extend, rotate, revoke);
      tr.append(actions);
      body.append(tr);
    }

    renderPager($("subscriptions-pager"), { page, pageSize: page_size, total }, (next) => {
      state.subscriptions.page = next;
      loadSubscriptions();
    });
  }

  function openSubAction(subscription, mode) {
    state.sub = subscription;
    state.subMode = mode;
    $("sub-months").value = "1";
    $("sub-note").value = "";
    $("sub-months-field").hidden = mode !== "extend";
    $("sub-note-field").hidden = mode !== "revoke";
    setAlert($("sub-alert"), "");

    if (mode === "extend") {
      $("sub-title").textContent = "Extend subscription";
      $("sub-message").textContent = `Adds months from the later of today and ${formatDate(subscription.expires_at)}.`;
      $("sub-confirm").textContent = "Extend subscription";
      $("sub-confirm").className = "btn btn-primary";
    } else if (mode === "rotate") {
      $("sub-title").textContent = "Rotate licence";
      $("sub-message").textContent = "The current key stops working immediately. The new key is shown once — send it to the customer.";
      $("sub-confirm").textContent = "Rotate licence";
      $("sub-confirm").className = "btn btn-danger";
    } else {
      $("sub-title").textContent = "Revoke subscription";
      $("sub-message").textContent = "The subscription and every active licence for it stop working immediately. This cannot be undone.";
      $("sub-confirm").textContent = "Revoke subscription";
      $("sub-confirm").className = "btn btn-danger";
    }

    $("sub-target").textContent = subscription.customer_email;
    $("sub-dialog").showModal();
    if (mode === "extend") $("sub-months").focus();
    if (mode === "revoke") $("sub-note").focus();
  }

  async function confirmSubAction() {
    if (!state.sub || !state.subMode) return;
    const button = $("sub-confirm");
    const id = encodeURIComponent(state.sub.id);
    let path;
    let body;
    let verb = "Update";

    if (state.subMode === "extend") {
      const months = Number($("sub-months").value);
      if (!Number.isInteger(months) || months < 1 || months > 24) {
        setAlert($("sub-alert"), "Months must be a whole number between 1 and 24.");
        return;
      }
      path = `/api/admin/subscriptions/${id}/extend`;
      body = { months };
      verb = "Extended";
    } else if (state.subMode === "revoke") {
      const note = $("sub-note").value.trim();
      if (!note) {
        setAlert($("sub-alert"), "A note is required to revoke a subscription.");
        $("sub-note").focus();
        return;
      }
      path = `/api/admin/subscriptions/${id}/revoke`;
      body = { note };
    } else {
      path = `/api/admin/subscriptions/${id}/license`;
    }

    button.disabled = true;
    const result = await request(path, { method: "POST", mutate: true, body });
    button.disabled = false;

    if (!result.ok) {
      setAlert($("sub-alert"), errorText(result, "The action failed."));
      return;
    }

    if (state.subMode === "rotate") {
      const sub = state.sub;
      $("sub-dialog").close();
      showLicense({
        key: result.data.license,
        email: sub.customer_email,
        expiresAt: sub.expires_at,
      });
    } else if (state.subMode === "revoke") {
      $("sub-dialog").close();
      showToast(`Revoked · ${result.data.licenses_revoked} licence${result.data.licenses_revoked === 1 ? "" : "s"} invalidated`);
    } else {
      $("sub-dialog").close();
      showToast(`Extended to ${formatDate(result.data.subscription.expires_at)}`);
    }
    loadSubscriptions();
  }

  /* Comp grant */

  async function submitGrant(event) {
    event.preventDefault();
    setAlert($("grant-alert"), "");
    const email = $("grant-email").value.trim();
    const months = Number($("grant-months").value);
    if (!email) {
      setAlert($("grant-alert"), "Enter the customer email.");
      $("grant-email").focus();
      return;
    }
    if (!Number.isInteger(months) || months < 1 || months > 24) {
      setAlert($("grant-alert"), "Months must be a whole number between 1 and 24.");
      $("grant-months").focus();
      return;
    }

    const button = $("grant-submit");
    button.disabled = true;
    button.textContent = "Granting…";
    const result = await request("/api/admin/subscriptions", {
      method: "POST",
      mutate: true,
      body: {
        email,
        months,
        name: $("grant-name").value.trim() || undefined,
        note: $("grant-note").value.trim() || undefined,
      },
    });
    button.disabled = false;
    button.textContent = "Grant Pro";

    if (!result.ok) {
      setAlert($("grant-alert"), errorText(result, "Could not grant Pro."));
      return;
    }

    $("grant-dialog").close();
    $("grant-form").reset();
    showLicense({
      key: result.data.license,
      name: result.data.customer.name,
      email: result.data.customer.email,
      expiresAt: result.data.subscription.expires_at,
    });
    loadSubscriptions();
  }

  /* Customers */

  async function loadCustomers() {
    const body = $("customers-body");
    body.replaceChildren(rowMessage("Loading…", 5));
    const result = await request(
      `/api/admin/customers${buildQuery({ q: state.customers.q, page: state.customers.page, pageSize: 20 })}`,
    );
    body.replaceChildren();
    if (!result.ok) {
      body.append(rowMessage(errorText(result, "Could not load customers."), 5));
      return;
    }

    const { items, total, page, page_size } = result.data;
    if (!items.length) body.append(rowMessage("No customers match this search.", 5));
    for (const customer of items) {
      const tr = node("tr");
      tr.append(
        node("td", null, customer.name),
        node("td", null, customer.email),
        node("td", "mono", customer.phone || "—"),
        node("td", null, formatDate(customer.created_at)),
      );
      const actions = node("td");
      const orders = node("button", "btn btn-sm", "View orders");
      orders.type = "button";
      orders.addEventListener("click", () => {
        state.orders = { page: 1, status: "", q: customer.email };
        $("orders-search").value = customer.email;
        $("orders-status").value = "";
        selectView("orders");
      });
      actions.append(orders);
      tr.append(actions);
      body.append(tr);
    }

    renderPager($("customers-pager"), { page, pageSize: page_size, total }, (next) => {
      state.customers.page = next;
      loadCustomers();
    });
  }

  /* Audit */

  async function loadAudit() {
    const body = $("audit-body");
    body.replaceChildren(rowMessage("Loading…", 4));
    const result = await request(
      `/api/admin/audit${buildQuery({ page: state.audit.page, pageSize: 30 })}`,
    );
    body.replaceChildren();
    if (!result.ok) {
      body.append(rowMessage(errorText(result, "Could not load the audit log."), 4));
      return;
    }

    const { items, total, page, page_size } = result.data;
    if (!items.length) body.append(rowMessage("No admin actions have been recorded yet.", 4));
    for (const entry of items) {
      const tr = node("tr");
      const action = node("td");
      action.append(node("div", null, actionLabel(entry.action)), node("div", "subline", entry.actor));
      tr.append(
        node("td", null, formatDate(entry.at)),
        action,
        node("td", "mono", entry.target),
        node("td", "subline", parseDetail(entry.detail)),
      );
      body.append(tr);
    }

    renderPager($("audit-pager"), { page, pageSize: page_size, total }, (next) => {
      state.audit.page = next;
      loadAudit();
    });
  }

  /* Settings */

  async function loadSettings() {
    setAlert($("settings-alert"), "");
    const result = await request("/api/admin/settings");
    if (!result.ok) {
      setAlert($("settings-alert"), errorText(result, "Could not load settings."));
      return;
    }
    state.settings = result.data.settings;
    renderSettings(state.settings);
  }

  function renderSettings(settings) {
    for (const key of SETTING_KEYS) {
      const input = $(`set-${key}`);
      if (input) input.value = String(settings[key] ?? "");
    }
    updatePricePreview();
  }

  function updatePricePreview() {
    const preview = $("price-preview");
    if (!preview) return;
    const cents = Number($("set-pro_monthly_cents").value);
    preview.textContent = Number.isFinite(cents) && cents >= 0 ? `Shown as ${formatUsd(cents)} per month` : "Enter whole cents";
  }

  async function saveSettings(event) {
    event.preventDefault();
    setAlert($("settings-alert"), "");
    if (!state.settings) return;

    const changed = SETTING_KEYS.filter(
      (key) => String($(`set-${key}`).value).trim() !== String(state.settings[key]),
    );
    if (!changed.length) {
      showToast("No changes to save");
      return;
    }

    const button = $("settings-save");
    button.disabled = true;
    button.textContent = "Saving…";

    for (const key of changed) {
      const raw = $(`set-${key}`).value;
      const value = NUMERIC_SETTINGS.has(key) ? Number(raw) : raw.trim();
      const result = await request("/api/admin/settings", {
        method: "PUT",
        mutate: true,
        body: { key, value },
      });
      if (!result.ok) {
        setAlert($("settings-alert"), `${key}: ${errorText(result, "rejected")}`);
        $(`set-${key}`).focus();
        button.disabled = false;
        button.textContent = "Save changes";
        return;
      }
      state.settings = result.data.settings;
    }

    renderSettings(state.settings);
    button.disabled = false;
    button.textContent = "Save changes";
    showToast(`${changed.length} setting${changed.length === 1 ? "" : "s"} saved`);
  }

  /* Licence dialog */

  function showLicense({ key, name, email, expiresAt }) {
    $("license-key").textContent = key;
    $("license-meta").textContent = `Valid until ${formatDate(expiresAt)} · send it now, it is stored only as a hash.`;
    $("license-message").value = licenseMessage({ name, email, key, expiresAt });
    setAlert($("license-alert"), "");
    $("license-dialog").showModal();
  }

  async function copyLicenseKey() {
    const key = $("license-key").textContent;
    try {
      await navigator.clipboard.writeText(key);
      showToast("Licence key copied");
    } catch {
      showToast("Copy failed — select the key and copy it");
    }
  }

  async function copyLicenseMessage() {
    try {
      await navigator.clipboard.writeText($("license-message").value);
      showToast("Message copied");
    } catch {
      showToast("Copy failed — select the message and copy it");
    }
  }

  /* CSV export */

  async function exportCsv(type, button) {
    button.disabled = true;
    try {
      const response = await fetchImpl(`${api}/api/admin/export?type=${encodeURIComponent(type)}`, {
        credentials: "include",
      });
      if (response.status === 401) {
        expireSession();
        return;
      }
      if (!response.ok) {
        showToast("Export failed");
        return;
      }
      const blob = await response.blob();
      const disposition = response.headers.get("content-disposition") ?? "";
      const match = disposition.match(/filename="([^"]+)"/);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = match ? match[1] : `threats-${type}.csv`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast("CSV downloaded");
    } catch {
      showToast("Export failed");
    } finally {
      button.disabled = false;
    }
  }

  /* Events */

  function debounce(callback, delay = 250) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => callback(...args), delay);
    };
  }

  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setAlert($("login-alert"), "");
    const button = $("login-submit");
    button.disabled = true;
    button.textContent = "Signing in…";

    const result = await request("/api/admin/login", {
      method: "POST",
      body: {
        password: $("login-password").value,
        code: $("login-code").value.trim(),
      },
    });

    button.disabled = false;
    button.textContent = "Sign in";

    if (!result.ok) {
      const code = result.data?.error?.code;
      const copy = {
        invalid_credentials: "Password or authenticator code is wrong.",
        login_locked: "Too many attempts. Try again in 15 minutes.",
        admin_unconfigured: "Admin access is not configured on the server yet.",
        network: "Could not reach the admin API.",
      };
      setAlert($("login-alert"), copy[code] ?? errorText(result, "Sign-in failed."));
      $("login-code").value = "";
      $("login-code").focus();
      return;
    }

    $("login-password").value = "";
    $("login-code").value = "";
    showApp(result.data);
  });

  $("logout").addEventListener("click", async () => {
    await request("/api/admin/logout", { method: "POST" });
    clearSession("Signed out.");
    showToast("Signed out");
  });

  document.querySelectorAll("[data-refresh]").forEach((button) => {
    button.addEventListener("click", () => activateView(button.dataset.refresh));
  });

  document.querySelectorAll("[data-export]").forEach((button) => {
    button.addEventListener("click", () => exportCsv(button.dataset.export, button));
  });

  document.querySelectorAll("[data-goto]").forEach((button) => {
    button.addEventListener("click", () => selectView(button.dataset.goto));
  });

  $("orders-status").addEventListener("change", (event) => {
    state.orders = { ...state.orders, status: event.target.value, page: 1 };
    loadOrders();
  });
  $("orders-search").addEventListener("input", debounce((event) => {
    state.orders = { ...state.orders, q: event.target.value, page: 1 };
    loadOrders();
  }));

  $("subscriptions-status").addEventListener("change", (event) => {
    state.subscriptions = { ...state.subscriptions, status: event.target.value, page: 1 };
    loadSubscriptions();
  });
  $("subscriptions-search").addEventListener("input", debounce((event) => {
    state.subscriptions = { ...state.subscriptions, q: event.target.value, page: 1 };
    loadSubscriptions();
  }));

  $("customers-search").addEventListener("input", debounce((event) => {
    state.customers = { page: 1, q: event.target.value };
    loadCustomers();
  }));

  $("order-approve-open").addEventListener("click", () => setOrderMode("approve"));
  $("order-approve-cancel").addEventListener("click", () => setOrderMode(null));
  $("order-reject-open").addEventListener("click", () => setOrderMode("reject"));
  $("order-reject-cancel").addEventListener("click", () => setOrderMode(null));
  $("order-approve-confirm").addEventListener("click", confirmApprove);
  $("order-reject-confirm").addEventListener("click", confirmReject);
  $("order-close").addEventListener("click", () => $("order-dialog").close());
  $("order-x").addEventListener("click", () => $("order-dialog").close());

  $("sub-cancel").addEventListener("click", () => $("sub-dialog").close());
  $("sub-confirm").addEventListener("click", confirmSubAction);
  $("grant-open").addEventListener("click", () => {
    setAlert($("grant-alert"), "");
    $("grant-dialog").showModal();
    $("grant-email").focus();
  });
  $("grant-cancel").addEventListener("click", () => $("grant-dialog").close());
  $("grant-form").addEventListener("submit", submitGrant);

  $("license-copy-key").addEventListener("click", copyLicenseKey);
  $("license-copy-message").addEventListener("click", copyLicenseMessage);
  $("license-done").addEventListener("click", () => $("license-dialog").close());

  $("settings-form").addEventListener("submit", saveSettings);
  $("settings-reload").addEventListener("click", loadSettings);
  $("set-pro_monthly_cents").addEventListener("input", updatePricePreview);

  for (const dialog of document.querySelectorAll("dialog")) {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  }

  /* Boot */

  async function boot() {
    const result = await request("/api/admin/session");
    if (result.ok) {
      showApp(result.data);
      return;
    }
    if (result.status === 503) {
      showLogin(errorText(result, "Admin access is not configured yet."));
      return;
    }
    showLogin(result.status === 401 ? "" : errorText(result, "The admin API is unreachable."));
  }

  boot();
}
