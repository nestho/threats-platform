/*
 * Checkout helpers and page wiring for subscribe.html.
 *
 * The pure functions at the top are imported by checkout.test.mjs under Node.
 * Nothing here may touch `document` or `location` at import time.
 */

import { copyText } from "./app.js";

const PROD_API = "https://api.threats.top";
const LOCAL_API = "http://localhost:8787";
const FALLBACK_SUPPORT = "nestho@icloud.com";

export function apiOrigin(hostname, override) {
  if (override) return String(override).replace(/\/+$/, "");
  const host = String(hostname ?? "").toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return LOCAL_API;
  return PROD_API;
}

export function formatUsd(cents) {
  if (typeof cents !== "number" || !Number.isFinite(cents) || cents < 0) return "—";
  const total = Math.round(cents);
  const dollars = Math.floor(total / 100);
  const rest = total % 100;
  const grouped = dollars.toLocaleString("en-US");
  return rest === 0 ? `$${grouped}` : `$${grouped}.${String(rest).padStart(2, "0")}`;
}

export function amountFor(monthlyCents, months) {
  if (typeof monthlyCents !== "number" || !Number.isFinite(monthlyCents) || monthlyCents < 0) return null;
  if (typeof months !== "number" || !Number.isInteger(months) || months < 1) return null;
  return monthlyCents * months;
}

export function planLabel(months) {
  if (typeof months !== "number" || !Number.isInteger(months) || months < 1) return "—";
  return `${months} month${months === 1 ? "" : "s"}`;
}

const METHOD_LABELS = {
  usdt_trc20: "USDT · TRON (TRC20)",
  btc: "Bitcoin · native SegWit",
};

export function methodLabel(method) {
  return METHOD_LABELS[method] ?? "Unknown method";
}

const EXPLORERS = {
  usdt_trc20: { tx: "https://tronscan.org/#/transaction/", address: "https://tronscan.org/#/address/" },
  btc: { tx: "https://mempool.space/tx/", address: "https://mempool.space/address/" },
};

export function explorerUrl(method, txRef) {
  const base = EXPLORERS[method]?.tx;
  const ref = cleanTxRef(txRef);
  return base && ref ? base + encodeURIComponent(ref) : null;
}

export function walletExplorerUrl(method, address) {
  const base = EXPLORERS[method]?.address;
  const value = String(address ?? "").trim();
  return base && value ? base + encodeURIComponent(value) : null;
}

const ERROR_COPY = {
  invalid: "Check the highlighted fields and submit again.",
  duplicate_tx: "That transaction is already attached to an order. Check its status below instead of submitting it twice.",
  rate_limited: "Too many orders from this network. Wait a little, then try again.",
  order_not_found: "No order matches that code and email. Check both and try again.",
  payload_too_large: "That note is too long. Shorten it and try again.",
  unsupported_media_type: "The browser sent an unexpected request. Reload the page and try again.",
  network: "Couldn't reach the payment service. Check your connection — nothing was charged.",
  server: "Something went wrong. Nothing was charged — try again.",
};

export function errorMessage(code, fallback) {
  if (ERROR_COPY[code]) return ERROR_COPY[code];
  if (typeof fallback === "string" && fallback.trim()) return fallback;
  return "Something went wrong. Nothing was charged — try again.";
}

const STATUS_LABELS = {
  pending: "Awaiting verification",
  approved: "Approved",
  rejected: "Rejected",
  expired: "Expired",
};

const STATUS_BADGES = {
  pending: "med",
  approved: "ok",
  rejected: "crit",
  expired: "muted",
};

export function orderStatusLabel(status) {
  return STATUS_LABELS[status] ?? "Unknown";
}

export function badgeClass(status) {
  return STATUS_BADGES[status] ?? "muted";
}

export function cleanTxRef(value) {
  return String(value ?? "").replace(/\s+/g, "");
}

export function isTxRefShape(value) {
  return /^[A-Za-z0-9:_-]{8,128}$/.test(String(value ?? ""));
}

/* ── Page wiring ────────────────────────────────────────────────────── */

const METHOD_DETAILS = {
  usdt_trc20: {
    coin: "USDT",
    network: "TRON · TRC20",
    warning: "Send USDT over TRON (TRC20) only. USDT sent on another chain cannot be recovered.",
  },
  btc: {
    coin: "Bitcoin",
    network: "native SegWit",
    warning: "Send BTC to this bc1 address only. An exchange-internal transfer never reaches the chain.",
  },
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function formatDate(iso) {
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  return new Date(time).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

async function requestJson(fetchImpl, origin, path, options = {}) {
  try {
    const response = await fetchImpl(origin + path, {
      method: options.method ?? "GET",
      headers: options.body ? { "content-type": "application/json" } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    let data = null;
    try { data = await response.json(); } catch { /* empty or non-JSON error page */ }
    return { ok: response.ok, status: response.status, data };
  } catch {
    return { ok: false, status: 0, data: { error: { code: "network", message: "" } } };
  }
}

export function initCheckout({ hostname, origin, fetchImpl = fetch } = {}) {
  const api = origin ?? apiOrigin(hostname ?? location.hostname);

  const plansEl = document.getElementById("plans");
  const walletsEl = document.getElementById("wallets");
  const startEl = document.getElementById("checkout-start");
  const downEl = document.getElementById("api-down");
  const form = document.getElementById("order-form");
  const submitEl = document.getElementById("order-submit");
  const alertEl = document.getElementById("form-alert");
  const confirmation = document.getElementById("confirmation");
  const lookupForm = document.getElementById("lookup-form");
  const lookupAlert = document.getElementById("lookup-alert");
  const lookupResult = document.getElementById("lookup-result");
  const summaryPlan = document.getElementById("sum-plan");
  const summaryAmount = document.getElementById("sum-amount");
  const summaryMethod = document.getElementById("sum-method");
  const payInstruction = document.getElementById("pay-instruction");
  const networkWarning = document.getElementById("network-warning");

  const state = { config: null, plan: 1, method: "usdt_trc20", support: FALLBACK_SUPPORT };

  const setAlert = (element, message, kind = "error") => {
    if (!element) return;
    element.hidden = !message;
    element.textContent = message ?? "";
    element.className = message ? (kind === "ok" ? "form-alert ok" : "form-alert") : "form-alert";
  };

  const clearFieldErrors = () => {
    for (const id of ["name", "email", "phone", "tx_ref", "note"]) {
      const input = document.getElementById(id);
      const error = document.getElementById(`${id}-err`);
      if (input) input.removeAttribute("aria-invalid");
      if (error) error.textContent = "";
    }
  };

  const showFieldErrors = (fields) => {
    let first = null;
    for (const [field, message] of Object.entries(fields ?? {})) {
      const input = document.getElementById(field);
      const error = document.getElementById(`${field}-err`);
      if (!input || !error) continue;
      input.setAttribute("aria-invalid", "true");
      error.textContent = String(message);
      if (!first) first = input;
    }
    if (first) first.focus();
  };

  const refreshSummary = () => {
    const amount = amountFor(state.config.pro_monthly_cents, state.plan);
    if (summaryPlan) summaryPlan.textContent = planLabel(state.plan);
    if (summaryAmount) summaryAmount.textContent = formatUsd(amount);
    if (summaryMethod) summaryMethod.textContent = methodLabel(state.method);
    const detail = METHOD_DETAILS[state.method];
    if (payInstruction) {
      payInstruction.textContent = state.method === "btc"
        ? `Send ${formatUsd(amount)} worth of Bitcoin to the address below, then report the transaction.`
        : `Send ${formatUsd(amount)} worth of USDT on TRON (TRC20) to the address below, then report the transaction.`;
    }
    if (networkWarning) networkWarning.textContent = detail.warning;
  };

  const renderPlans = () => {
    plansEl.replaceChildren();
    for (const months of state.config.plan_months) {
      const label = node("label", "plan");
      const input = node("input");
      input.type = "radio";
      input.name = "months";
      input.value = String(months);
      input.checked = months === state.plan;
      input.addEventListener("change", () => {
        if (!input.checked) return;
        state.plan = months;
        refreshSummary();
      });

      const body = node("span", "plan-body");
      body.append(
        node("span", "plan-term", planLabel(months)),
        node("span", "plan-price", formatUsd(amountFor(state.config.pro_monthly_cents, months))),
        node("span", "plan-meta", months === 1 ? "billed monthly" : `${months} × ${formatUsd(state.config.pro_monthly_cents)}`),
      );
      label.append(input, body);
      plansEl.append(label);
    }
  };

  const renderWallets = () => {
    walletsEl.replaceChildren();
    for (const method of state.config.methods) {
      const detail = METHOD_DETAILS[method];
      if (!detail) continue;
      const address = state.config.wallets[method];
      const card = node("div", "wallet");

      const pick = node("label", "wallet-pick");
      const input = node("input");
      input.type = "radio";
      input.name = "method";
      input.value = method;
      input.checked = method === state.method;
      input.addEventListener("change", () => {
        if (!input.checked) return;
        state.method = method;
        refreshSummary();
      });

      const head = node("span", "wallet-head");
      head.append(node("span", "wallet-name", detail.coin), node("span", "badge", detail.network));

      const value = node("span", "wallet-addr mono", address);
      pick.append(input, node("span", "wallet-radio", ""), head, value);
      pick.querySelector(".wallet-radio").setAttribute("aria-hidden", "true");

      const actions = node("div", "wallet-actions");
      const copy = node("button", "copy-inline", "Copy address");
      copy.type = "button";
      copy.addEventListener("click", () => copyText(address, `${detail.coin} address copied`));
      actions.append(copy);

      const explorer = walletExplorerUrl(method, address);
      if (explorer) {
        const link = node("a", "map-link", "Explorer ↗");
        link.href = explorer;
        link.target = "_blank";
        link.rel = "noopener";
        actions.append(link);
      }

      card.append(pick, actions);
      walletsEl.append(card);
    }
  };

  const showConfirmation = (order, txRef) => {
    document.getElementById("conf-code").textContent = order.code;
    document.getElementById("conf-term").textContent = planLabel(order.months);
    document.getElementById("conf-amount").textContent = formatUsd(order.amount_cents);
    document.getElementById("conf-method").textContent = methodLabel(order.method);
    document.getElementById("conf-created").textContent = formatDate(order.created_at);

    const link = document.getElementById("conf-explorer");
    const url = explorerUrl(order.method, txRef);
    link.hidden = !url;
    if (url) link.href = url;

    const lookupCode = document.getElementById("lookup-code");
    const lookupEmail = document.getElementById("lookup-email");
    if (lookupCode) lookupCode.value = order.code;
    if (lookupEmail) lookupEmail.value = form.elements.email.value;

    form.hidden = true;
    const reportStep = document.getElementById("report-step");
    if (reportStep) reportStep.hidden = true;
    confirmation.hidden = false;
    confirmation.scrollIntoView({ block: "start", behavior: "smooth" });
    document.getElementById("conf-copy").focus();
  };

  const submitOrder = async (event) => {
    event.preventDefault();
    clearFieldErrors();
    setAlert(alertEl, "");

    const txRef = cleanTxRef(form.elements.tx_ref.value);
    if (!isTxRefShape(txRef)) {
      showFieldErrors({ tx_ref: "Enter the transaction ID from the explorer (8–128 letters, digits, : _ or -)." });
      setAlert(alertEl, errorMessage("invalid"));
      return;
    }

    if (typeof form.reportValidity === "function" && !form.reportValidity()) return;

    const payload = {
      name: form.elements.name.value.trim(),
      email: form.elements.email.value.trim(),
      phone: form.elements.phone.value.trim(),
      months: state.plan,
      method: state.method,
      tx_ref: txRef,
      note: form.elements.note.value.trim(),
      company: form.elements.company.value,
    };

    submitEl.disabled = true;
    submitEl.setAttribute("aria-busy", "true");
    submitEl.textContent = "Submitting…";

    const result = await requestJson(fetchImpl, api, "/api/orders", { method: "POST", body: payload });

    submitEl.disabled = false;
    submitEl.removeAttribute("aria-busy");
    submitEl.textContent = "Submit for review";

    if (!result.ok) {
      const error = result.data?.error ?? {};
      setAlert(alertEl, errorMessage(error.code, error.message));
      showFieldErrors(error.fields);
      return;
    }

    showConfirmation(result.data.order, txRef);
  };

  const submitLookup = async (event) => {
    event.preventDefault();
    setAlert(lookupAlert, "");
    lookupResult.hidden = true;

    const payload = {
      code: lookupForm.elements.code.value.trim().toUpperCase(),
      email: lookupForm.elements.email.value.trim(),
    };
    const result = await requestJson(fetchImpl, api, "/api/orders/lookup", { method: "POST", body: payload });
    if (!result.ok) {
      const error = result.data?.error ?? {};
      setAlert(lookupAlert, errorMessage(error.code, error.message));
      return;
    }

    const order = result.data.order;
    lookupResult.replaceChildren();
    const head = node("div", "lookup-head");
    head.append(
      node("span", "mono lookup-code", order.code),
      node("span", `badge ${badgeClass(order.status)}`, orderStatusLabel(order.status)),
    );

    const facts = node("dl", "lookup-facts");
    for (const [term, value] of [
      ["Term", planLabel(order.months)],
      ["Amount", formatUsd(order.amount_cents)],
      ["Paid with", methodLabel(order.method)],
      ["Submitted", formatDate(order.created_at)],
      ...(order.reviewed_at ? [["Reviewed", formatDate(order.reviewed_at)]] : []),
    ]) {
      const row = node("div");
      row.append(node("dt", null, term), node("dd", null, value));
      facts.append(row);
    }

    const messages = {
      pending: "Payment is being verified manually. The licence key is emailed after approval — usually within one business day.",
      approved: "Approved. The licence key was emailed to the address on this order. Activate it on the Pro console.",
      rejected: "This order was rejected. Reply to the review email or contact support if you believe the payment was valid.",
      expired: "This order expired before the transfer was verified. Submit a new order if you have paid.",
    };

    const message = node("p", "lookup-msg", messages[order.status] ?? "");
    lookupResult.append(head, facts, message);
    lookupResult.hidden = false;
  };

  form.addEventListener("submit", submitOrder);
  lookupForm.addEventListener("submit", submitLookup);
  form.addEventListener("input", (event) => {
    const error = document.getElementById(`${event.target.id}-err`);
    if (error) error.textContent = "";
    event.target.removeAttribute("aria-invalid");
  });

  document.getElementById("conf-copy").addEventListener("click", () => {
    copyText(document.getElementById("conf-code").textContent, "Order code copied");
  });

  document.getElementById("conf-track").addEventListener("click", () => {
    document.getElementById("lookup-code").value = document.getElementById("conf-code").textContent;
    document.getElementById("lookup-code").scrollIntoView({ block: "center", behavior: "smooth" });
    document.getElementById("lookup-code").focus({ preventScroll: true });
  });

  requestJson(fetchImpl, api, "/api/config").then((result) => {
    if (!result.ok || !result.data || !Array.isArray(result.data.plan_months)) {
      const support = document.getElementById("api-support");
      support.textContent = state.support;
      support.href = `mailto:${state.support}`;
      downEl.hidden = false;
      startEl.hidden = true;
      setAlert(alertEl, "");
      return;
    }

    state.config = result.data;
    state.support = result.data.support_email || FALLBACK_SUPPORT;
    state.plan = result.data.plan_months.includes(1) ? 1 : result.data.plan_months[0];
    state.method = result.data.methods.includes("usdt_trc20") ? "usdt_trc20" : result.data.methods[0];

    renderPlans();
    renderWallets();
    refreshSummary();
  });
}
