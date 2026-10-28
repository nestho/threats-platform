/*
 * Pro console helpers and page wiring for pro.html.
 *
 * The pure functions at the top are imported by pro.test.mjs under Node.
 * Nothing here may touch `document` or `location` at import time.
 *
 * The licence key never leaves the browser except as a Bearer token to the
 * API. It is stored only when the customer ticks "remember on this device":
 * localStorage for a remembered device, sessionStorage otherwise, and both are
 * cleared by "Forget this device".
 */

import { copyText, showToast } from "./app.js";
import { apiOrigin } from "./checkout.js";

const KEY_PREFIX = "THREATS-PRO-";
const KEY_PATTERN = /^THREATS-PRO-[0-9A-HJKMNP-TV-Z]{20}$/;
const STORAGE_KEY = "threats.pro.key";
const FALLBACK_SUPPORT = "nestho@icloud.com";

export function normalizeKey(value) {
  return typeof value === "string" ? value.replace(/\s+/g, "").toUpperCase() : "";
}

export function isKeyShape(value) {
  return KEY_PATTERN.test(normalizeKey(value));
}

export function maskKey(value) {
  const key = normalizeKey(value);
  if (!KEY_PATTERN.test(key)) return "—";
  return `${KEY_PREFIX}${key.slice(KEY_PREFIX.length, KEY_PREFIX.length + 8)}${"•".repeat(12)}`;
}

export function formatDay(iso) {
  if (!iso) return "—";
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return "—";
  return new Date(time).toLocaleDateString("en-GB", {
    day: "numeric", month: "short", year: "numeric", timeZone: "UTC",
  });
}

export function daysLabel(days) {
  if (typeof days !== "number" || !Number.isFinite(days)) return "—";
  if (days < 0) return "Expired";
  if (days === 0) return "Expires today";
  return `${Math.floor(days)} day${Math.floor(days) === 1 ? "" : "s"} left`;
}

const ERROR_COPY = {
  license_missing: "Paste your licence key to check it.",
  license_invalid: "That key does not match an active licence. Check for typos — a key starts with THREATS-PRO- and has 20 characters after it.",
  license_revoked: "This licence was revoked, so exports are stopped. If that is unexpected, contact support.",
  license_expired: "This licence expired. Renew with a new order and activate the new key that arrives by email.",
  rate_limited: "This licence reached its export limit for the minute. Wait a minute and try again.",
  feed_unavailable: "The public feeds are temporarily unavailable, so the bundle could not be built. Try again shortly.",
  network: "Couldn't reach the licence service. Check your connection and try again.",
  server: "The licence service had a problem. Try again in a moment.",
};

export function licenseMessage(code, fallback) {
  if (ERROR_COPY[code]) return ERROR_COPY[code];
  if (typeof fallback === "string" && fallback.trim()) return fallback;
  return "That licence could not be checked. Try again.";
}

export function needsNewKey(code) {
  return code === "license_expired" || code === "license_revoked";
}

export function filenameFromDisposition(header, fallback) {
  const value = typeof header === "string" ? header : "";
  const match = /filename="?([^";]+)"?/i.exec(value);
  const candidate = (match ? match[1] : value).split(/[\\/]/).pop() ?? "";
  const safe = candidate.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!safe || safe === "." || safe === "..") return fallback;
  return safe;
}

export function curlExample(apiBase, key) {
  const secret = isKeyShape(key) ? normalizeKey(key) : "<licence key>";
  return `curl -H "Authorization: Bearer ${secret}" ${apiBase}/api/stix -o threats-stix.json`;
}

/* ── Page wiring ────────────────────────────────────────────────────── */

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function requestJson(fetchImpl, path, options = {}) {
  return fetchImpl(path, {
    method: options.method ?? "GET",
    headers: options.authorization ? { authorization: `Bearer ${options.authorization}` } : undefined,
  })
    .then(async (response) => {
      let data = null;
      try { data = await response.json(); } catch { /* empty or non-JSON error page */ }
      return { ok: response.ok, status: response.status, data };
    })
    .catch(() => ({ ok: false, status: 0, data: { error: { code: "network", message: "" } } }));
}

function readStoredKey() {
  try {
    const local = localStorage.getItem(STORAGE_KEY);
    if (local) return { key: local, remember: true };
    const session = sessionStorage.getItem(STORAGE_KEY);
    if (session) return { key: session, remember: false };
  } catch {
    /* storage blocked by the browser; activation still works in memory */
  }
  return null;
}

function storeKey(key, remember) {
  try {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
    (remember ? localStorage : sessionStorage).setItem(STORAGE_KEY, key);
  } catch {
    /* storage blocked; the key stays in memory for this page only */
  }
}

function clearStoredKey() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* nothing to clear */
  }
}

export function initPro({ hostname, origin, fetchImpl = fetch } = {}) {
  const api = origin ?? apiOrigin(hostname ?? location.hostname);

  const loadingEl = document.getElementById("pro-loading");
  const activateEl = document.getElementById("pro-activate");
  const activeEl = document.getElementById("pro-active");
  const form = document.getElementById("activate-form");
  const input = document.getElementById("key-input");
  const rememberEl = document.getElementById("remember-key");
  const submitEl = document.getElementById("activate-submit");
  const keyAlert = document.getElementById("activate-alert");
  const activeHead = document.getElementById("pro-status-head");
  const stixAlert = document.getElementById("stix-alert");
  const downloadEl = document.getElementById("stix-download");
  const nextEl = document.getElementById("pro-next");

  const state = { key: "" };

  const setAlert = (element, message, kind = "error") => {
    if (!element) return;
    element.hidden = !message;
    element.textContent = message ?? "";
    element.className = message ? (kind === "ok" ? "form-alert ok" : "form-alert") : "form-alert";
  };

  const setNextLinks = (code) => {
    if (!nextEl) return;
    nextEl.hidden = !needsNewKey(code);
  };

  const showActivate = ({ message = "", code = null, kind = "error", focus = false } = {}) => {
    loadingEl.hidden = true;
    activeEl.hidden = true;
    activateEl.hidden = false;
    setAlert(keyAlert, message, kind);
    setNextLinks(code);
    if (focus) input.focus();
  };

  const showActive = (data) => {
    loadingEl.hidden = true;
    activateEl.hidden = true;
    activeEl.hidden = false;
    setAlert(keyAlert, "");
    setAlert(stixAlert, "");

    document.getElementById("pro-plan").textContent = data.plan === "pro" ? "Pro" : String(data.plan);
    document.getElementById("pro-expiry").textContent = formatDay(data.expires_at);
    document.getElementById("pro-days").textContent = daysLabel(data.days_left);
    document.getElementById("pro-key-masked").textContent = maskKey(state.key);
    document.getElementById("pro-limit").textContent = String(data.limits.stix_rate_per_min);
    document.getElementById("curl").textContent = curlExample(api, state.key);

    activeHead.focus({ preventScroll: true });
  };

  const signOut = (code, message) => {
    state.key = "";
    clearStoredKey();
    document.getElementById("curl").textContent = curlExample(api, "");
    showActivate({ message, code, focus: true });
  };

  const verify = async (key, { remember = false, auto = false } = {}) => {
    state.key = key;
    const result = await requestJson(fetchImpl, `${api}/api/pro/me`, { authorization: key });
    if (result.ok) {
      storeKey(key, remember);
      showActive(result.data);
      return;
    }

    const error = result.data?.error ?? {};
    const network = result.status === 0 || result.status >= 500;
    if (network) {
      if (!auto) clearStoredKey();
      state.key = key;
      showActivate({
        message: licenseMessage(error.code, error.message),
        focus: !auto,
      });
      return;
    }
    signOut(error.code, licenseMessage(error.code, error.message));
  };

  const activate = async (event) => {
    event.preventDefault();
    setAlert(keyAlert, "");
    setNextLinks(null);

    const key = normalizeKey(input.value);
    input.removeAttribute("aria-invalid");
    document.getElementById("key-err").textContent = "";

    if (!isKeyShape(key)) {
      input.setAttribute("aria-invalid", "true");
      document.getElementById("key-err").textContent = "A licence key looks like THREATS-PRO- followed by 20 letters and digits.";
      input.focus();
      return;
    }

    input.value = key;
    submitEl.disabled = true;
    submitEl.setAttribute("aria-busy", "true");
    submitEl.textContent = "Checking…";

    await verify(key, { remember: Boolean(rememberEl?.checked) });

    submitEl.disabled = false;
    submitEl.removeAttribute("aria-busy");
    submitEl.textContent = "Activate key";
  };

  const downloadStix = async () => {
    setAlert(stixAlert, "");
    downloadEl.disabled = true;
    downloadEl.setAttribute("aria-busy", "true");
    downloadEl.textContent = "Preparing…";

    try {
      const response = await fetchImpl(`${api}/api/stix`, {
        headers: { authorization: `Bearer ${state.key}` },
      });

      if (!response.ok) {
        let data = null;
        try { data = await response.json(); } catch { /* empty error page */ }
        const error = data?.error ?? {};
        if (response.status === 401) {
          signOut(error.code, licenseMessage(error.code, error.message));
          return;
        }
        setAlert(stixAlert, licenseMessage(error.code, error.message));
        return;
      }

      const blob = await response.blob();
      const today = new Date().toISOString().slice(0, 10);
      const name = filenameFromDisposition(
        response.headers.get("content-disposition"),
        `threats-stix-${today}.json`,
      );
      const url = URL.createObjectURL(blob);
      const link = node("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
      showToast("STIX bundle downloaded");
    } catch {
      setAlert(stixAlert, licenseMessage("network"));
    } finally {
      downloadEl.disabled = false;
      downloadEl.removeAttribute("aria-busy");
      downloadEl.textContent = "Download STIX bundle";
    }
  };

  const forget = () => {
    state.key = "";
    clearStoredKey();
    input.value = "";
    document.getElementById("curl").textContent = curlExample(api, "");
    showActivate({ message: "Key forgotten on this device. Paste it again to unlock exports.", kind: "ok", focus: true });
  };

  form.addEventListener("submit", activate);
  input.addEventListener("input", () => {
    input.removeAttribute("aria-invalid");
    document.getElementById("key-err").textContent = "";
  });

  downloadEl.addEventListener("click", downloadStix);
  document.getElementById("pro-recheck").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "Checking…";
    await verify(state.key);
    button.disabled = false;
    button.textContent = "Check again";
  });
  document.getElementById("forget-device").addEventListener("click", forget);
  document.getElementById("copy-curl").addEventListener("click", () => {
    void copyText(document.getElementById("curl").textContent, "cURL command copied");
  });

  void requestJson(fetchImpl, `${api}/api/config`).then((result) => {
    const support = result.ok && result.data?.support_email ? result.data.support_email : FALLBACK_SUPPORT;
    for (const link of document.querySelectorAll("[data-support]")) {
      link.textContent = support;
      link.href = `mailto:${support}`;
    }
  });

  const stored = readStoredKey();
  if (!stored) {
    activateEl.hidden = false;
    loadingEl.hidden = true;
    return;
  }

  input.value = stored.key;
  if (rememberEl) rememberEl.checked = stored.remember;
  activateEl.hidden = true;
  loadingEl.hidden = false;
  void verify(stored.key, { remember: stored.remember, auto: true });
}
