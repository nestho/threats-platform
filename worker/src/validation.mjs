/**
 * Request validation for the public order endpoints.
 *
 * Every parser returns `{ ok: true, value }` or `{ ok: false, errors }` where
 * `errors` is field-keyed so the page can highlight the exact input.
 */

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE = /^[0-9+().\-\s]+$/;
const TX_REF = /^[A-Za-z0-9:_-]+$/;
const ORDER_CODE = /^TH-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/;

export const ORDER_MONTHS = Object.freeze([1, 3, 12]);
export const PAYMENT_METHODS = Object.freeze(["usdt_trc20", "btc"]);

const text = (value) => (typeof value === "string" ? value.trim() : "");

export function normalizeEmail(value) {
  return text(value).toLowerCase();
}

export function parseMonths(value, { min, max, values = ORDER_MONTHS } = {}) {
  const months = typeof value === "string" ? Number(value) : value;
  if (!Number.isInteger(months)) return null;
  if (min !== undefined || max !== undefined) {
    return months >= (min ?? 1) && months <= (max ?? 24) ? months : null;
  }
  return values.includes(months) ? months : null;
}

export function parseOrder(body, settings, now = Date.now()) {
  const input = body && typeof body === "object" ? body : {};
  const errors = {};

  const name = text(input.name);
  if (name.length < 2 || name.length > 80) {
    errors.name = "Enter the name on the payment, 2–80 characters.";
  }

  const email = normalizeEmail(input.email);
  if (email.length > 254 || !EMAIL.test(email)) {
    errors.email = "Enter an email address you can check.";
  }

  const phone = text(input.phone);
  const digits = phone.replace(/\D/g, "").length;
  if (phone && (phone.length < 5 || phone.length > 32 || !PHONE.test(phone) || digits < 5)) {
    errors.phone = "Use digits and + ( ) - . only, 5–32 characters.";
  }

  const months = typeof input.months === "number" ? parseMonths(input.months) : null;
  if (months === null) {
    errors.months = "Choose 1, 3, or 12 months.";
  }

  const method = text(input.method);
  if (!PAYMENT_METHODS.includes(method)) {
    errors.method = "Choose USDT (TRC20) or BTC.";
  }

  const txRef = text(input.tx_ref);
  if (txRef.length < 8 || txRef.length > 128 || !TX_REF.test(txRef)) {
    errors.tx_ref = "Paste the transaction ID, 8–128 characters.";
  }

  const note = text(input.note);
  if (note.length > 500) {
    errors.note = "Keep the note under 500 characters.";
  }

  if (text(input.company)) {
    errors.company = "Unexpected field.";
  }

  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const monthly = Number(settings?.pro_monthly_cents) || 0;
  return {
    ok: true,
    value: {
      name,
      email,
      phone: phone || null,
      months,
      method,
      tx_ref: txRef,
      note,
      amount_cents: monthly * months,
      created_at: new Date(now).toISOString().replace(".000Z", "Z"),
    },
  };
}

export function parseLookup(body) {
  const input = body && typeof body === "object" ? body : {};
  const errors = {};

  const code = text(input.code).toUpperCase();
  if (!ORDER_CODE.test(code)) errors.code = "Order codes look like TH-ABCDE-23456.";

  const email = normalizeEmail(input.email);
  if (email.length > 254 || !EMAIL.test(email)) {
    errors.email = "Enter the email used for the order.";
  }

  if (Object.keys(errors).length > 0) return { ok: false, errors };
  return { ok: true, value: { code, email } };
}
