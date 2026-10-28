/**
 * Runtime settings live in D1 so the owner can change wallets and prices
 * without a deploy. Only keys in this file are writable; everything else in
 * the table is seed data and internal.
 */

import { normalizeEmail } from "./validation.mjs";

const TRON_ADDRESS = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
const BECH32_ADDRESS = /^bc1q[02-9ac-hj-np-z]{38,58}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const defaultSettings = Object.freeze({
  pro_monthly_cents: 3900,
  usdt_trc20_address: "TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2",
  btc_address: "bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq",
  stix_rate_per_min: 600,
  support_email: "nestho@icloud.com",
  order_retention_days: 180,
});

const validators = {
  pro_monthly_cents(value) {
    const cents = Number(value);
    if (!Number.isInteger(cents) || cents < 100 || cents > 1_000_000) {
      return { ok: false, error: "Price must be whole cents between 100 and 1000000." };
    }
    return { ok: true, value: cents };
  },
  usdt_trc20_address(value) {
    const address = String(value).trim();
    if (!TRON_ADDRESS.test(address)) {
      return { ok: false, error: "Enter a TRON (TRC20) address starting with T." };
    }
    return { ok: true, value: address };
  },
  btc_address(value) {
    const address = String(value).trim().toLowerCase();
    if (!BECH32_ADDRESS.test(address)) {
      return { ok: false, error: "Enter a native SegWit address starting with bc1q." };
    }
    return { ok: true, value: address };
  },
  stix_rate_per_min(value) {
    const rate = Number(value);
    if (!Number.isInteger(rate) || rate < 1 || rate > 10_000) {
      return { ok: false, error: "Rate must be between 1 and 10000 per minute." };
    }
    return { ok: true, value: rate };
  },
  support_email(value) {
    const email = normalizeEmail(value);
    if (email.length > 254 || !EMAIL.test(email)) {
      return { ok: false, error: "Enter a valid email address." };
    }
    return { ok: true, value: email };
  },
  order_retention_days(value) {
    const days = Number(value);
    if (!Number.isInteger(days) || days < 31 || days > 3650) {
      return { ok: false, error: "Retention must be between 31 and 3650 days." };
    }
    return { ok: true, value: days };
  },
};

export function validateSetting(key, value) {
  const validate = validators[key];
  if (!validate) return { ok: false, error: `Unknown setting: ${key}` };
  return validate(value);
}

export function publicConfig(settings) {
  const merged = { ...defaultSettings, ...settings };
  return {
    pro_monthly_cents: merged.pro_monthly_cents,
    plan_months: [1, 3, 12],
    methods: ["usdt_trc20", "btc"],
    wallets: {
      usdt_trc20: merged.usdt_trc20_address,
      btc: merged.btc_address,
    },
    support_email: merged.support_email,
  };
}
