/**
 * Order codes and licence keys.
 *
 * Crockford base32 drops I, L, O, and U so a code read over the phone cannot
 * be mistyped into a different valid value.
 */

export const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const LICENSE_PREFIX = "THREATS-PRO-";

function pick(alphabet, length, random) {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += alphabet[Math.floor(random() * alphabet.length)];
  }
  return out;
}

export function orderCode(random = Math.random) {
  return `TH-${pick(CROCKFORD, 5, random)}-${pick(CROCKFORD, 5, random)}`;
}

export function licenseKey(random = Math.random) {
  return `${LICENSE_PREFIX}${pick(CROCKFORD, 20, random)}`;
}

export function licensePrefix(key) {
  return String(key).slice(LICENSE_PREFIX.length, LICENSE_PREFIX.length + 8);
}
