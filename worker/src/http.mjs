/**
 * HTTP helpers shared by the public and admin routers.
 *
 * CORS is an explicit allowlist: the site and the local dev origin. There is
 * no wildcard, and credentials are allowed because the admin cookie is sent
 * from the same site but a different hostname.
 */

const JSON_TYPE = "application/json; charset=utf-8";

export function json(data, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": JSON_TYPE, "cache-control": "no-store", ...headers },
  });
}

export function fail(status, code, message, { headers = {}, ...extra } = {}) {
  return json({ error: { code, message, ...extra } }, { status, headers });
}

export function allowedOrigins(env) {
  return String(env?.ALLOWED_ORIGINS ?? "https://threats.top")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

export function corsOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  return allowedOrigins(env).includes(origin) ? origin : false;
}

export function withCors(response, origin) {
  if (!origin) return response;
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-credentials", "true");
  headers.append("vary", "Origin");
  return new Response(response.body, { status: response.status, headers });
}

export function preflight(origin) {
  const headers = new Headers({
    "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-csrf-token",
    "access-control-max-age": "600",
  });
  if (origin) headers.set("access-control-allow-origin", origin);
  return new Response(null, { status: 204, headers });
}

const BODY_ERRORS = {
  invalid_json: [400, "Send a valid JSON body."],
  payload_too_large: [413, "The request body is too large."],
  unsupported_media_type: [415, "Send content-type: application/json."],
};

export async function readJsonBody(request, limit = 16_384) {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().includes("application/json")) {
    return { ok: false, code: "unsupported_media_type" };
  }
  const text = await request.text();
  if (text.length > limit) {
    return { ok: false, code: "payload_too_large" };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, code: "invalid_json" };
  }
}

export function bodyFailure(result) {
  const [status, message] = BODY_ERRORS[result.code] ?? [400, "Invalid request body."];
  return fail(status, result.code, message);
}

export function clientIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "0.0.0.0"
  );
}
