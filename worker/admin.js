/**
 * Legacy threats.top admin API — retired.
 *
 * The previous Worker authenticated an admin password or HMAC "SaaS" key and
 * committed `data/manual.json` / `data/saas_tenants.json` straight to `main`
 * with a GitHub PAT. That made Cloudflare a second write path into published
 * data and bypassed review entirely. The tenant data it wrote was also public,
 * which is not a SaaS boundary.
 *
 * v1 has one write path: a pull request that passes the feed, Python, and unit
 * checks. Program scope is edited in `data/manual.json` through that path.
 *
 * This Worker now fails closed. Every legacy route returns 410 so an old client
 * gets an explicit answer instead of a silent 404, and nothing here reads a
 * secret or talks to GitHub. Phase 2 replaces this file with the D1-backed
 * `/api/*` Worker; until then the route stays parked.
 *
 * After deploying this version, delete the now-unused Cloudflare secrets:
 *   wrangler secret delete GITHUB_TOKEN
 *   wrangler secret delete ADMIN_PASSWORD_HASH
 *   wrangler secret delete SAAS_SIGNING_SECRET
 */

const RETIRED = {
  error: "This API was retired. Program scope changes go through a pull request.",
  docs: "https://github.com/nestho/threats-platform",
};

function json(payload, status) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export default {
  async fetch(request) {
    const { pathname } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }

    if (pathname === "/health" && request.method === "GET") {
      return json({ ok: true, service: "threats-edge", admin_api: "retired" }, 200);
    }

    return json(RETIRED, 410);
  },
};
