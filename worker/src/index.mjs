/**
 * Router for threats-platform-api.
 *
 * `createApp` takes an injected repository so tests can run against the fake;
 * the default export wires D1 from the Worker binding.
 */

import * as admin from "./admin.mjs";
import { clientIp, corsOrigin, fail, preflight, withCors } from "./http.mjs";
import {
  config,
  createOrder,
  health,
  lookupOrder,
  proMe,
  stixDownload,
} from "./public.mjs";
import { createRepo } from "./repo.mjs";

const ROUTES = [
  ["GET", /^\/api\/health$/, health],
  ["GET", /^\/api\/config$/, config],
  ["POST", /^\/api\/orders$/, createOrder],
  ["POST", /^\/api\/orders\/lookup$/, lookupOrder],
  ["GET", /^\/api\/pro\/me$/, proMe],
  ["GET", /^\/api\/stix$/, stixDownload],
  ["POST", /^\/api\/admin\/login$/, admin.login],
  ["POST", /^\/api\/admin\/logout$/, admin.logout],
  ["GET", /^\/api\/admin\/session$/, admin.sessionInfo],
  ["GET", /^\/api\/admin\/orders$/, admin.listOrders],
  ["GET", /^\/api\/admin\/orders\/([^/]+)$/, admin.getOrder],
  ["POST", /^\/api\/admin\/orders\/([^/]+)\/approve$/, admin.approveOrder],
  ["POST", /^\/api\/admin\/orders\/([^/]+)\/reject$/, admin.rejectOrder],
  ["GET", /^\/api\/admin\/subscriptions$/, admin.listSubscriptions],
  ["POST", /^\/api\/admin\/subscriptions$/, admin.grantSubscription],
  ["POST", /^\/api\/admin\/subscriptions\/([^/]+)\/extend$/, admin.extendSubscription],
  ["POST", /^\/api\/admin\/subscriptions\/([^/]+)\/revoke$/, admin.revokeSubscription],
  ["POST", /^\/api\/admin\/subscriptions\/([^/]+)\/license$/, admin.rotateLicense],
  ["GET", /^\/api\/admin\/customers$/, admin.listCustomers],
  ["GET", /^\/api\/admin\/audit$/, admin.listAudit],
  ["GET", /^\/api\/admin\/stats$/, admin.stats],
  ["GET", /^\/api\/admin\/settings$/, admin.getSettings],
  ["PUT", /^\/api\/admin\/settings$/, admin.putSetting],
  ["GET", /^\/api\/admin\/export$/, admin.exportCsv],
];

export function createApp({ repo, env = {}, now = () => Date.now() }) {
  async function handle(request) {
    const origin = corsOrigin(request, env);
    if (origin === false) {
      return fail(403, "origin_rejected", "This origin is not allowed.");
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return withCors(preflight(origin), origin);
    }

    const candidates = ROUTES.map(([method, pattern, handler]) => {
      const match = path.match(pattern);
      return match ? { method, handler, params: match.slice(1) } : null;
    }).filter(Boolean);

    if (!candidates.length) {
      return withCors(fail(404, "not_found", "No such endpoint."), origin);
    }

    const route = candidates.find((candidate) => candidate.method === request.method);
    if (!route) {
      const allow = ["OPTIONS", ...candidates.map((candidate) => candidate.method)].join(", ");
      return withCors(
        fail(405, "method_not_allowed", `Use one of: ${allow}.`, { headers: { allow } }),
        origin,
      );
    }

    const ctx = { request, env, repo, url, now, ip: clientIp(request), params: route.params };
    try {
      const response = await route.handler(ctx);
      return withCors(response, origin);
    } catch (error) {
      console.error(`api error: ${error?.message ?? error}`);
      return withCors(fail(500, "server_error", "Something went wrong on our side."), origin);
    }
  }

  return { handle };
}

export function handleRequest(request, env) {
  return createApp({ repo: createRepo(env.DB), env }).handle(request);
}

const iso = (ms) => new Date(ms).toISOString().replace(".000Z", "Z");

export async function pruneRoutine(env, nowMs = Date.now()) {
  const repo = createRepo(env.DB);
  const settings = await repo.getSettings();
  const retentionDays = settings.order_retention_days ?? 180;
  return repo.prune({
    ordersBefore: iso(nowMs - retentionDays * 86_400_000),
    attemptsBefore: iso(nowMs - 30 * 86_400_000),
    windowsBefore: Math.floor((nowMs - 86_400_000) / 1000),
  });
}

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
  scheduled(_controller, env, ctx) {
    ctx.waitUntil(pruneRoutine(env));
  },
};
