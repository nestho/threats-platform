/**
 * Router for threats-platform-api.
 *
 * `createApp` takes an injected repository so tests can run against the fake;
 * the default export wires D1 from the Worker binding.
 */

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

    const matched = ROUTES.filter(([, pattern]) => pattern.test(path));
    if (!matched.length) {
      return withCors(fail(404, "not_found", "No such endpoint."), origin);
    }

    const route = matched.find(([method]) => method === request.method);
    if (!route) {
      const allow = ["OPTIONS", ...matched.map(([method]) => method)].join(", ");
      return withCors(
        fail(405, "method_not_allowed", `Use one of: ${allow}.`, { headers: { allow } }),
        origin,
      );
    }

    const ctx = { request, env, repo, url, now, ip: clientIp(request) };
    try {
      const response = await route[2](ctx);
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

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
};
