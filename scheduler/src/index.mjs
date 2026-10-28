/**
 * External cron for the data pipeline.
 *
 * GitHub's own scheduler delivers only a fraction of `schedule` events for this
 * repository (measured: 3-8 of 24 per day, in 2-5 hour gaps), which is why
 * collection is triggered from a Cloudflare Cron Trigger instead. This Worker
 * only dispatches the existing workflow; it never touches data, and the token
 * it holds can do nothing except start workflows in this repository.
 */
const WORKFLOW = "update-data.yml";
const REF = "main";
const MAX_ATTEMPTS = 3;

const isRetryable = (status) => status === 429 || status >= 500;

export async function dispatchUpdate({
  token,
  repo,
  fetchImpl = fetch,
  attempts = MAX_ATTEMPTS,
}) {
  if (!token) throw new Error("GH_TOKEN is not configured");
  if (!repo) throw new Error("REPO is not configured");

  const url = `https://api.github.com/repos/${repo}/actions/workflows/${WORKFLOW}/dispatches`;
  let lastError = "";

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "threats-scheduler",
      },
      body: JSON.stringify({ ref: REF, inputs: { feeds: "auto" } }),
    });

    if (response.ok) return { status: response.status, attempts: attempt };

    lastError = `GitHub responded ${response.status}: ${await response.text()}`;
    if (!isRetryable(response.status)) break;
  }

  throw new Error(lastError);
}

async function run(env) {
  const result = await dispatchUpdate({ token: env.GH_TOKEN, repo: env.REPO });
  console.log(`dispatched ${WORKFLOW} (${result.status}) on attempt ${result.attempts}`);
}

export default {
  scheduled(_controller, env, ctx) {
    ctx.waitUntil(run(env));
  },
};
