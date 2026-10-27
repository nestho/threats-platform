#!/usr/bin/env bash
# Repository protection for nestho/threats-platform.
#
# Why rulesets and not classic branch protection: a ruleset is evaluated by
# GitHub's backend and cannot be bypassed by a plain `git push` or by an admin
# clicking through a warning. `bypass_actors` is deliberately empty, so there is
# no account-level escape hatch either.
#
# What this script enforces
# -------------------------
#   main accepts changes only through a pull request
#   the pull request must pass: Feed data, Unit tests, Python tests
#   history stays linear (squash merges only)
#   main cannot be deleted or force-pushed
#   the default Actions token is read-only and cannot approve pull requests
#   Pages serves threats.top over HTTPS
#
# It is idempotent: re-running updates the existing ruleset in place.
#
# Requires: Administration read-write on the repository (gh auth with `repo`
# scope plus admin on the repo).
set -euo pipefail

REPO="${REPO:-nestho/threats-platform}"
RULESET_NAME="protect-main"

# The check names below are the `name:` of each job in
# .github/workflows/validate.yml. Changing a job name without changing this
# list would leave a required check that never reports, which blocks every
# merge; changing one without the other is the failure this comment prevents.
read -r -d '' RULESET <<'JSON' || true
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "require_extra_approval_for_unattributed_changes": false,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "Feed data" },
          { "context": "Unit tests" },
          { "context": "Python tests" }
        ]
      }
    }
  ]
}
JSON

# One approval would deadlock a solo-maintained repository: GitHub does not let
# an author approve their own pull request, and the automation bot cannot either.
# The gate is therefore the pull request plus the three required checks, not a
# human approval. Set this to 1 the day a second maintainer joins.
#
# require_extra_approval_for_unattributed_changes defaults to true and demands
# an additional human approval for commits whose author is not a known GitHub
# account -- which is every commit the data bot makes. Left on, automated data
# pull requests could never auto-merge, so it is explicitly disabled.

echo "==> repository: $REPO"

# ---------------------------------------------------------------- ruleset ---

existing_id="$(
  gh api "/repos/$REPO/rulesets" \
    --jq ".[] | select(.name == \"$RULESET_NAME\") | .id" \
    | head -n 1
)"

if [[ -n "$existing_id" ]]; then
  echo "==> updating ruleset $RULESET_NAME (id $existing_id)"
  gh api --method PUT "/repos/$REPO/rulesets/$existing_id" \
    --input - <<<"$RULESET" \
    --jq '{id, name, enforcement, target, bypass_actors}'
else
  echo "==> creating ruleset $RULESET_NAME"
  gh api --method POST "/repos/$REPO/rulesets" \
    --input - <<<"$RULESET" \
    --jq '{id, name, enforcement, target, bypass_actors}'
fi

# ------------------------------------------------------- merge behaviour ---

echo
echo "==> enforcing squash-only merges and branch cleanup"
gh api --method PATCH "/repos/$REPO" --input - --jq \
  '{allow_auto_merge, allow_squash_merge, allow_merge_commit, allow_rebase_merge, delete_branch_on_merge, squash_merge_commit_title, squash_merge_commit_message}' <<'JSON'
{
  "allow_auto_merge": true,
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "delete_branch_on_merge": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY"
}
JSON

# ------------------------------------------------- Actions token hardening ---

echo
echo "==> setting the default Actions token to read-only"
gh api --method PUT "/repos/$REPO/actions/permissions/workflow" \
  --input - --jq . <<'JSON'
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": false
}
JSON

# Workflows that need write access request it explicitly (`update-data.yml`
# uses the data bot token, not the job token), so this closes the default
# "every workflow can push to main" hole without breaking either workflow.

# ---------------------------------------------------------------- Pages ---

echo
echo "==> enabling HTTPS enforcement for the custom domain"
if gh api --method PUT "/repos/$REPO/pages" --input - --jq \
  '{cname, https_enforced, status, source, html_url}' <<'JSON'
{
  "cname": "threats.top",
  "source": { "branch": "main", "path": "/" },
  "https_enforced": true
}
JSON
then
  :
else
  # GitHub refuses to enforce HTTPS until it has issued the certificate for the
  # domain. The domain is already attached, so this is a timing condition, not
  # a misconfiguration; re-run the script once Pages shows the certificate.
  echo "WARNING: HTTPS enforcement not enabled yet." >&2
  echo "         GitHub has not finished issuing the certificate for threats.top." >&2
  echo "         Re-run this script after the Pages settings show the certificate." >&2
fi

# -------------------------------------------------------------- bot creds ---

echo
echo "==> data bot credentials"
has_app_id="$(
  gh api "/repos/$REPO/actions/variables" \
    --jq '.variables[] | select(.name == "DATA_BOT_APP_ID") | .name' 2>/dev/null || true
)"
has_app_key="$(
  gh api "/repos/$REPO/actions/secrets" \
    --jq '.secrets[] | select(.name == "DATA_BOT_PRIVATE_KEY") | .name' 2>/dev/null || true
)"
has_pat="$(
  gh api "/repos/$REPO/actions/secrets" \
    --jq '.secrets[] | select(.name == "DATA_BOT_TOKEN") | .name' 2>/dev/null || true
)"

if [[ -n "$has_app_id" && -n "$has_app_key" ]]; then
  echo "    GitHub App credentials present (vars.DATA_BOT_APP_ID + secrets.DATA_BOT_PRIVATE_KEY)."
elif [[ -n "$has_pat" ]]; then
  echo "    PAT fallback present (secrets.DATA_BOT_TOKEN)."
else
  echo "    MISSING. Scheduled collection will run and validate, but it cannot"
  echo "    open the pull request that publishes the data."
  echo
  echo "    Preferred: create a GitHub App"
  echo "      1. https://github.com/settings/apps/new"
  echo "         name: threats-data-bot, no webhook, no user authorization"
  echo "         repository permissions: Contents R/W, Pull requests R/W,"
  echo "         Metadata R (granted automatically)"
  echo "      2. Install it on $REPO only."
  echo "      3. Set the repository variable DATA_BOT_APP_ID to the App ID."
  echo "      4. Set the repository secret DATA_BOT_PRIVATE_KEY to the .pem."
  echo
  echo "    Fallback: a fine-grained PAT with Contents and Pull requests write"
  echo "    on $REPO, stored as the repository secret DATA_BOT_TOKEN."
  echo
  echo "    App-created pull requests trigger the required checks; ones created"
  echo "    with the built-in GITHUB_TOKEN do not, which is why the fallback"
  echo "    must also be a bot credential rather than github.token."
fi

# --------------------------------------------------------------- verify ---

echo
echo "==> verify: ruleset"
gh api "/repos/$REPO/rulesets" \
  --jq '.[] | select(.name == "protect-main") | {id, name, enforcement, target}'

ruleset_id="$(
  gh api "/repos/$REPO/rulesets" \
    --jq '.[] | select(.name == "protect-main") | .id' | head -n 1
)"
gh api "/repos/$REPO/rulesets/$ruleset_id" \
  --jq '{bypass_actors, rules: [.rules[] | {type, parameters}]}'

echo
echo "==> verify: repository merge settings"
gh api "/repos/$REPO" \
  --jq '{allow_auto_merge, allow_squash_merge, allow_merge_commit, allow_rebase_merge, delete_branch_on_merge}'

echo
echo "==> verify: Actions token"
gh api "/repos/$REPO/actions/permissions/workflow" --jq .

echo
echo "==> verify: Pages"
gh api "/repos/$REPO/pages" \
  --jq '{cname, https_enforced, status, source}'

echo
echo "Done. main now accepts changes only through a pull request whose"
echo "Feed data, Unit tests and Python tests checks pass."
