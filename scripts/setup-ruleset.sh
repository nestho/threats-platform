#!/usr/bin/env bash
# Branch protection for nestho/threats-platform, via GitHub rulesets.
#
# Why rulesets and not classic branch protection: a ruleset is evaluated by
# GitHub's backend and cannot be bypassed with a plain `git push`, which is
# exactly the failure that let an empty feed reach production before this branch.
#
# Requires: Administration read-write on the repo.
set -euo pipefail

REPO="nestho/threats-platform"

# Required status check. The gate runs as the "Validate feed data" step inside
# the Update Threat Data workflow, which is NOT a PR check -- so this deliberately
# does not require it. A PR check needs a separate workflow; see the note below.
read -r -d '' RULESET <<'JSON' || true
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    {
      "type": "deletion",
      "parameters": { "restricts deletions": true }
    },
    {
      "type": "non_fast_forward",
      "parameters": { "restricts non-fast-forward merges": true }
    }
  ]
}
JSON

echo "==> creating ruleset on $REPO"
gh api --method POST "/repos/$REPO/rulesets" --input - <<<"$RULESET" \
  --jq '{id, name, enforcement, target}'

echo
echo "==> current rulesets"
gh api "/repos/$REPO/rulesets" --jq '.[] | {id, name, enforcement, target}'

echo
echo "NOTE: this blocks force-push and deletion on main, but does not yet"
echo "      require a PR. To also require one, add a ruleset rule of type"
echo "      \"pull_request\" with \"required_approving_review_count\": 0 and"
echo "      \"required_linear_history\": true."
echo
echo "ALSO: the feed gate is a step inside the scheduled Update Threat Data"
echo "      workflow, not a check on pull requests. To gate merges on it, add a"
echo "      .github/workflows/validate.yml that runs on pull_request and calls"
echo "      scripts/validate_feeds.py. Say the word and I'll write it."
