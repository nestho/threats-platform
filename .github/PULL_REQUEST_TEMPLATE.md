## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Type

- [ ] Fix
- [ ] Feature
- [ ] Data or collector
- [ ] Documentation / CI
- [ ] Design or accessibility

## Data impact

<!-- Which feeds change, whether the contract changes, and whether anything is dropped during normalisation. Write "none" if not applicable. -->

## Test plan

<!-- Paste the commands you ran and their result, plus any manual checks. -->

- [ ] `python3 scripts/dev.py test`
- [ ] `python3 scripts/validate_feeds.py --against HEAD`
- [ ] Manual check at 500 px and 1440 px (UI changes)

## Checklist

- [ ] No demo, placeholder, or seeded data
- [ ] Upstream strings escaped; URLs restricted to http(s); indicators stay defanged
- [ ] `docs/CONTRACT.md` regenerated if a feed shape changed
- [ ] Accessibility considered for new interaction (keyboard, focus, reduced motion)
- [ ] No new runtime dependency or build step
- [ ] Security issues were reported privately, not in this pull request
