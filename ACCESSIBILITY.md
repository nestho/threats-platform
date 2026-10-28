# Accessibility

threats.top targets **WCAG 2.2 Level AA**. Security decisions are sometimes made
under time pressure, and the site must remain readable and operable by keyboard,
screen reader, low-vision, and reduced-motion users.

## What is implemented

- Semantic landmarks (`header`, `nav`, `main`, `aside`, `footer`), one `h1` per
  page, and a skip link as the first focusable element.
- Visible focus indicators on every interactive element; no focus traps.
- Data tables with captions, column scopes, and a text alternative for every
  state that is also conveyed by colour.
- Tabs implemented with `role="tablist"`, arrow-key navigation, and
  `aria-selected`.
- Live regions (`aria-live`) for counts, filter results, and status changes, so
  updates are announced without stealing focus.
- `prefers-reduced-motion` disables non-essential animation; no information is
  conveyed by motion alone.
- Colour tokens chosen for AA contrast on the dark surface; status is never
  communicated by colour only (label plus icon or text).
- Relative timestamps always carry an absolute UTC value in a `title` or
  adjacent text.

## Known limitations

- The map view (when enabled) renders country-level aggregates. Its underlying
  numbers are duplicated in a table view for screen readers and for users who
  cannot use pointer interaction.
- Long indicator values and adversarial URLs are wrapped rather than truncated;
  at very high zoom this can make a row taller.

## How this is checked

- Keyboard-only pass and 200% zoom on each page for changes that touch
  interaction.
- Chrome, Safari, and Firefox current versions.
- Automated checks in review; the pull request template requires an
  accessibility note for new components.

## Report a barrier

Open an issue with the **Bug report** template and describe the page, the
assistive technology, and what you expected. If the barrier is also a security
issue, follow [SECURITY.md](SECURITY.md) instead.
