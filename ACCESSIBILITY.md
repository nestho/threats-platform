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
  conveyed by motion alone. On the live map this suppresses claim pulses and
  country flashes, and turns the replay button into a jump to the start of the
  window that the labelled range slider steps through.
- The live map's layer switcher is a button group with `aria-pressed`; every
  placed country is a keyboard-operable button named with its claim and host
  counts. The 72-hour replay is a labelled range input. Feed polling pauses
  when the tab is hidden and can be stopped with a toggle button.
- The subscribe page is one labelled form: plan choices are a radio group in a
  fieldset, each wallet has a copy button whose success is announced, every
  error is linked to its field with `aria-describedby` and `aria-invalid`, and
  the confirmation and status lookup results land in a live region.
- The Pro console announces activation, expiry, revocation, and download
  outcomes through a live region; the status heading receives focus after a
  key is verified so a screen reader lands on the result, and the key input
  carries a description of the expected format. The remembered-key checkbox is
  a normal 15px control, not a stretched input.
- The admin panel uses the same tab implementation as the public pages. Every
  confirm action is a native `<dialog>` opened with `showModal()`, labelled by
  its heading, with focus moved to the first control, Escape to close, and
  focus returned to the trigger by the browser. Clicking the backdrop closes
  it. Session expiry is announced as an alert and returns to the sign-in form.
  Wide tables carry a visible note that they scroll horizontally.
- Colour tokens chosen for AA contrast on the dark surface; status is never
  communicated by colour only (label plus icon or text).
- Relative timestamps always carry an absolute UTC value in a `title` or
  adjacent text.

## Known limitations

- The live map renders country-level aggregates only, and the world outline
  has no polygon for some microstates; those are named in a note under the map
  and remain in the table. Every number on the map is duplicated in a table for
  screen readers and for users who cannot use pointer interaction. Phishing
  host countries describe where the IP is registered, often a CDN, not where an
  operator sits.
- Long indicator values and adversarial URLs are wrapped rather than truncated;
  at very high zoom this can make a row taller.
- The admin tables are dense by design and scroll horizontally on narrow
  screens; the first columns stay readable, but a 390px viewport shows fewer
  columns at once. The transaction reference and action column need the scroll.
- The payment pages ask the buyer to copy addresses from the page. There is no
  QR code, so a screen-reader user copies the same text as everyone else; the
  copy button is an alternative to selecting the address by hand.

## How this is checked

- Keyboard-only pass and 200% zoom on each page for changes that touch
  interaction, including checkout, the Pro console, and the admin panel.
- Chrome, Safari, and Firefox current versions at 1440 and 390 CSS pixels.
- Automated checks in review; the pull request template requires an
  accessibility note for new components.
- The Design detector job (Impeccable) annotates contrast, line-length, and
  target-size findings on every pull request. It is advisory, not a substitute
  for a rendered-page pass.

## Report a barrier

Open an issue with the **Bug report** template and describe the page, the
assistive technology, and what you expected. If the barrier is also a security
issue, follow [SECURITY.md](SECURITY.md) instead.
