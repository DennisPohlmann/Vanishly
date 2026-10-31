# Accessibility

Vanishly is meant to be usable by everyone: with a keyboard only, with a
screen reader, with zoom or on a small phone.

## Target

The web interface aims at **WCAG 2.2 level AA**, which is also what
BITV 2.0 and EN 301 549 require. This covers every page of the built-in
templates (`default`, `aurora`, `example-brand`) in light and dark mode,
in English and German: create, link ready, reveal, status page, sign-in,
API tokens and the audit log page.

## What Vanishly does

- **Keyboard:** everything works without a mouse; the first Tab reaches
  "Skip to content"; the focus is always visible and moves to the link
  after "Create", to the secret after "Show" and to the field after an
  error.
- **Screen readers:** landmarks, labelled fields, hints tied to their
  field, errors read out, status messages ("Copied", "Your link is ready")
  in a live region, the page language set.
- **Seeing:** contrast at least 4.5:1 for text and 3:1 for controls;
  Windows high contrast keeps every control visible; light and dark mode.
- **Zoom and phones:** works at 320 px width and 400 % zoom without
  sideways scrolling; touch targets at least 24 px.
- **Motion:** animations only when the system does not ask for reduced
  motion.

The details for developers are in
[DEVELOPMENT.md](DEVELOPMENT.md#accessibility).

## How it is checked

Every change runs `npm run test:a11y` in CI: the form, errors, link
ready, reveal, wrong passphrase, revealed, status page, gone, 404 and the
sign-in flow with recipients, in every built-in template, light and dark, at desktop size and at 320 px,
checked with [axe-core](https://github.com/dequelabs/axe-core) against
WCAG 2.0 to 2.2 A/AA, plus the reflow, the skip link and the focus on
errors.

## Known limits

- Automated tests find about half of all problems. No formal audit
  with a screen reader (NVDA, VoiceOver) has been made yet.
- The pages "API tokens" and the audit log page (`/admin`) are built
  with the same components but are not yet part of the automated check.
- The API reference at `/api/docs` is a third-party page (Scalar) for
  developers and not part of the check.
- Own templates (`TEMPLATES_DIR`) are the operator's responsibility; check
  them with `TEMPLATES_DIR=/path/to/templates A11Y_TEMPLATES=my-brand npm run test:a11y`.

## Feedback

Found something that is hard or impossible to use? Please open an
[accessibility issue](https://github.com/DennisPohlmann/Vanishly/issues/new?template=accessibility.yml).
Operators who run Vanishly for an organisation publish their own
accessibility statement; this page describes the software.
