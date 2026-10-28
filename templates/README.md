# Design templates

Each folder here is one design. `TEMPLATE=<folder name>` picks it (default:
`default`). Built in:

- `default`: blue and calm
- `aurora`: bright white with soft violet and teal accents, round pill
  buttons; a deep night-blue dark mode
- `example-brand`: an orange company example with logo, footer links, own
  texts and an own error page; copy it as a starting point

All of them have light and dark mode (the button in the header,
`ENABLE_THEME_TOGGLE`) and work on phones. Which mode a visitor sees first:
`DEFAULT_MODE` (`auto`, `light`, `dark`), otherwise `defaultMode` in
`template.json`, otherwise the system setting.

```
templates/
  my-brand/
    theme.css        # required: the CSS variables (light and dark)
    template.json    # optional: site name, logo, favicon, footer links, texts
    assets/          # optional: logo, pictures, fonts, extra files
      logo.svg
    views/           # optional: own HTML for single pages
      error.html
```

## Your own template

1. Copy `default` or `example-brand` and give it a new name: lower-case
   letters, digits, `-` and `_`, at most 32 characters (`acme`, `it-blue`).
2. Change the colours in `theme.css`. Keep the two blocks
   `:root, html[data-theme="light"]` and `html[data-theme="dark"]`; only CSS
   variables belong there (the layout is in `public/css/base.css`). After
   them you may add own rules for more character, as `aurora` (accent
   line, pill buttons, gradient button) does;
   they are loaded after `base.css` and win. Keep
   text readable (contrast at least 4.5:1), e.g. `--accent-on` on
   `--accent` and `--bad-on` on `--bad`.
3. Put your pictures into `assets/` and name them in `template.json`.
4. Put the folder where Vanishly finds it and restart:
   - **Docker Compose:** `./custom-templates/` (mounted read-only at
     `/var/lib/vanishly/templates`).
   - **Container:** mount a folder at `/var/lib/vanishly/templates`:
     `-v /srv/vanishly-templates:/var/lib/vanishly/templates:ro`.
   - **tar.gz:** `/var/lib/vanishly/templates/` (`TEMPLATES_DIR`).
   - Or directly into this folder; an update replaces it.

   The container reads as uid 1000 (under rootless Podman not your own
   user): make the files readable with `chmod -R a+rX custom-templates`.
   With SELinux (Fedora, RHEL) mount with `:ro,Z` instead of `:ro`.

   A folder in `TEMPLATES_DIR` with the name of a built-in one replaces it.
   Templates are read at start: restart after a change
   (`docker compose restart vanishly`).

Only plain files are used (no symbolic links); views and `template.json` at
most 512 KB each.

## CSS variables (`theme.css`)

| Variable | Use |
|---|---|
| `--font`, `--font-mono` | text font, font of secrets and links |
| `--radius` | corner radius of cards, fields, buttons |
| `--logo-height` | height of the logo in the header |
| `--bg` | page background |
| `--surface`, `--surface-2` | cards; secondary buttons and badges |
| `--input-bg` | text fields |
| `--border` | lines and borders |
| `--text`, `--muted` | text, secondary text |
| `--link`, `--link-hover` | links |
| `--accent`, `--accent-hover`, `--accent-on` | main buttons, focus ring; text on the accent |
| `--header-bg`, `--header-text` | header bar |
| `--good`, `--good-bg` | success notices, open states |
| `--bad`, `--bad-bg`, `--bad-on` | errors, burn button; text on `--bad` |
| `--shadow` | shadow of the cards |

Fonts and pictures in `assets/` are served at `/theme/assets/<file>`;
from `theme.css` (served at `/theme/theme.css`) use relative URLs:
`url("assets/brand.woff2")`. Everything must be on your server: the Content
Security Policy blocks external fonts, images and scripts.

## `template.json`

```json
{
  "name": { "de": "ACME", "en": "ACME" },
  "siteName": "ACME Secrets",
  "logo": "logo.svg",
  "favicon": "favicon.png",
  "defaultMode": "auto",
  "footerLinks": [
    { "label": { "de": "Impressum", "en": "Imprint" }, "url": "https://example.com/imprint" }
  ],
  "strings": {
    "en": { "tagline": "One link, one view." },
    "de": { "tagline": "Ein Link, ein Aufruf." }
  }
}
```

| Key | Meaning |
|---|---|
| `siteName` | name in the header and the page title (default `Vanishly`) |
| `logo`, `favicon` | file names in `assets/` |
| `defaultMode` | `auto` (system setting), `light` or `dark`; the visitor's switch wins |
| `footerLinks` | links in the footer; `url` must start with `https://`, `http://`, `mailto:` or `/` |
| `strings` | overrides texts of `translations/<lang>.json` by key, per language (`en`, `de`, or one added in `TRANSLATIONS_DIR`) |

## Own views (`views/`)

A template can replace `layout.html`, `home.html`, `secret.html`,
`receipt.html`, `error.html` or `login.html` (the sign-in prompt) of the
app's `views/` folder. Start from the
original. Placeholders:

- `{{ name }}`: a value, HTML-escaped
- `{{{ name }}}`: HTML built by Vanishly (`content`, `ttlSelect`, `footerLinks`, `logoHtml`, `i18n`,
  and with sign-in `authNav` in the layout and `recipientsBlock` in the home view)
- `{{ t:key }}`: a text from `translations/*.json` or `strings`

Keep the element ids the page script uses (`create-form`, `secret`,
`reveal-card`, ...) and do not add inline `<script>` or `style=""`: the
Content Security Policy blocks them. Extra CSS goes into `theme.css`.

## Own views and the switches

The `ENABLE_*` switches (docs/CONFIG.md) add classes to `<body>`, e.g.
`no-passphrase no-receipts`, and `public/css/base.css` hides the matching
parts by their ids: `#passphrase-wrap`, `#views-wrap`, `#receipt-wrap`,
`.r-log-row`, `#generate`, `.lang-switch`, `#mode-toggle`, `.api-link`. An
own `home.html`, `receipt.html` or `layout.html` should keep these ids and
classes (copy them from `views/`), or hide the parts itself, e.g.
`.no-generator .my-button { display: none; }`. The server enforces the
switches anyway; the classes only keep the page tidy.

With sign-in (`AUTH_PROVIDER`), an own `layout.html` needs `{{{ authNav }}}`
for the "Sign in" / "Sign out" links, an own `home.html`
`{{{ recipientsBlock }}}` and `#created-restricted`, and an own
`secret.html` the `#locked` block with `data-locked` on `#reveal-card`
(copy them from `views/`). Without them the sign-in still protects the
secrets, but the page lacks the buttons.
