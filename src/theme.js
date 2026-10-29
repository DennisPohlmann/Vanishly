// Vanishly - design templates, page rendering and translations.
//
// Translations are one JSON file per language (key -> text): the built-in
// translations/ folder (en, de), then TRANSLATIONS_DIR, whose files replace
// texts or add languages (fr.json adds French). Missing keys fall back to
// English.
//
// A template is a folder (see templates/README.md):
//   template.json  optional: site name, logo, favicon, footer links, texts
//   theme.css      required: the CSS variables for light and dark mode
//   assets/        optional: images, fonts, extra CSS, served at /theme/assets/
//   views/         optional: own HTML for layout, home, secret, receipt, error
// It is looked up in TEMPLATES_DIR first (mounted, survives updates), then in
// the built-in templates/ folder. Views it does not bring come from views/.

import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VIEWS = ['layout', 'home', 'secret', 'receipt', 'error', 'login'];
const BUILTIN_TRANSLATIONS = join(ROOT, 'translations');

/** @param {string} s */
export function escapeHtml(s) {
  return String(s ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] || c,
  );
}

/**
 * Fills {{ key }} (escaped), {{{ key }}} (raw HTML, only for values the app
 * builds itself) and {{ t:key }} (translation, escaped).
 * @param {string} tpl
 * @param {Record<string, any>} ctx
 * @param {Record<string, string>} t
 */
export function render(tpl, ctx, t) {
  return tpl.replace(/\{\{(\{?)\s*(t:)?([\w.-]+)\s*\}?\}\}/g, (_, raw, isT, key) => {
    const v = isT ? (t[key] ?? key) : ctx[key];
    return raw ? String(v ?? '') : escapeHtml(v);
  });
}

/** @param {string} file */
function readSmall(file) {
  const st = lstatSync(file);
  if (!st.isFile() || st.size > 512 * 1024) throw new Error(`${file}: not a plain file up to 512 KB`);
  return readFileSync(file, 'utf8');
}

/**
 * Reads the translation files: built-in, then translationsDir (replaces keys,
 * adds languages). Returns key -> text per language code, English first.
 * @param {string} [translationsDir]
 */
export function loadTranslations(translationsDir) {
  /** @type {Record<string, Record<string, string>>} */
  const found = {};
  for (const dir of [BUILTIN_TRANSLATIONS, translationsDir]) {
    if (!dir || !isDir(dir)) continue;
    for (const f of readdirSync(dir).sort()) {
      if (!f.endsWith('.json')) continue;
      const file = join(dir, f);
      const code = f.slice(0, -5);
      if (!/^[a-z]{2,3}$/.test(code)) throw new Error(`${file}: the name must be a language code like fr.json`);
      /** @type {any} */
      let data;
      try {
        data = JSON.parse(readSmall(file));
      } catch (err) {
        throw new Error(`${file}: ${/** @type {Error} */ (err).message}`);
      }
      if (!data || typeof data !== 'object' || Array.isArray(data) || Object.values(data).some((v) => typeof v !== 'string')) {
        throw new Error(`${file}: must be a JSON object of texts ("key": "text")`);
      }
      found[code] = { ...found[code], ...data };
    }
  }
  if (!found.en) throw new Error('translations: en.json is missing');
  const codes = ['en', ...(found.de ? ['de'] : []), ...Object.keys(found).filter((c) => c !== 'en' && c !== 'de').sort()];
  /** @type {Record<string, Record<string, string>>} */
  const out = {};
  for (const c of codes) out[c] = { ...found.en, lang: c, ...found[c] };
  return out;
}

/** @param {string} dir */
function isDir(dir) {
  try {
    return lstatSync(dir).isDirectory();
  } catch {
    return false;
  }
}

/**
 * @param {string} name
 * @param {string} templatesDir
 */
export function findTemplate(name, templatesDir) {
  for (const base of [templatesDir, join(ROOT, 'templates')]) {
    const dir = join(base, name);
    if (base && isDir(dir) && existsSync(join(dir, 'theme.css'))) return dir;
  }
  throw new Error(`template "${name}" not found in ${templatesDir} or templates/`);
}

/** @param {string} url */
function safeUrl(url) {
  return typeof url === 'string' && /^(https?:\/\/|mailto:|\/)/i.test(url) && !/^\/\//.test(url) ? url : '';
}

/**
 * Loads a template with its views and the translations. LANGUAGES (empty:
 * all found) and DEFAULT_LANG (empty: en, or the first served) are checked
 * against the translations; with one language the language link is off.
 * @param {{ template: string, templatesDir: string, translationsDir?: string, languages?: string[] | null,
 *   defaultLang?: string, defaultMode?: string, apiDocs?: boolean, features?: Record<string, boolean> }} config
 * @param {string} version
 */
export function loadTheme(config, version) {
  const dir = findTemplate(config.template, config.templatesDir);
  /** @type {any} */
  let meta = {};
  if (existsSync(join(dir, 'template.json'))) meta = JSON.parse(readSmall(join(dir, 'template.json')));

  /** @type {Record<string, string>} */
  const views = {};
  for (const v of VIEWS) {
    const own = join(dir, 'views', `${v}.html`);
    views[v] = readSmall(existsSync(own) ? own : join(ROOT, 'views', `${v}.html`));
  }

  const all = loadTranslations(config.translationsDir);
  const languages = config.languages?.length ? config.languages : Object.keys(all);
  for (const l of languages) {
    if (!all[l]) throw new Error(`LANGUAGES: no translation for "${l}" (translations/ or TRANSLATIONS_DIR)`);
  }
  const defaultLang = config.defaultLang || (languages.includes('en') ? 'en' : languages[0]);
  if (!languages.includes(defaultLang)) throw new Error(`DEFAULT_LANG=${defaultLang} is not one of LANGUAGES (${languages.join(',')})`);
  // The template's own texts (template.json "strings") on top.
  /** @type {Record<string, Record<string, string>>} */
  const strings = {};
  for (const l of languages) strings[l] = { ...all[l], ...(meta.strings?.[l] || {}) };

  /** @param {string | undefined} file */
  const asset = (file) =>
    file && /^[\w.-]+(\/[\w.-]+)*$/.test(file) && !file.includes('..') && existsSync(join(dir, 'assets', file))
      ? `/theme/assets/${file}?v=${encodeURIComponent(version)}`
      : '';

  const links = Array.isArray(meta.footerLinks) ? meta.footerLinks : [];
  /** @param {string} lang */
  const footerLinks = (lang) =>
    links
      .map((l) => {
        const url = safeUrl(l?.url);
        const label = typeof l?.label === 'object' ? l.label[lang] || l.label.en : l?.label;
        return url && label ? `<a href="${escapeHtml(url)}" rel="noopener">${escapeHtml(label)}</a>` : '';
      })
      .filter(Boolean)
      .join('');

  // Body classes for switched-off features (ENABLE_*=false); base.css hides them.
  const f = config.features || {};
  const langSwitch = f.langSwitch !== false && languages.length > 1;
  const featureClasses = [
    [f.passphrase, 'no-passphrase'],
    [f.views, 'no-views'],
    [f.receipts, 'no-receipts'],
    [f.burn, 'no-burn'],
    [f.viewLog, 'no-view-log'],
    [f.receiptShareLink, 'no-receipt-key'],
    [f.generator, 'no-generator'],
    [langSwitch, 'no-lang-switch'],
    [f.themeToggle, 'no-theme-toggle'],
    [f.apiLink, 'no-api-link'],
    [f.githubLink, 'no-github-link'],
  ]
    .filter(([enabled]) => enabled === false)
    .map(([, cls]) => cls)
    .join(' ');
  const apiHref = config.apiDocs === false ? '/api/openapi.json' : '/api/docs';

  // DEFAULT_MODE, otherwise the template's defaultMode, otherwise the system.
  const mode = [config.defaultMode, meta.defaultMode].find((m) => ['light', 'dark', 'auto'].includes(m)) || 'auto';

  return {
    dir,
    name: config.template,
    views,
    strings,
    /** The languages served, the default first-choice fallback, and whether visitors may switch. */
    languages,
    defaultLang,
    langSwitch,
    /**
     * @param {string} view
     * @param {string} lang
     * @param {Record<string, any>} ctx
     * @param {string[]} [clientKeys] translations the page script needs
     */
    page(view, lang, ctx, clientKeys = []) {
      const t = strings[lang] || strings[defaultLang];
      const next = languages[(languages.indexOf(t.lang) + 1) % languages.length];
      const siteName = meta.siteName || 'Vanishly';
      /** @type {Record<string, string>} */
      const client = {};
      for (const k of Object.keys(t)) {
        if (clientKeys.some((p) => k === p || k.startsWith(`${p}.`))) client[k] = t[k];
      }
      const logo = asset(meta.logo);
      const base = {
        lang,
        siteName,
        version,
        defaultMode: mode,
        logoHtml: logo ? `<img class="brand-logo" src="${escapeHtml(logo)}" alt="">` : '',
        favicon: asset(meta.favicon) || `/static/favicon.svg?v=${encodeURIComponent(version)}`,
        themeCss: `/theme/theme.css?v=${encodeURIComponent(version)}`,
        footerLinks: footerLinks(lang),
        otherLang: next,
        otherLangName: strings[next]['lang.name'] || next,
        featureClasses: [featureClasses, ...(Array.isArray(ctx.bodyClasses) ? ctx.bodyClasses : [])].filter(Boolean).join(' '),
        modeToggle: f.themeToggle === false ? '0' : '1',
        apiHref,
        ...ctx,
      };
      const body = render(views[view], base, t);
      const html = render(
        views.layout,
        {
          ...base,
          title: ctx.title ? `${ctx.title} - ${siteName}` : siteName,
          content: body,
          // JSON inside <script type="application/json">: no "<" so it cannot end the tag.
          i18n: JSON.stringify(client).replace(/</g, '\\u003c'),
        },
        t,
      );
      // Signed out where creating needs a sign-in: the "New secret" link is
      // left out of the page (base.css hides it too, for layouts without the class).
      return base.featureClasses.split(' ').includes('no-new-link') ? html.replace(/<a class="nav-new" href="\/">[^<]*<\/a>\s*/, '') : html;
    },
  };
}

/**
 * Lists the template folders (for docs and the startup log).
 * @param {string} templatesDir
 */
export function listTemplates(templatesDir) {
  const names = new Set();
  for (const base of [templatesDir, join(ROOT, 'templates')]) {
    if (!isDir(base)) continue;
    for (const n of readdirSync(base)) if (existsSync(join(base, n, 'theme.css'))) names.add(n);
  }
  return [...names].sort();
}

/** @typedef {ReturnType<typeof loadTheme>} Theme */
