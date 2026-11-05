import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { escapeHtml, listTemplates, loadTheme, loadTranslations, render } from '../src/theme.js';

test('render escapes {{ }} and keeps {{{ }}} raw', () => {
  const out = render('<p>{{ a }}</p>{{{ b }}}{{ t:x.y }}{{ missing }}', { a: '<script>"', b: '<i>ok</i>' }, { 'x.y': 'A&B' });
  assert.equal(out, '<p>&lt;script&gt;&quot;</p><i>ok</i>A&amp;B');
  assert.equal(escapeHtml(`'`), '&#39;');
});

test('built-in default template loads with both languages', () => {
  const theme = loadTheme({ template: 'default', templatesDir: '/nonexistent', defaultLang: 'en' }, '1.2.3');
  const html = theme.page('home', 'de', { page: 'home', ttlSelect: '', viewsSelect: '', maxChars: 10 }, ['home']);
  assert.match(html, /<html lang="de"/);
  assert.match(html, /Geheimnis teilen/);
  assert.match(html, /\/theme\/assets\/logo\.svg\?v=1\.2\.3/);
  assert.match(html, /id="mode-toggle"/);
  assert.ok(listTemplates('/nonexistent').includes('default'));
});

test('an own template overrides views, texts, links; unsafe links are dropped', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ots-tpl-'));
  const t = join(dir, 'acme');
  mkdirSync(join(t, 'views'), { recursive: true });
  mkdirSync(join(t, 'assets'));
  writeFileSync(join(t, 'theme.css'), ':root{--accent:red}');
  writeFileSync(join(t, 'assets', 'logo.png'), 'x');
  writeFileSync(join(t, 'views', 'error.html'), '<div class="acme">{{ heading }}</div>');
  writeFileSync(
    join(t, 'template.json'),
    JSON.stringify({
      siteName: 'ACME Secrets',
      logo: 'logo.png',
      footerLinks: [
        { label: { en: 'Imprint', de: 'Impressum' }, url: 'https://example.com/imprint' },
        { label: 'Evil', url: 'javascript:alert(1)' },
        { label: 'Proto-relative', url: '//evil.example' },
      ],
      strings: { en: { 'nav.new': 'New ACME secret' } },
    }),
  );
  const theme = loadTheme({ template: 'acme', templatesDir: dir, defaultLang: 'en' }, '1');
  const html = theme.page('error', 'en', { page: 'error', heading: 'Oops' });
  assert.match(html, /<div class="acme">Oops<\/div>/);
  assert.match(html, /ACME Secrets/);
  assert.match(html, /New ACME secret/);
  assert.match(html, /href="https:\/\/example.com\/imprint"/);
  assert.doesNotMatch(html, /javascript:|evil\.example/);
  assert.match(html, /\/theme\/assets\/logo\.png/);
  assert.match(theme.page('error', 'de', { heading: 'x' }), /Impressum/);
});

test('a symlinked theme.css or view is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ots-tpl-'));
  const t = join(dir, 'linky');
  mkdirSync(join(t, 'views'), { recursive: true });
  writeFileSync(join(t, 'theme.css'), '');
  symlinkSync('/etc/hostname', join(t, 'views', 'home.html'));
  assert.throws(() => loadTheme({ template: 'linky', templatesDir: dir, defaultLang: 'en' }, '1'));
  const c = join(dir, 'linkcss');
  mkdirSync(c);
  symlinkSync(join(t, 'theme.css'), join(c, 'theme.css'));
  assert.throws(() => loadTheme({ template: 'linkcss', templatesDir: dir, defaultLang: 'en' }, '1'), /plain file/);
});

test('DEFAULT_MODE overrides the defaultMode of the template', () => {
  const page = (/** @type {string} */ mode) =>
    loadTheme({ template: 'example-brand', templatesDir: '/nonexistent', defaultLang: 'en', defaultMode: mode }, '1').page('error', 'en', { page: 'error' });
  assert.match(page(''), /data-default-mode="light"/); // example-brand says light
  assert.match(page('dark'), /data-default-mode="dark"/);
  assert.match(page('auto'), /data-default-mode="auto"/);
});

test('translations: built-in languages, checks of the files in TRANSLATIONS_DIR', () => {
  assert.deepEqual(Object.keys(loadTranslations()), ['en', 'de', 'es', 'fr', 'it', 'nl', 'pl', 'pt']);
  const base = { template: 'default', templatesDir: '/nonexistent' };
  assert.throws(() => loadTheme({ ...base, languages: ['sv'] }, '1'), /LANGUAGES: no translation for "sv"/);
  assert.throws(() => loadTheme({ ...base, languages: ['de'], defaultLang: 'en' }, '1'), /DEFAULT_LANG=en is not one of LANGUAGES/);
  assert.throws(() => loadTheme({ ...base, confirmText: { any: '', ge: 'x' } }, '1'), /CONFIRM_TEXT_GE: no translation for "ge"/);
  assert.doesNotThrow(() => loadTheme({ ...base, confirmText: { any: 'x', pl: 'y' } }, '1'));
  const de = loadTheme({ ...base, languages: ['de'] }, '1');
  assert.deepEqual([de.languages, de.defaultLang, de.langSwitch], [['de'], 'de', false]);
  /** @param {string} name @param {string} content */
  const dirWith = (name, content) => {
    const dir = mkdtempSync(join(tmpdir(), 'vanishly-tr-'));
    writeFileSync(join(dir, name), content);
    return dir;
  };
  assert.throws(() => loadTranslations(dirWith('sv.json', '{ broken')), /sv\.json: /);
  assert.throws(() => loadTranslations(dirWith('sv.json', '{"a": 1}')), /JSON object of texts/);
  assert.throws(() => loadTranslations(dirWith('sv.json', '["a"]')), /JSON object of texts/);
  assert.throws(() => loadTranslations(dirWith('French.json', '{}')), /language code/);
  assert.throws(() => loadTranslations(dirWith('sv.json', `{"a": "${'x'.repeat(600 * 1024)}"}`)), /plain file up to 512 KB/);
  const link = mkdtempSync(join(tmpdir(), 'vanishly-tr-'));
  symlinkSync(join(dirWith('x.json', '{}'), 'x.json'), join(link, 'sv.json'));
  assert.throws(() => loadTranslations(link), /plain file/);
  const sv = loadTranslations(dirWith('sv.json', '{"home.title": "Dela"}')).sv;
  assert.equal(sv['home.title'], 'Dela');
  assert.equal(sv['home.expires'], 'Expires after');
  assert.equal(sv.lang, 'sv');
  // TRANSLATIONS_DIR replaces single texts of a built-in language.
  assert.equal(loadTranslations(dirWith('fr.json', '{"home.title": "Partager"}')).fr['home.title'], 'Partager');
});

test('built-in translations: every key of en.json, with the same placeholders', () => {
  const read = (/** @type {string} */ f) => JSON.parse(readFileSync(`translations/${f}`, 'utf8'));
  const en = read('en.json');
  const ph = (/** @type {string} */ s) => (s.match(/\{\w+\}/g) || []).sort().join();
  for (const f of readdirSync('translations')) {
    const file = read(f);
    assert.equal(file.lang, f.slice(0, -5), f);
    for (const k of Object.keys(en)) {
      assert.ok(k in file, `${f}: ${k} is missing`);
      assert.equal(ph(file[k]), ph(en[k]), `${f}: ${k} placeholders`);
    }
  }
});

test('SITE_NAME replaces the name in the header and the title; more than two languages: a menu', () => {
  const base = { template: 'default', templatesDir: '/nonexistent' };
  const html = loadTheme({ ...base, siteName: 'ACME <Secrets>' }, '1').page('error', 'fr', { page: 'error', title: 'Erreur' });
  assert.match(html, /<title>Erreur - ACME &lt;Secrets&gt;<\/title>/);
  assert.match(html, /<span class="brand-name">ACME &lt;Secrets&gt;<\/span>/);
  assert.match(html, /<details class="nav-menu lang-switch lang-menu">/);
  assert.match(html, /<a class="nav-menu-item" href="\?lang=de" hreflang="de" lang="de">Deutsch<\/a>/);
  assert.ok(!html.includes('href="?lang=fr"'), 'the current language is not offered');
  assert.match(loadTheme(base, '1').page('error', 'en', { page: 'error' }), /<title>Vanishly<\/title>/);
  const two = loadTheme({ ...base, languages: ['en', 'de'] }, '1').page('error', 'de', { page: 'error' });
  assert.match(two, /<a class="lang-switch" href="\?lang=en" hreflang="en" lang="en">English<\/a>/);
});
