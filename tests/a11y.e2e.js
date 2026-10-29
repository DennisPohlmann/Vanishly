// Accessibility check (WCAG 2.2 AA via axe-core) of every page and state, in
// each built-in template, light and dark, desktop and phone (320 px).
// Needs Redis (REDIS_URL or redis-server) and Chromium: npx playwright install chromium
// Run: npm run test:a11y
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { after, before, test } from 'node:test';
import { chromium } from 'playwright';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { loadTheme } from '../src/theme.js';
import { startMock } from './oidc-mock.js';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'];
// A11Y_TEMPLATES=name,name (with TEMPLATES_DIR) checks own templates instead.
const TEMPLATES = process.env.A11Y_TEMPLATES ? process.env.A11Y_TEMPLATES.split(',') : ['default', 'aurora', 'example-brand'];

/** @type {any} */ let redisProc;
/** @type {import('playwright').Browser} */ let browser;
let redisUrl = process.env.REDIS_URL || '';

before(async () => {
  if (!redisUrl) {
    assert.equal(spawnSync('redis-server', ['--version']).status, 0, 'needs REDIS_URL or redis-server');
    const port = 20000 + Math.floor(Math.random() * 20000);
    redisProc = spawn('redis-server', ['--port', String(port), '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
    redisUrl = `redis://127.0.0.1:${port}`;
    await new Promise((r) => setTimeout(r, 300));
  }
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  redisProc?.kill();
});

/**
 * Runs axe on the page and returns readable violations.
 * @param {import('playwright').Page} page
 * @param {string} where
 */
async function scan(page, where) {
  await page.addScriptTag({ content: AXE });
  const result = await page.evaluate(
    (tags) => /** @type {any} */ (window).axe.run(document, { runOnly: { type: 'tag', values: tags } }),
    TAGS,
  );
  // WCAG 1.4.10 reflow: no sideways scrolling, also at 320 px
  const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  /** @type {string[]} */
  const extra = wide ? [`${where}: reflow: the page scrolls sideways`] : [];
  return extra.concat(result.violations.map(
    (/** @type {any} */ v) => `${where}: ${v.id} (${v.impact}) ${v.help}: ${v.nodes.map((/** @type {any} */ n) => n.target.join(' ')).join(', ')}`,
  ));
}

for (const template of TEMPLATES) {
  test(`WCAG 2.2 AA: template ${template}`, async () => {
    const config = loadConfig({
      REDIS_URL: redisUrl,
      REDIS_PREFIX: `a11y${process.pid}${template}:`,
      TEMPLATE: template,
      ...(process.env.TEMPLATES_DIR ? { TEMPLATES_DIR: process.env.TEMPLATES_DIR } : {}),
      CONFIRM_CHECKBOX: 'true',
      MIN_PASSPHRASE_LENGTH: '8',
      PASSPHRASE_COMPLEXITY: 'upper,digit',
      RATE_LIMIT_CREATE: '1000',
      RATE_LIMIT_READ: '1000',
      ACCESS_LOG: 'false',
    });
    const store = await Store.connect(redisUrl, config);
    const srv = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' }).listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const base = `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`;
    /** @type {string[]} */
    const problems = [];
    try {
      for (const mode of ['light', 'dark']) {
        for (const [device, viewport] of /** @type {const} */ ([['desktop', { width: 1280, height: 900 }], ['phone', { width: 320, height: 640 }]])) {
          // bypassCSP: only so the test can inject axe-core; the app's CSP stays as it is.
          const ctx = await browser.newContext({ viewport, colorScheme: /** @type {any} */ (mode), bypassCSP: true });
          await ctx.addInitScript((m) => localStorage.setItem('vanishly-mode', m), mode);
          const page = await ctx.newPage();
          const at = (/** @type {string} */ s) => `${template}/${mode}/${device}/${s}`;
          await page.goto(`${base}/`);
          problems.push(...(await scan(page, at('home'))));
          // keyboard: the first Tab reaches the skip link, Enter moves to the content
          await page.keyboard.press('Tab');
          if (!(await page.evaluate(() => document.activeElement?.classList.contains('skip-link')))) {
            problems.push(`${at('home')}: keyboard: the first Tab does not reach the skip link`);
          }
          // error state: weak passphrase, box not ticked
          await page.fill('#secret', 'correct horse battery staple');
          await page.fill('#passphrase', 'weak');
          await page.click('#create-submit');
          await page.waitForSelector('#create-error:not([hidden])');
          problems.push(...(await scan(page, at('home-error'))));
          if ((await page.evaluate(() => document.activeElement?.id)) !== 'passphrase') {
            problems.push(`${at('home-error')}: focus is not on the field with the error`);
          }
          await page.fill('#passphrase', 'Sunflower42');
          await page.check('#confirm');
          await page.click('#create-submit');
          await page.waitForFunction(() => !document.getElementById('created-card')?.hidden);
          problems.push(...(await scan(page, at('created'))));
          const link = await page.inputValue('#share-link');
          const receipt = await page.inputValue('#receipt-link');
          await page.goto(link);
          problems.push(...(await scan(page, at('secret'))));
          await page.fill('#reveal-passphrase', 'wrong');
          await page.click('#reveal-submit');
          await page.waitForSelector('#reveal-error:not([hidden])');
          problems.push(...(await scan(page, at('secret-error'))));
          await page.fill('#reveal-passphrase', 'Sunflower42');
          await page.click('#reveal-submit');
          await page.waitForFunction(() => !document.getElementById('revealed')?.hidden);
          problems.push(...(await scan(page, at('revealed'))));
          await page.goto(receipt);
          await page.waitForFunction(() => !document.getElementById('receipt-facts')?.hidden);
          problems.push(...(await scan(page, at('receipt'))));
          await page.goto(`${base}/s/${'a'.repeat(22)}`);
          problems.push(...(await scan(page, at('gone'))));
          await page.goto(`${base}/nope`);
          problems.push(...(await scan(page, at('404'))));
          await ctx.close();
        }
      }
    } finally {
      srv.close();
      await store.close();
    }
    for (const p of problems) console.log(`a11y: ${p}`);
    assert.equal(problems.length, 0, `${problems.length} accessibility problems, see the a11y: lines`);
  });
}

// Sign-in (AUTH_PROVIDER=entra, the provider stand-in): the whole browser
// flow, including the key kept across the sign-in, and its pages.
test('WCAG 2.2 AA and flow: sign-in and recipients', async () => {
  const TENANT = '11111111-2222-3333-4444-555555555555';
  const CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const IT = '0f0f0f0f-1111-2222-3333-444444444444';
  const mock = await startMock({ tenant: TENANT, clientId: CLIENT, clientSecret: 'test-secret' });
  /** @type {any} */ let handler = null;
  const { createServer } = await import('node:http');
  const srv = createServer((req, res) => handler(req, res));
  await new Promise((r) => srv.listen(0, '127.0.0.1', () => r(undefined)));
  const base = `http://127.0.0.1:${/** @type {any} */ (srv.address()).port}`;
  const config = loadConfig({
    REDIS_URL: redisUrl,
    REDIS_PREFIX: `a11yauth${process.pid}:`,
    RATE_LIMIT_CREATE: '1000',
    RATE_LIMIT_READ: '1000',
    ACCESS_LOG: 'false',
    BASE_URL: base,
    AUTH_PROVIDER: 'entra',
    ENTRA_TENANT_ID: TENANT,
    ENTRA_CLIENT_ID: CLIENT,
    ENTRA_CLIENT_SECRET: 'test-secret',
    ENTRA_AUTHORITY: mock.base,
    AUTH_SECRET: 'x'.repeat(40),
    ENTRA_GRAPH: 'true',
    ENTRA_GRAPH_URL: mock.base,
    RECIPIENT_GROUPS: `IT Admins=${IT}`,
    RECIPIENT_USER_GROUP: IT,
    RECEIPT_SHOW_VIEWER: 'true',
    REQUIRE_PASSPHRASE: 'unless-recipients',
    RESPONSIBLE: 'optional',
  });
  const store = await Store.connect(redisUrl, config);
  handler = createApp({ config, store, theme: loadTheme(config, 'test'), version: 'test' });
  const alice = { oid: '00000000-0000-0000-0000-00000000000a', tid: TENANT, name: 'Alice Example', preferred_username: 'alice@example.com' };
  const bob = { oid: '00000000-0000-0000-0000-00000000000b', tid: TENANT, name: 'Bob Example', preferred_username: 'bob@example.com' };
  mock.members[IT] = [
    { displayName: 'Bob Example', mail: 'bob@example.com', userPrincipalName: 'bob@example.com' },
    { displayName: 'Bonnie Example', mail: 'bonnie@example.com', userPrincipalName: 'bonnie@example.com' },
  ];
  /** @type {string[]} */
  const problems = [];
  try {
    for (const mode of ['light', 'dark']) {
      for (const [device, viewport] of /** @type {const} */ ([['desktop', { width: 1280, height: 900 }], ['phone', { width: 320, height: 640 }]])) {
        const ctx = await browser.newContext({ viewport, colorScheme: /** @type {any} */ (mode), bypassCSP: true });
        await ctx.addInitScript((m) => localStorage.setItem('vanishly-mode', m), mode);
        const page = await ctx.newPage();
        const at = (/** @type {string} */ s) => `auth/${mode}/${device}/${s}`;
        await page.goto(`${base}/`);
        problems.push(...(await scan(page, at('login'))));
        mock.user = alice;
        await page.click('#login-card [data-login]');
        await page.waitForSelector('#create-form');
        await page.fill('#secret', 'only for bob');
        // REQUIRE_PASSPHRASE=unless-recipients: required until a recipient is chosen.
        assert.equal(await page.getAttribute('#passphrase', 'aria-required'), 'true');
        assert.match((await page.textContent('#passphrase-label')) || '', /required/);
        await page.fill('#recipient-email', 'not-an-address');
        await page.click('#recipient-add');
        await page.waitForSelector('#create-error:not([hidden])');
        problems.push(...(await scan(page, at('home-recipient-error'))));
        // People search: type, pick with the arrow keys and Enter.
        await page.fill('#recipient-email', 'bo');
        await page.waitForSelector('#people-results:not([hidden]) [role="option"]');
        assert.equal(await page.getAttribute('#recipient-email', 'aria-expanded'), 'true');
        await page.keyboard.press('ArrowDown');
        assert.equal(await page.getAttribute('#recipient-email', 'aria-activedescendant'), 'people-opt-0');
        problems.push(...(await scan(page, at('home-people-search'))));
        await page.keyboard.press('Enter');
        assert.equal(await page.isHidden('#people-results'), true);
        assert.equal(await page.getAttribute('#passphrase', 'aria-required'), null);
        assert.match((await page.textContent('#passphrase-label')) || '', /optional/);
        assert.match((await page.textContent('#recipient-list')) || '', /Bob Example/);
        await page.selectOption('#recipient-group', IT);
        await page.click('#recipient-group-add');
        assert.equal(await page.locator('#recipient-list li').count(), 2);
        problems.push(...(await scan(page, at('home-recipients'))));
        // RESPONSIBLE: the folded section with its own picker.
        await page.click('.responsible-box > summary');
        await page.selectOption('#responsible-group', IT);
        await page.click('#responsible-group-add');
        assert.equal(await page.locator('#responsible-list li').count(), 1);
        problems.push(...(await scan(page, at('home-responsible'))));
        await page.click('#create-submit');
        await page.waitForFunction(() => !document.getElementById('created-card')?.hidden);
        assert.equal(await page.isVisible('#created-restricted'), true);
        problems.push(...(await scan(page, at('created'))));
        const link = await page.inputValue('#share-link');
        const receipt = await page.inputValue('#receipt-link');
        // Alice is signed in but not a recipient.
        await page.goto(link);
        await page.waitForSelector('#locked:not([hidden])');
        assert.equal(await page.isVisible('#locked-switch'), true);
        problems.push(...(await scan(page, at('secret-denied'))));
        // "Another account": out, in as Bob, back on the secret with its key.
        mock.user = bob;
        await page.click('#locked-switch button');
        await page.waitForURL(/\/s\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);
        assert.equal(await page.evaluate(() => sessionStorage.length), 0);
        await page.click('#reveal-submit');
        await page.waitForFunction(() => !document.getElementById('revealed')?.hidden);
        assert.equal(await page.inputValue('#revealed-secret'), 'only for bob');
        await page.goto(receipt);
        await page.waitForFunction(() => !document.getElementById('receipt-facts')?.hidden);
        assert.match(await page.textContent('#r-log') || '', /Bob Example/);
        assert.match(await page.textContent('#r-timeline') || '', /Opened/);
        problems.push(...(await scan(page, at('receipt'))));
        // Not signed in: the sign-in prompt on a restricted secret.
        await page.click('.nav-logout button');
        await page.waitForURL(`${base}/`);
        // STATUS_ACCESS=signed-in: the status page asks for a sign-in.
        await page.goto(receipt);
        await page.waitForSelector('#r-locked:not([hidden])');
        problems.push(...(await scan(page, at('receipt-login'))));
        await page.goto(`${base}/`);
        mock.user = alice;
        await page.click('#login-card [data-login]');
        await page.waitForSelector('#create-form');
        await page.fill('#secret', 'second');
        await page.fill('#recipient-email', 'bob@example.com');
        await page.click('#create-submit');
        await page.waitForFunction(() => !document.getElementById('created-card')?.hidden);
        const link2 = await page.inputValue('#share-link');
        await page.click('.nav-logout button');
        await page.waitForURL(`${base}/`);
        await page.goto(link2);
        await page.waitForSelector('#locked-login:not([hidden])');
        problems.push(...(await scan(page, at('secret-login'))));
        mock.user = bob;
        await page.click('#locked-login');
        await page.waitForURL(/#[A-Za-z0-9_-]{43}$/);
        await page.click('#reveal-submit');
        await page.waitForFunction(() => !document.getElementById('revealed')?.hidden);
        assert.equal(await page.inputValue('#revealed-secret'), 'second');
        await ctx.close();
      }
    }
  } finally {
    srv.close();
    await store.close();
    await mock.close();
  }
  for (const p of problems) console.log(`a11y: ${p}`);
  assert.equal(problems.length, 0, `${problems.length} accessibility problems, see the a11y: lines`);
});
