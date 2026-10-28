// Vanishly - browser side: encrypts before sending, decrypts after the
// reveal. The key only lives in the URL fragment (#...), which the browser
// never sends to the server.

import { decryptSecret, encryptSecret, unlockKey, verifierFor } from './vanishly-crypto.js';
import { missingClasses } from './rules.js';

/** @type {Record<string, string>} */
const T = JSON.parse(document.getElementById('i18n')?.textContent || '{}');
/** @param {string} k @param {Record<string, string | number>} [vars] */
const t = (k, vars = {}) => (T[k] || k).replace(/\{(\w+)\}/g, (_, v) => String(vars[v] ?? ''));
/** @param {string} id */
const $ = (id) => /** @type {any} */ (document.getElementById(id));
const lang = document.documentElement.lang || 'en';
/** @param {string} name a switched-off feature, see the body classes */
const off = (name) => document.body.classList.contains(`no-${name}`);
/** @param {string | number} d */
const fmt = (d) => new Date(d).toLocaleString(lang, { dateStyle: 'medium', timeStyle: 'short' });

/**
 * Shows (or clears) an error. The element has role="alert", so screen readers
 * read it out; the field it is about gets aria-invalid and the focus.
 * @param {HTMLElement} el
 * @param {string} text
 * @param {HTMLElement | null} [field]
 */
function showError(el, text, field = null) {
  el.hidden = !text;
  el.textContent = text;
  if (!text) {
    for (const f of document.querySelectorAll('[aria-invalid]')) f.removeAttribute('aria-invalid');
  } else if (field) {
    field.setAttribute('aria-invalid', 'true');
    field.setAttribute('aria-errormessage', el.id);
    field.focus();
  }
}

/** Tells screen readers about a change that has no visible message (e.g. "Copied"). @param {string} text */
function announce(text) {
  const s = $('sr-status');
  if (!s) return;
  s.textContent = '';
  setTimeout(() => (s.textContent = text), 50);
}

/**
 * @param {string} url
 * @param {any} [body]
 */
async function api(url, body) {
  const res = await fetch(url, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data: /** @type {any} */ (data) };
}

/** @param {number} status */
function errorText(status) {
  if (status === 429) return t('error.ratelimit');
  if (status === 413) return t('error.tooLong');
  return t('error.generic');
}

// Light/dark switch, remembered in localStorage. aria-pressed = dark mode on.
const modeToggle = $('mode-toggle');
modeToggle?.setAttribute('aria-pressed', String(document.documentElement.getAttribute('data-theme') === 'dark'));
modeToggle?.addEventListener('click', () => {
  const root = document.documentElement;
  const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  modeToggle.setAttribute('aria-pressed', String(next === 'dark'));
  try {
    localStorage.setItem('vanishly-mode', next);
  } catch {}
});

// Copy buttons: data-copy="<id of the input or textarea>".
document.addEventListener('click', async (e) => {
  const btn = /** @type {HTMLElement | null} */ (/** @type {HTMLElement} */ (e.target).closest('[data-copy]'));
  if (!btn) return;
  const field = $(btn.dataset.copy || '');
  if (!field) return;
  try {
    await navigator.clipboard.writeText(field.value);
  } catch {
    field.select();
    document.execCommand('copy');
  }
  const old = btn.textContent;
  btn.textContent = t('created.copied');
  announce(t('a11y.copied'));
  setTimeout(() => (btn.textContent = old), 1500);
});

/** Character sets of the generator, without look-alikes (0/O, 1/l/I). */
const GEN_SETS = /** @type {Record<string, string>} */ ({
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lower: 'abcdefghijkmnopqrstuvwxyz',
  digit: '23456789',
  symbol: '-_!?%+=#',
});

/** Uniform random index below n, from crypto.getRandomValues (no modulo bias). @param {number} n */
function randomIndex(n) {
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < Math.floor(0x100000000 / n) * n) return buf[0] % n;
  }
}

/**
 * Random password with at least one character of every chosen set
 * (GENERATOR_LENGTH, GENERATOR_COMPLEXITY).
 * @param {number} length
 * @param {string[]} sets
 */
function generatePassword(length, sets) {
  const use = sets.filter((s) => GEN_SETS[s]);
  if (!use.length) use.push(...Object.keys(GEN_SETS));
  const all = use.map((s) => GEN_SETS[s]).join('');
  for (;;) {
    const out = Array.from({ length }, () => all[randomIndex(all.length)]);
    // Retry until every set appears: still uniform over the valid passwords.
    if (use.every((s) => out.some((c) => GEN_SETS[s].includes(c)))) return out.join('');
  }
}

// Before a sign-in from a secret page, the key (after #) is kept in this
// tab's sessionStorage: the redirect to the sign-in provider and back loses
// the fragment. It never goes to the server and is removed when the page
// comes back. Only this tab and this origin can read it.
/** @param {string} id */
const keySlot = (id) => `vanishly-key:${id}`;
document.addEventListener('click', (e) => remember(/** @type {HTMLElement} */ (e.target).closest('a[data-login]')));
document.addEventListener('submit', (e) => remember(/** @type {HTMLElement} */ (e.target).closest('form[data-login]')));
/** @param {Element | null} el */
function remember(el) {
  const id = $('reveal-card')?.dataset.id;
  const key = location.hash.slice(1);
  if (!el || !id || !/^[A-Za-z0-9_-]{43}$/.test(key)) return;
  try {
    sessionStorage.setItem(keySlot(id), key);
  } catch {}
}

/**
 * The "Only for" field: e-mail addresses and groups as a list of chips.
 * @returns {{ users: () => string[], groups: () => string[], flush: () => string, clear: () => void } | null}
 */
/**
 * RECIPIENT_USER_GROUP: the address field also searches people (ARIA
 * combobox with a listbox of suggestions from /api/v1/people).
 * @param {HTMLInputElement} input
 * @param {(kind: 'user' | 'group', id: string, name: string) => boolean} add
 * @param {() => void} clearError
 */
function initPeople(input, add, clearError) {
  const box = $('people-results');
  const status = $('people-status');
  /** @type {{ name: string, user: string, mail: string }[]} */
  let found = [];
  let active = -1;
  /** @type {any} */ let timer;
  const close = () => {
    found = [];
    active = -1;
    box.hidden = true;
    box.replaceChildren();
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
  };
  /** @param {number} i */
  const mark = (i) => {
    active = i;
    [...box.children].forEach((li, n) => li.setAttribute('aria-selected', n === i ? 'true' : 'false'));
    if (i < 0) return input.removeAttribute('aria-activedescendant');
    input.setAttribute('aria-activedescendant', `people-opt-${i}`);
    box.children[i]?.scrollIntoView({ block: 'nearest' });
  };
  /** @param {number} i */
  const pick = (i) => {
    const p = found[i];
    if (!p) return;
    clearError();
    if (add('user', p.user, p.name)) {
      input.value = '';
      status.textContent = '';
      close();
    }
    input.focus();
  };
  /** @param {string} state @param {string} text */
  const say = (state, text) => {
    status.dataset.state = state;
    status.textContent = text;
  };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const q = input.value.trim();
    if (q.length < 2 || /@.*\./.test(q)) {
      say('', '');
      return close();
    }
    timer = setTimeout(async () => {
      say('loading', '');
      const { status: code, data } = await api(`/api/v1/people?q=${encodeURIComponent(q)}`);
      if (input.value.trim() !== q) return;
      close();
      if (code !== 200) return say('error', errorText(code));
      found = data.people;
      if (!found.length) return say('empty', t('home.peopleNone'));
      box.replaceChildren(
        ...found.map((p, i) => {
          const li = document.createElement('li');
          li.id = `people-opt-${i}`;
          li.className = 'suggestion';
          li.setAttribute('role', 'option');
          li.setAttribute('aria-selected', 'false');
          const name = document.createElement('span');
          name.className = 'suggestion-name';
          name.textContent = p.name;
          const detail = document.createElement('span');
          detail.className = 'suggestion-detail';
          detail.textContent = p.user;
          li.append(name, detail);
          // mousedown, not click: the field keeps the focus.
          li.addEventListener('mousedown', (e) => {
            e.preventDefault();
            pick(i);
          });
          return li;
        }),
      );
      box.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      say('results', t('home.peopleCount', { n: found.length }));
    }, 250);
  });
  input.addEventListener('blur', () => setTimeout(close, 150));
  return {
    /** Arrow keys, Enter and Escape while suggestions are open; true = handled. @param {KeyboardEvent} e */
    key(e) {
      if (box.hidden || !found.length) return false;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const n = found.length;
        mark(e.key === 'ArrowDown' ? (active + 1) % n : (active - 1 + n) % n);
        return true;
      }
      if (e.key === 'Enter' && active >= 0) {
        e.preventDefault();
        pick(active);
        return true;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
        return true;
      }
      return false;
    },
  };
}

function initRecipients() {
  const wrap = $('recipients-wrap');
  if (!wrap) return null;
  const list = $('recipient-list');
  const email = $('recipient-email');
  const err = $('create-error');
  const max = Number(wrap.dataset.max || 10);
  /** @type {{ kind: 'user' | 'group', id: string, name: string }[]} */
  let items = [];
  const draw = () => {
    list.replaceChildren(
      ...items.map((it, i) => {
        const li = document.createElement('li');
        li.className = `chip chip-${it.kind}`;
        const label = document.createElement('span');
        label.textContent = it.name;
        if (it.kind === 'user' && it.name !== it.id) {
          const detail = document.createElement('span');
          detail.className = 'chip-detail';
          detail.textContent = it.id;
          label.append(' ', detail);
        }
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'chip-remove';
        btn.textContent = '\u00d7';
        btn.setAttribute('aria-label', t('home.recipientRemove', { name: it.name }));
        btn.addEventListener('click', () => {
          items.splice(i, 1);
          draw();
          announce(t('home.recipientRemove', { name: it.name }));
          email.focus();
        });
        li.append(label, btn);
        return li;
      }),
    );
    // REQUIRE_PASSPHRASE=unless-recipients: the form follows the list.
    wrap.dispatchEvent(new CustomEvent('recipients-change', { detail: items.length }));
  };
  /** @param {'user' | 'group'} kind @param {string} id @param {string} name */
  const add = (kind, id, name) => {
    if (items.some((it) => it.kind === kind && it.id === id)) return true;
    if (items.length >= max) {
      showError(err, t('error.recipientsMax', { n: max }), email);
      return false;
    }
    items.push({ kind, id, name });
    draw();
    announce(name);
    return true;
  };
  // Returns an error text, or '' when the field is empty or was added.
  const flush = () => {
    const v = email.value.trim().toLowerCase();
    if (!v) return '';
    if (!/^[^\s@<>"',;]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v)) return t('error.recipientInvalid', { name: v });
    if (!add('user', v, v)) return t('error.recipientsMax', { n: max });
    email.value = '';
    return '';
  };
  const addEmail = () => {
    showError(err, '');
    const e = flush();
    if (e) showError(err, e, email);
    email.focus();
  };
  $('recipient-add').addEventListener('click', addEmail);
  const people = wrap.dataset.people === '1' ? initPeople(email, add, () => showError(err, '')) : null;
  email.addEventListener('keydown', (/** @type {KeyboardEvent} */ e) => {
    if (people?.key(e)) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      addEmail();
    }
  });
  const groupSelect = $('recipient-group');
  $('recipient-group-add')?.addEventListener('click', () => {
    const o = groupSelect.selectedOptions[0];
    if (o?.value) add('group', o.value, o.textContent || o.value);
    groupSelect.value = '';
  });
  const search = $('group-search');
  if (search) {
    const results = $('group-results');
    /** @type {any} */ let timer;
    search.addEventListener('input', () => {
      clearTimeout(timer);
      const q = search.value.trim();
      if (q.length < 2) return results.replaceChildren();
      timer = setTimeout(async () => {
        const { status, data } = await api(`/api/v1/groups?q=${encodeURIComponent(q)}`);
        if (search.value.trim() !== q) return;
        const groups = status === 200 ? data.groups : [];
        results.replaceChildren(
          ...(groups.length ? groups : [null]).map((/** @type {{ id: string, name: string } | null} */ g) => {
            const li = document.createElement('li');
            if (!g) {
              li.textContent = status === 200 ? t('home.groupNone') : errorText(status);
              return li;
            }
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'btn btn-small btn-ghost';
            b.textContent = `${t('home.recipientAdd')}: ${g.name}`;
            b.addEventListener('click', () => {
              if (add('group', g.id, g.name)) {
                search.value = '';
                results.replaceChildren();
                search.focus();
              }
            });
            li.append(b);
            return li;
          }),
        );
        announce(groups.length ? `${groups.length}` : t('home.groupNone'));
      }, 250);
    });
  }
  return {
    users: () => items.filter((it) => it.kind === 'user').map((it) => it.id),
    groups: () => items.filter((it) => it.kind === 'group').map((it) => it.id),
    flush,
    clear: () => {
      items = [];
      draw();
    },
  };
}

function initHome() {
  const form = $('create-form');
  const recipients = initRecipients();
  const secret = $('secret');
  const count = $('char-count');
  const err = $('create-error');
  // Passphrase required: always ('1'), or while no recipient is chosen
  // ('unless-recipients'); label and aria-required follow.
  const passLabel = $('passphrase-label');
  let passRequired = form.dataset.passRequired === '1';
  const setPassRequired = (/** @type {boolean} */ on) => {
    passRequired = on;
    if (on) $('passphrase').setAttribute('aria-required', 'true');
    else $('passphrase').removeAttribute('aria-required');
    if (passLabel?.dataset.required) passLabel.textContent = on ? passLabel.dataset.required : passLabel.dataset.optional || '';
  };
  if (form.dataset.passRequired === 'unless-recipients') {
    setPassRequired(true);
    $('recipients-wrap')?.addEventListener('recipients-change', (/** @type {any} */ ev) => setPassRequired(!ev.detail));
  } else if (passRequired) setPassRequired(true);
  const update = () => (count.textContent = String(secret.value.length));
  secret.addEventListener('input', update);
  $('generate').addEventListener('click', () => {
    const gen = /** @type {HTMLElement} */ ($('generate'));
    secret.value = generatePassword(Number(gen.dataset.length || 20), (gen.dataset.sets || '').split(',').filter(Boolean));
    update();
    secret.focus();
  });
  form.addEventListener('submit', async (/** @type {Event} */ e) => {
    e.preventDefault();
    showError(err, '');
    const passField = $('passphrase');
    if (!secret.value) return showError(err, t('error.empty'), secret);
    const minChars = Number(form.dataset.minChars || 1);
    const minPass = Number(form.dataset.minPass || 0);
    const pass = off('passphrase') ? '' : $('passphrase').value;
    if (secret.value.length < minChars) return showError(err, t('error.tooShort', { n: minChars }), secret);
    // Recipients first: an address typed but not yet added counts (and so
    // decides REQUIRE_PASSPHRASE=unless-recipients).
    if (recipients) {
      const e = recipients.flush();
      if (e) return showError(err, e, $('recipient-email'));
      if ($('recipients-wrap').dataset.required === '1' && !recipients.users().length && !recipients.groups().length) {
        return showError(err, t('error.recipientsRequired'), $('recipient-email'));
      }
    }
    if (passRequired && !pass) {
      return showError(err, t(form.dataset.passRequired === 'unless-recipients' ? 'error.passRequiredNoRecipients' : 'error.passRequired'), passField);
    }
    if (pass && pass.length < minPass) return showError(err, t('error.passTooShort', { n: minPass }), passField);
    const missing = pass ? missingClasses(pass, (form.dataset.passClasses || '').split(',').filter(Boolean)) : [];
    if (missing.length) {
      return showError(err, t('error.passWeak', { list: missing.map((c) => t(`rule.${c}`)).join(', ') }), passField);
    }
    const confirmBox = $('confirm');
    if (confirmBox && !confirmBox.checked) return showError(err, t('error.confirm'), confirmBox);
    const submit = $('create-submit');
    submit.disabled = true;
    try {
      const { key, payload } = await encryptSecret(secret.value, pass);
      const { status, data } = await api('/api/v1/secrets', {
        ...payload,
        ttl: Number($('ttl').value),
        views: off('views') ? 1 : Number($('views').value),
        ...(confirmBox ? { confirmed: true } : {}),
        ...(recipients ? { recipients: recipients.users(), recipientGroups: recipients.groups() } : {}),
      });
      if (status !== 201) {
        if (status === 401) return showError(err, t('error.loginRequired'));
        if (data.error === 'invalid_recipient') return showError(err, t('error.recipientInvalid', { name: data.recipient }), $('recipient-email'));
        if (data.error === 'recipient_domain') return showError(err, t('error.recipientDomain', { list: data.domains.join(', ') }), $('recipient-email'));
        if (data.error === 'recipients_required') return showError(err, t('error.recipientsRequired'), $('recipient-email'));
        if (data.error === 'too_many_recipients') return showError(err, t('error.recipientsMax', { n: data.max }), $('recipient-email'));
        if (data.error === 'too_short') return showError(err, t('error.tooShort', { n: minChars }), secret);
        if (data.error === 'confirmation_required') return showError(err, t('error.confirm'), confirmBox);
        if (data.error === 'passphrase_required') {
          return showError(err, t(form.dataset.passRequired === 'unless-recipients' ? 'error.passRequiredNoRecipients' : 'error.passRequired'), passField);
        }
        return showError(err, errorText(status));
      }
      const origin = location.origin;
      $('share-link').value = `${origin}${data.secretPath}#${key}`;
      // The receipt link carries the key too, so the sender can copy the
      // share link again later. Only the sender should have it.
      if (data.receiptPath) $('receipt-link').value = `${origin}${data.receiptPath}${off('receipt-key') ? '' : `#${key}`}`;
      // Templates with an own home.html may lack the wrapper.
      const receiptWrap = $('receipt-wrap') || $('receipt-link')?.closest('.copy-row');
      if (receiptWrap) receiptWrap.hidden = !data.receiptPath;
      // One view (the default) needs no counter.
      $('created-info').textContent =
        `${t('created.expires')}: ${fmt(data.expires)}` + (data.views > 1 ? ` · ${t('views.n', { n: data.views })}` : '');
      const restricted = $('created-restricted');
      if (restricted) restricted.hidden = !data.restricted;
      recipients?.clear();
      secret.value = '';
      if (confirmBox) confirmBox.checked = false;
      $('passphrase').value = '';
      $('create-card').hidden = true;
      $('created-card').hidden = false;
      // Focus on the link field: screen readers read its label, keyboard users can copy at once.
      $('share-link').focus();
      $('share-link').select();
      announce(t('a11y.created'));
    } catch {
      showError(err, t('error.generic'));
    } finally {
      submit.disabled = false;
    }
  });
}

function initSecret() {
  const card = $('reveal-card');
  const id = card.dataset.id;
  const needsPass = card.dataset.passphrase === '1';
  // Back from the sign-in: the key was kept in sessionStorage (see remember()).
  try {
    const kept = sessionStorage.getItem(keySlot(id));
    if (kept) {
      sessionStorage.removeItem(keySlot(id));
      if (!location.hash) history.replaceState(null, '', `${location.pathname}#${kept}`);
    }
  } catch {}
  const key = location.hash.slice(1);
  const err = $('reveal-error');
  const submit = $('reveal-submit');
  const locked = card.dataset.locked || '';
  if (locked) {
    // Not signed in, or not a recipient: no reveal form, no view used.
    $('reveal-form').hidden = true;
    $('locked').hidden = false;
    $('locked-login').hidden = locked !== 'login';
    $('locked-switch').hidden = locked !== 'denied';
    return;
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) {
    showError(err, t('reveal.nokey'));
    submit.disabled = true;
    return;
  }
  if (needsPass) $('passphrase-field').hidden = false;
  // The reveal needs a click, so link previews in chat apps do not burn it.
  $('reveal-form').addEventListener('submit', async (/** @type {Event} */ e) => {
    e.preventDefault();
    showError(err, '');
    submit.disabled = true;
    const label = submit.textContent;
    submit.textContent = t('reveal.working');
    try {
      /** @type {Uint8Array | undefined} */
      let pk;
      /** @type {Record<string, string>} */
      const body = {};
      if (needsPass) {
        // Salt and iterations come with the page; a view of an own template
        // without them falls back to GET /v1/secrets/{id}.
        let params = card.dataset.salt ? { salt: card.dataset.salt, iterations: Number(card.dataset.iterations) } : null;
        if (!params) {
          const meta = await api(`/api/v1/secrets/${id}`);
          if (meta.status !== 200) return gone(meta.status);
          params = meta.data;
        }
        pk = await unlockKey($('reveal-passphrase').value, params);
        body.verifier = await verifierFor(pk, params);
      }
      const { status, data } = await api(`/api/v1/secrets/${id}/reveal`, body);
      if (status === 401 || data.error === 'not_recipient') {
        $('reveal-form').hidden = true;
        return showError(err, status === 401 ? t('reveal.lockedLogin') : t('reveal.notRecipient'));
      }
      if (status === 403) return showError(err, t('reveal.badpass', { n: data.attemptsLeft }), $('reveal-passphrase'));
      if (status === 410) {
        $('reveal-form').hidden = true;
        return showError(err, t('reveal.burnedByAttempts'));
      }
      if (status !== 200) return gone(status);
      let text;
      try {
        text = await decryptSecret(data, key, pk);
      } catch {
        $('reveal-form').hidden = true;
        return showError(err, t('reveal.badkey'));
      }
      // Drop the key from the address bar and the history entry.
      history.replaceState(null, '', location.pathname);
      $('reveal-form').hidden = true;
      $('revealed').hidden = false;
      $('revealed-secret').value = text;
      $('revealed-secret').focus();
      $('revealed-info').textContent = data.viewsLeft > 0 ? t('reveal.doneLeft', { n: data.viewsLeft }) : t('reveal.done');
    } catch {
      showError(err, t('error.generic'));
    } finally {
      submit.disabled = false;
      submit.textContent = label;
    }
  });

  /** @param {number} status */
  function gone(status) {
    if (status === 404) {
      $('reveal-form').hidden = true;
      showError(err, `${t('gone.title')}. ${t('gone.text')}`);
    } else showError(err, errorText(status));
  }
}

async function initReceipt() {
  const card = $('receipt-card');
  const id = card.dataset.id;
  const key = location.hash.slice(1);
  const err = $('receipt-error');
  const load = async () => {
    const { status, data } = await api(`/api/v1/receipts/${id}`);
    if (status !== 200) {
      $('receipt-facts').hidden = true;
      $('burn').hidden = true;
      $('r-share').hidden = true;
      return showError(err, status === 404 ? t('receipt.notfound') : errorText(status));
    }
    showError(err, '');
    $('receipt-facts').hidden = false;
    const state = $('r-state');
    state.textContent = t(`receipt.state.${data.state}`);
    state.className = `badge badge-${data.state}`;
    $('r-created').textContent = fmt(data.created);
    $('r-expires').textContent = fmt(data.expires);
    $('r-views').textContent = `${data.viewsLeft} / ${data.maxViews}`;
    // One-view secrets: the state badge says it all, no "views left" row.
    for (const el of document.querySelectorAll('.r-views-row')) /** @type {HTMLElement} */ (el).hidden = data.maxViews === 1;
    $('r-pass').textContent = data.passphrase ? t('receipt.yes') : t('receipt.no');
    for (const el of document.querySelectorAll('.r-recipients-row')) /** @type {HTMLElement} */ (el).hidden = !data.recipients;
    if ($('r-recipients')) $('r-recipients').textContent = String(data.recipients || 0);
    const log = $('r-log');
    log.replaceChildren(
      ...(data.views.length ? data.views : [null]).map((/** @type {string | null} */ v, /** @type {number} */ i) => {
        const li = document.createElement('li');
        const by = data.viewedBy?.[i];
        li.textContent = v ? (by ? t('receipt.viewedBy', { time: fmt(v), name: by }) : fmt(v)) : t('receipt.none');
        return li;
      }),
    );
    const alive = data.state === 'new' || data.state === 'viewed';
    $('burn').hidden = !alive || off('burn');
    $('r-share').hidden = !(alive && data.secretPath && /^[A-Za-z0-9_-]{43}$/.test(key));
    if (!$('r-share').hidden) $('r-share-link').value = `${location.origin}${data.secretPath}#${key}`;
  };
  $('burn').addEventListener('click', async () => {
    if (!confirm(t('receipt.burnConfirm'))) return;
    const { status } = await api(`/api/v1/receipts/${id}/burn`, {});
    if (status !== 200 && status !== 409) showError(err, errorText(status));
    await load();
  });
  await load();
}

const page = document.body.dataset.page;
if (page === 'home') initHome();
else if (page === 'secret') initSecret();
else if (page === 'receipt') initReceipt();
