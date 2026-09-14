// Download page.
//
// The share key is in the URL; the password is not, and never goes into one.
// Unlocking exchanges the password for a session token held in memory only, so
// a reload asks again rather than leaving a reusable secret in storage.

'use strict';

const el = (id) => document.getElementById(id);

// i18n: strings come from window.I18N, served per language by /i18n.js.
const t = (k) => (window.I18N && window.I18N[k]) || k;
const tf = (k, params) => {
  let s = t(k);
  for (const [key, val] of Object.entries(params)) s = s.split('%' + key + '%').join(val);
  return s;
};
const LOCALE = window.LANG || 'ja';

const ui = {
  page: document.querySelector('.page'),
  checking: el('checking'),
  gone: el('gone'),
  locked: el('locked'),
  lockedMeta: el('locked-meta'),
  unlockForm: el('unlock-form'),
  unlockButton: el('unlock'),
  password: el('password'),
  unlocked: el('unlocked'),
  messageView: el('message-view'),
  messageText: el('message-text'),
  messageCopy: el('message-copy'),
  list: el('download-list'),
  downloadAll: el('download-all'),
  unlockedMeta: el('unlocked-meta'),
  deleteBox: el('delete-box'),
  deleteButton: el('delete-share'),
  deleted: el('deleted'),
  errorLine: el('error-line'),
};

const key = ui.page.dataset.key;
let sessionToken = null;
let dropKind = 'file';
// Object URLs created for previews, revoked when the page unloads.
const previewUrls = [];

// Capture and scrub the embed password from the URL fragment immediately, as the
// very first thing this script does — before any ad script on the page can run
// and read location.hash. The share key is not in the URL (the receive page is
// key-free), so once the fragment is gone the URL holds nothing sensitive.
const embeddedPassword = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';
if (location.hash) history.replaceState(null, document.title, location.pathname + location.search);

function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function showError(message) {
  ui.errorLine.textContent = message;
  ui.errorLine.hidden = false;
}

function clearError() {
  ui.errorLine.hidden = true;
  ui.errorLine.textContent = '';
}

function show(section) {
  for (const s of [ui.checking, ui.gone, ui.locked, ui.unlocked, ui.deleted]) {
    s.hidden = s !== section;
  }
}

// --- step 1: does the link resolve? ---------------------------------------

async function check() {
  try {
    const response = await fetch(`/api/drops/${encodeURIComponent(key)}`);
    if (!response.ok) {
      show(ui.gone);
      return;
    }
    const info = await response.json();
    dropKind = info.kind || 'file';
    const expires = new Date(info.expiresAt);
    ui.lockedMeta.textContent = tf('dl_locked_meta', {
      N: info.fileCount, SIZE: humanBytes(info.totalSize),
      EXPIRY: expires.toLocaleString(LOCALE), REMAINING: info.remaining,
    });

    // If the password rode in as a URL fragment (embed mode), it was captured
    // and scrubbed at load; unlock with it straight away.
    if (embeddedPassword) {
      await doUnlock(embeddedPassword, { silentFail: true });
      if (!ui.unlocked.hidden) return;
    }

    show(ui.locked);
    ui.password.focus();
  } catch {
    showError(t('dl_conn_retry'));
    show(ui.gone);
  }
}

// --- step 2: password ------------------------------------------------------

// doUnlock verifies a password and, on success, shows the file list. With
// silentFail set (auto-unlock from a fragment), a wrong password quietly falls
// back to the manual form instead of showing an error.
async function doUnlock(password, { silentFail = false } = {}) {
  const response = await fetch(`/api/drops/${encodeURIComponent(key)}/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (!silentFail) {
      showError(response.status === 401 ? t('dl_wrong_password') : (body.error || t('dl_unlock_failed')));
    }
    return false;
  }
  sessionToken = body.token;
  renderFiles(body);
  show(ui.unlocked);
  return true;
}

ui.unlockForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError();
  const orig = ui.unlockButton.textContent;
  ui.unlockButton.disabled = true;
  ui.unlockButton.textContent = t('dl_checking');
  try {
    await doUnlock(ui.password.value);
  } catch {
    showError(t('dl_conn'));
  } finally {
    ui.unlockButton.disabled = false;
    ui.unlockButton.textContent = orig;
  }
});

// --- step 3: transfers -----------------------------------------------------

function renderFiles(body) {
  const isText = dropKind === 'text' && body.files.length === 1;

  ui.messageView.hidden = !isText;
  ui.list.hidden = isText;
  ui.downloadAll.hidden = isText || body.files.length < 2;
  ui.deleteBox.hidden = !body.deleteAllowed;

  if (isText) {
    renderMessage(body.files[0]);
  } else {
    ui.list.replaceChildren();
    for (const file of body.files) {
      ui.list.append(fileItem(file));
    }
  }

  const expires = new Date(body.expiresAt);
  ui.unlockedMeta.textContent = tf('dl_page_valid', { EXPIRY: expires.toLocaleString(LOCALE) });
}

// fileItem builds one row: name, size, a download button, and — for an image or
// PDF — a preview toggle.
function fileItem(file) {
  const item = document.createElement('li');
  item.className = 'file-item';

  const name = document.createElement('span');
  name.className = 'file-name';
  name.textContent = file.name;

  const size = document.createElement('span');
  size.className = 'file-size';
  size.textContent = humanBytes(file.size);

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'file-download';
  button.textContent = t('dl_download');
  button.addEventListener('click', () => transfer({ fileId: file.id }, button));

  item.append(name, size);

  const kind = previewKind(file.name);
  if (kind) {
    const preview = document.createElement('button');
    preview.type = 'button';
    preview.className = 'file-preview';
    preview.textContent = t('dl_preview');
    preview.addEventListener('click', () => togglePreview(file, kind, preview, item));
    item.append(preview);
  }

  item.append(button);
  return item;
}

// previewKind classifies a filename by extension for inline preview.
function previewKind(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'svg'].includes(ext)) return 'image';
  if (ext === 'pdf') return 'pdf';
  return null;
}

// mimeFor returns a concrete media type for a blob so a browser renders it
// rather than treating the octet-stream download as a file to save.
function mimeFor(name, kind) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (kind === 'pdf') return 'application/pdf';
  const map = { jpg: 'image/jpeg', jpeg: 'image/jpeg', svg: 'image/svg+xml' };
  return map[ext] || `image/${ext}`;
}

// togglePreview fetches the file once, decrypted, into a blob URL and shows it
// inline. A second click hides it. Previewing spends the same one download the
// actual save would, and is free thereafter within this session.
async function togglePreview(file, kind, button, item) {
  const existing = item.querySelector('.file-preview-box');
  if (existing) {
    existing.remove();
    button.textContent = t('dl_preview');
    return;
  }
  clearError();
  button.disabled = true;
  button.textContent = t('dl_preparing');
  try {
    const url = await requestTicket({ fileId: file.id });
    const response = await fetch(url);
    if (!response.ok) { showError(t('dl_start_failed')); return; }
    const raw = await response.blob();
    const typed = new Blob([raw], { type: mimeFor(file.name, kind) });
    const objectUrl = URL.createObjectURL(typed);
    previewUrls.push(objectUrl);

    const box = document.createElement('div');
    box.className = 'file-preview-box';
    if (kind === 'image') {
      const img = document.createElement('img');
      img.alt = file.name;
      img.src = objectUrl;
      box.append(img);
    } else {
      // <embed> is governed by object-src (which allows blob:); an <iframe>
      // would need frame-src, kept locked down for the ad frames only.
      const embed = document.createElement('embed');
      embed.className = 'pdf-frame';
      embed.type = 'application/pdf';
      embed.src = objectUrl;
      box.append(embed);
    }
    item.append(box);
    button.textContent = t('dl_preview_hide');
  } catch {
    showError(t('dl_conn'));
  } finally {
    button.disabled = false;
  }
}

// renderMessage shows a secret-message share inline, with a copy button.
async function renderMessage(file) {
  ui.messageText.value = t('dl_loading_message');
  try {
    const url = await requestTicket({ fileId: file.id });
    const response = await fetch(url);
    if (!response.ok) { ui.messageText.value = ''; showError(t('dl_start_failed')); return; }
    ui.messageText.value = await response.text();
  } catch {
    ui.messageText.value = '';
    showError(t('dl_conn'));
  }
}

ui.messageCopy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(ui.messageText.value);
  } catch {
    ui.messageText.select();
    ui.messageText.setSelectionRange(0, ui.messageText.value.length);
    return;
  }
  const orig = ui.messageCopy.textContent;
  ui.messageCopy.textContent = t('copied');
  setTimeout(() => { ui.messageCopy.textContent = orig; }, 1600);
});

window.addEventListener('pagehide', () => {
  for (const u of previewUrls) URL.revokeObjectURL(u);
});

// deleteShare removes the share from the server, when the uploader allowed it.
ui.deleteButton.addEventListener('click', async () => {
  if (!window.confirm(t('dl_delete_confirm'))) return;
  clearError();
  const orig = ui.deleteButton.textContent;
  ui.deleteButton.disabled = true;
  ui.deleteButton.textContent = t('dl_deleting');
  try {
    const response = await fetch('/api/session/delete', {
      method: 'POST',
      headers: { 'X-Session-Token': sessionToken },
    });
    if (!response.ok && response.status !== 204) {
      const body = await response.json().catch(() => ({}));
      showError(body.error || t('dl_delete_failed'));
      return;
    }
    show(ui.deleted);
  } catch {
    showError(t('dl_conn'));
  } finally {
    ui.deleteButton.disabled = false;
    ui.deleteButton.textContent = orig;
  }
});

/**
 * Exchanges the session token for a short-lived, single-file ticket and
 * navigates to it.
 *
 * The browser has to navigate to download, which would put whatever authorises
 * the transfer into the address bar and the access log. A ticket scoped to one
 * file for a few minutes is a far smaller thing to leak than the session token.
 */
async function transfer(what, button) {
  clearError();
  const label = button.textContent;
  button.disabled = true;
  button.textContent = t('dl_preparing');

  try {
    const url = await requestTicket(what);
    // The response carries Content-Disposition: attachment, so clicking a
    // link starts the download and leaves this page in place — the file list
    // stays available for the next file.
    const link = document.createElement('a');
    link.href = url;
    link.download = '';
    link.rel = 'noreferrer';
    document.body.append(link);
    link.click();
    link.remove();
  } catch (err) {
    showError(err.message === 'ticket' ? t('dl_start_failed') : t('dl_conn'));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

// requestTicket exchanges the session token for a short-lived, single-file (or
// whole-share ZIP) ticket URL. The ticket is a far smaller thing to put in the
// address bar than the session token would be.
async function requestTicket(what) {
  const response = await fetch('/api/session/tickets', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Token': sessionToken,
    },
    body: JSON.stringify(what.zip ? { zip: true } : { fileId: what.fileId }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error('ticket');
  return body.url;
}

ui.downloadAll.addEventListener('click', () => transfer({ zip: true }, ui.downloadAll));

check();
