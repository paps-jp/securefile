// Sender management page.
//
// The management token arrives in the URL fragment (never the path), so it stays
// out of the address bar, the access log, and any Referer. It is captured and
// scrubbed at once, then presented only in a request header.

'use strict';

const el = (id) => document.getElementById(id);
const t = (k) => (window.I18N && window.I18N[k]) || k;
const tf = (k, params) => {
  let s = t(k);
  for (const [key, val] of Object.entries(params)) s = s.split('%' + key + '%').join(val);
  return s;
};
const LOCALE = window.LANG || 'ja';

// Capture and scrub the token before anything else runs.
const token = location.hash ? decodeURIComponent(location.hash.slice(1)) : '';
if (location.hash) history.replaceState(null, document.title, location.pathname + location.search);

const ui = {
  checking: el('manage-checking'),
  missing: el('manage-missing'),
  status: el('manage-status'),
  deleted: el('manage-deleted'),
  state: el('manage-state'),
  downloads: el('manage-downloads'),
  expiry: el('manage-expiry'),
  created: el('manage-created'),
  size: el('manage-size'),
  url: el('manage-url'),
  deleteButton: el('manage-delete'),
  error: el('manage-error'),
};

function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function show(section) {
  for (const s of [ui.checking, ui.missing, ui.status, ui.deleted]) s.hidden = s !== section;
}

function showError(message) {
  ui.error.textContent = message;
  ui.error.hidden = false;
}

// A single state chip: picked, live, or ended.
function stateChip(info) {
  if (info.blocked) return { key: 'manage_state_blocked', cls: 'state-ended' };
  if (info.expired || info.exhausted || info.status !== 'ready') {
    return { key: 'manage_state_ended', cls: 'state-ended' };
  }
  if (info.downloads > 0) return { key: 'manage_state_picked', cls: 'state-picked' };
  return { key: 'manage_state_waiting', cls: 'state-waiting' };
}

function render(info) {
  const chip = stateChip(info);
  ui.state.textContent = t(chip.key);
  ui.state.className = `manage-state ${chip.cls}`;

  ui.downloads.textContent = tf('manage_downloads_value', {
    N: info.downloads, MAX: info.maxDownloads, REMAINING: info.remaining,
  });
  ui.expiry.textContent = new Date(info.expiresAt).toLocaleString(LOCALE);
  ui.created.textContent = new Date(info.createdAt).toLocaleString(LOCALE);
  ui.size.textContent = tf('manage_size_value', { N: info.fileCount, SIZE: humanBytes(info.totalSize) });
  ui.url.value = info.shareUrl;
  show(ui.status);
}

async function load() {
  if (!token) { show(ui.missing); return; }
  try {
    const response = await fetch('/api/manage', { headers: { 'X-Manage-Token': token } });
    if (response.status === 404) { show(ui.missing); return; }
    if (!response.ok) { showError(t('manage_load_failed')); show(ui.missing); return; }
    render(await response.json());
  } catch {
    showError(t('dl_conn'));
    show(ui.missing);
  }
}

ui.deleteButton.addEventListener('click', async () => {
  if (!window.confirm(t('manage_delete_confirm'))) return;
  ui.error.hidden = true;
  const orig = ui.deleteButton.textContent;
  ui.deleteButton.disabled = true;
  ui.deleteButton.textContent = t('dl_deleting');
  try {
    const response = await fetch('/api/manage/delete', {
      method: 'POST',
      headers: { 'X-Manage-Token': token },
    });
    if (!response.ok && response.status !== 204) {
      showError(t('manage_delete_failed'));
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

// Copy buttons (this page does not load upload.js).
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const target = el(button.dataset.copy);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.value);
    } catch {
      target.select();
      target.setSelectionRange(0, target.value.length);
      return;
    }
    const orig = button.textContent;
    button.textContent = t('copied');
    button.classList.add('is-copied');
    setTimeout(() => { button.textContent = orig; button.classList.remove('is-copied'); }, 1600);
  });
}

load();
