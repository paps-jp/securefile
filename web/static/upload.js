// Upload page.
//
// Files are sent in fixed-size parts rather than as one request. That is what
// makes a large transfer survive a flaky connection: each part is retried on
// its own, and the server reports how much it already holds, so a dropped
// link resumes instead of starting over.

'use strict';

const MAX_ATTEMPTS = 6;
const BASE_BACKOFF_MS = 800;

const el = (id) => document.getElementById(id);

// i18n: strings come from window.I18N, served per language by /i18n.js. tf
// substitutes %NAME% placeholders; LOCALE drives date/number formatting.
const t = (k) => (window.I18N && window.I18N[k]) || k;
const tf = (k, params) => {
  let s = t(k);
  for (const [key, val] of Object.entries(params)) s = s.split('%' + key + '%').join(val);
  return s;
};
const LOCALE = window.LANG || 'ja';

const ui = {
  form: el('upload-form'),
  dropzone: el('dropzone'),
  fileInput: el('file-input'),
  fileList: el('file-list'),
  totalLine: el('total-line'),
  password: el('password'),
  regen: el('regen'),
  embedPassword: el('embed-password'),
  passwordHint: el('password-hint'),
  allowDelete: el('allow-delete'),
  makeManage: el('make-manage'),
  submit: el('submit'),
  days: el('days'),
  maxDownloads: el('max-downloads'),

  modeFile: el('mode-file'),
  modeText: el('mode-text'),
  messageBlock: el('message-block'),
  messageInput: el('message-input'),

  progressPanel: el('progress-panel'),
  progressFill: el('progress-fill'),
  progressText: el('progress-text'),
  progressDetail: el('progress-detail'),
  cancel: el('cancel'),

  resultPanel: el('result-panel'),
  manageField: el('manage-field'),
  manageLink: el('manage-link'),
  shareUrl: el('share-url'),
  sharePassword: el('share-password'),
  passwordField: el('password-field'),
  passwordWarn: el('password-warn'),
  shareMessage: el('share-message'),
  shareQr: el('share-qr'),
  expiryLine: el('expiry-line'),
  another: el('another'),

  errorLine: el('error-line'),
};

/** Files the user has chosen, in the order they will be sent. */
let selected = [];
/** Set while a transfer is running, so Cancel can stop it. */
let transfer = null;
/** Server limits, loaded from /api/status; used to compute the dynamic cap. */
let limits = null;
/** 'file' to send chosen files, 'text' to send a secret message. */
let mode = 'file';
/** The server-rendered send-button label, restored when leaving message mode. */
const submitLabelFile = ui.submit.textContent;

// updateSubmitState enables the send button when there is something to send:
// at least one file, or a non-empty message.
function updateSubmitState() {
  ui.submit.disabled = mode === 'text'
    ? ui.messageInput.value.trim() === ''
    : selected.length === 0;
}

// setMode switches between file and message input. Only the input differs; the
// advanced settings, the encryption, and the result panel are shared.
function setMode(next) {
  mode = next;
  const isText = next === 'text';
  ui.dropzone.hidden = isText;
  ui.fileList.hidden = isText;
  ui.totalLine.hidden = isText || selected.length === 0;
  ui.messageBlock.hidden = !isText;
  ui.modeFile.classList.toggle('is-active', !isText);
  ui.modeText.classList.toggle('is-active', isText);
  ui.modeFile.setAttribute('aria-selected', String(!isText));
  ui.modeText.setAttribute('aria-selected', String(isText));
  ui.submit.textContent = isText ? t('submit_message') : submitLabelFile;
  updateSubmitState();
  if (isText) ui.messageInput.focus();
}

if (ui.modeFile && ui.modeText) {
  ui.modeFile.addEventListener('click', () => setMode('file'));
  ui.modeText.addEventListener('click', () => setMode('text'));
  ui.messageInput.addEventListener('input', updateSubmitState);
}

// geomLimit mirrors the server's geometric interpolation so the UI can show the
// current cap without a round trip. Keep this in step with service/config.go.
function geomLimit(x, x0, y0, x1, y1) {
  if (x1 === x0 || x <= x0) return y0;
  if (x >= x1) return y1;
  const t = (x - x0) / (x1 - x0);
  return Math.floor(y0 * Math.pow(y1 / y0, t));
}

/** maxBytes returns the allowed total size for the current retention/downloads. */
function maxBytes() {
  if (!limits) return Infinity;
  const days = Number(ui.days.value);
  const dl = Number(ui.maxDownloads.value);
  return Math.min(
    geomLimit(days, 1, limits.sizeAtMinDays, limits.maxDays, limits.sizeAtMaxDays),
    geomLimit(dl, 1, limits.sizeAtMinDownloads, limits.maxDownloads, limits.sizeAtMaxDownloads),
    limits.maxTotalBytes,
  );
}

/** updateLimit refreshes the on-screen cap and the drop-zone hint. */
function updateLimit() {
  const cap = maxBytes();
  if (!isFinite(cap)) return;
  const capText = humanBytes(cap);
  const el1 = el('current-limit');
  if (el1) el1.textContent = capText;
  const callout = el('limit-callout-value');
  if (callout) callout.textContent = capText;
  const hint = el('dropzone-hint');
  if (hint) {
    hint.textContent = tf('dropzone_hint_dynamic', { FILES: limits.maxFiles, SIZE: capText });
  }
}

async function loadLimits() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    limits = await res.json();
    updateLimit();
    updateUsage(limits);
  } catch { /* the server still enforces the real limit */ }
}

// --- helpers ---------------------------------------------------------------

function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function humanDuration(seconds) {
  if (!isFinite(seconds) || seconds < 0) return t('dash');
  if (seconds < 60) return tf('sec', { N: Math.ceil(seconds) });
  if (seconds < 3600) return tf('min', { N: Math.ceil(seconds / 60) });
  return tf('hour', { N: (seconds / 3600).toFixed(1) });
}

function showError(message) {
  ui.errorLine.textContent = message;
  ui.errorLine.hidden = false;
}

function clearError() {
  ui.errorLine.hidden = true;
  ui.errorLine.textContent = '';
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --- file selection --------------------------------------------------------

/** A file is identified by name+size+mtime so the same file is not added twice. */
function fileKey(file) {
  return `${file.name} ${file.size} ${file.lastModified}`;
}

function addFiles(list) {
  const seen = new Set(selected.map(fileKey));
  for (const file of list) {
    const key = fileKey(file);
    if (seen.has(key)) continue;
    seen.add(key);
    selected.push(file);
  }
  renderFileList();
}

function removeFile(index) {
  selected.splice(index, 1);
  renderFileList();
}

function renderFileList() {
  ui.fileList.replaceChildren();

  selected.forEach((file, index) => {
    const item = document.createElement('li');
    item.className = 'file-item';
    item.dataset.index = String(index);

    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = file.name;

    const size = document.createElement('span');
    size.className = 'file-size';
    size.textContent = humanBytes(file.size);

    const state = document.createElement('span');
    state.className = 'file-state';
    state.dataset.role = 'state';

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'file-remove';
    remove.textContent = t('remove');
    remove.setAttribute('aria-label', `${file.name} — ${t('remove')}`);
    remove.addEventListener('click', () => removeFile(index));

    item.append(name, size, state, remove);
    ui.fileList.append(item);
  });

  const total = selected.reduce((sum, f) => sum + f.size, 0);
  ui.totalLine.hidden = mode === 'text' || selected.length === 0;
  ui.totalLine.textContent = tf('file_total', { N: selected.length, SIZE: humanBytes(total) });
  updateSubmitState();
}

function setFileState(index, text, kind) {
  const item = ui.fileList.querySelector(`[data-index="${index}"]`);
  if (!item) return;
  const state = item.querySelector('[data-role="state"]');
  state.textContent = text;
  state.className = `file-state${kind ? ` is-${kind}` : ''}`;
}

// --- drag and drop ---------------------------------------------------------

let dragDepth = 0;
let overlay = null;

function showOverlay() {
  if (overlay) return;
  overlay = document.createElement('div');
  overlay.className = 'drag-overlay';
  overlay.textContent = t('drop_here');
  document.body.append(overlay);
}

function hideOverlay() {
  overlay?.remove();
  overlay = null;
}

// dragenter/dragleave fire for every element the pointer crosses, so the
// counter tracks whether the pointer is still anywhere inside the window.
window.addEventListener('dragenter', (e) => {
  if (!e.dataTransfer?.types.includes('Files')) return;
  e.preventDefault();
  dragDepth++;
  showOverlay();
});

window.addEventListener('dragover', (e) => {
  if (e.dataTransfer?.types.includes('Files')) e.preventDefault();
});

window.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) hideOverlay();
});

// filesFromDataTransfer expands a drop into a flat list of files, walking into
// any dropped folders (so a whole folder can be sent at once). The entries must
// be captured synchronously, before the first await, or the browser discards
// them when the drop event returns.
async function filesFromDataTransfer(dt) {
  const items = dt.items;
  if (!items || !items.length || !items[0].webkitGetAsEntry) {
    return [...dt.files];
  }
  const roots = [];
  for (const it of items) {
    const entry = it.webkitGetAsEntry && it.webkitGetAsEntry();
    if (entry) roots.push(entry);
  }
  const out = [];
  async function walk(entry) {
    if (entry.isFile) {
      out.push(await new Promise((res, rej) => entry.file(res, rej)));
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      let batch;
      do {
        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const e of batch) await walk(e);
      } while (batch.length);
    }
  }
  try {
    for (const e of roots) await walk(e);
  } catch { /* fall back below */ }
  return out.length ? out : [...dt.files];
}

window.addEventListener('drop', async (e) => {
  // A folder drop carries no entries in dataTransfer.files, so gate on the
  // "Files" type rather than on files.length.
  if (!e.dataTransfer || !Array.from(e.dataTransfer.types || []).includes('Files')) return;
  e.preventDefault();
  dragDepth = 0;
  hideOverlay();
  if (transfer) return; // a transfer is already running
  const files = await filesFromDataTransfer(e.dataTransfer);
  if (files.length) addFiles(files);
});

// Paste an image (e.g. a screenshot) straight onto the page to add it.
window.addEventListener('paste', (e) => {
  if (transfer) return;
  const items = e.clipboardData?.items;
  if (!items) return;
  const files = [];
  for (const it of items) {
    if (it.kind !== 'file') continue;
    const f = it.getAsFile();
    if (!f) continue;
    files.push(f.name ? f : new File([f], `pasted-${Date.now()}.${(f.type.split('/')[1] || 'png')}`, { type: f.type }));
  }
  if (files.length) { e.preventDefault(); addFiles(files); }
});

ui.dropzone.addEventListener('click', () => ui.fileInput.click());
ui.dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    ui.fileInput.click();
  }
});

ui.fileInput.addEventListener('change', () => {
  addFiles(ui.fileInput.files);
  // Reset so selecting the same file again still fires a change event.
  ui.fileInput.value = '';
});

// --- password --------------------------------------------------------------

// The password is generated in the browser so it can be shown and regenerated
// on demand. It is still sent to the server, which wraps the file key under it;
// the alphabet matches the server's (no 0/O/1/l-style look-alikes) so a
// password copied by hand survives the trip.
const PW_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz';

function generatePassword(length = 16) {
  const r = new Uint32Array(length);
  crypto.getRandomValues(r);
  let out = '';
  for (let i = 0; i < length; i++) out += PW_ALPHABET[r[i] % PW_ALPHABET.length];
  return out;
}

ui.regen.addEventListener('click', () => {
  ui.password.value = generatePassword();
  ui.password.focus();
});

// Show a fresh random password as soon as the page loads.
ui.password.value = generatePassword();

// Browsers restore prior checkbox state on reload/back; force the secure
// defaults (both off) so a share is never unexpectedly link-embedded or
// recipient-deletable.
ui.embedPassword.checked = false;
ui.allowDelete.checked = false;

// The hint changes with the delivery choice so the uploader understands the
// tradeoff: one convenient link, versus a password sent out-of-band.
ui.embedPassword.addEventListener('change', () => {
  ui.passwordHint.innerHTML = ui.embedPassword.checked
    ? t('password_hint_embed')
    : t('password_hint_default');
});

// --- transfer --------------------------------------------------------------

class Cancelled extends Error {
  constructor() {
    super('cancelled');
    this.name = 'Cancelled';
  }
}

/**
 * Sends one part and resolves with the offset the server holds afterwards.
 * Uses XMLHttpRequest rather than fetch because only XHR reports byte-level
 * upload progress, which is what keeps the bar moving during an 8 MiB part.
 */
function sendPart(session, fileId, offset, blob, onProgress, signal) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PATCH', `/api/uploads/${encodeURIComponent(session.sessionId)}/files/${fileId}`);
    xhr.setRequestHeader('Authorization', `Bearer ${session.token}`);
    xhr.setRequestHeader('Upload-Offset', String(offset));
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');

    const abort = () => xhr.abort();
    signal.addEventListener('abort', abort, { once: true });
    const done = () => signal.removeEventListener('abort', abort);

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) onProgress(e.loaded);
    });

    xhr.addEventListener('load', () => {
      done();
      if (xhr.status === 200) {
        resolve({ received: Number(xhr.getResponseHeader('Upload-Offset')) });
        return;
      }
      if (xhr.status === 409) {
        // The server holds a different amount than we assumed; continue from
        // where it actually is rather than failing the file.
        const expected = Number(xhr.getResponseHeader('Upload-Offset'));
        resolve({ received: expected, resynced: true });
        return;
      }
      let message = tf('server_error', { STATUS: xhr.status });
      try {
        const body = JSON.parse(xhr.responseText);
        if (body.error) message = body.error;
      } catch { /* non-JSON error body */ }
      const err = new Error(message);
      err.status = xhr.status;
      reject(err);
    });

    xhr.addEventListener('error', () => { done(); reject(new Error('network')); });
    xhr.addEventListener('timeout', () => { done(); reject(new Error('timeout')); });
    xhr.addEventListener('abort', () => { done(); reject(new Cancelled()); });

    xhr.send(blob);
  });
}

/** Retries a part on transport failures, but never on a rejection by the server. */
async function sendPartWithRetry(session, fileId, offset, blob, onProgress, signal) {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (signal.aborted) throw new Cancelled();
    try {
      return await sendPart(session, fileId, offset, blob, onProgress, signal);
    } catch (err) {
      if (err instanceof Cancelled) throw err;
      // 4xx means the request itself is wrong; repeating it changes nothing.
      if (err.status && err.status >= 400 && err.status < 500 && err.status !== 408) throw err;
      lastErr = err;
      if (attempt < MAX_ATTEMPTS) {
        ui.progressDetail.textContent =
          tf('reconnecting', { N: attempt, MAX: MAX_ATTEMPTS - 1 });
        await sleep(BASE_BACKOFF_MS * 2 ** (attempt - 1));
      }
    }
  }
  throw lastErr;
}

async function startUpload(session, files) {
  const controller = new AbortController();
  transfer = controller;
  ui.cancel.disabled = false;

  const grandTotal = files.reduce((sum, f) => sum + f.blob.size, 0);
  let completedBytes = 0;
  const startedAt = performance.now();

  const paint = (inFlight) => {
    const done = completedBytes + inFlight;
    const pct = grandTotal === 0 ? 100 : Math.floor((done / grandTotal) * 100);
    ui.progressFill.style.width = `${pct}%`;
    ui.progressText.textContent = `${pct}%`;

    const elapsed = (performance.now() - startedAt) / 1000;
    if (elapsed > 1 && done > 0) {
      const rate = done / elapsed;
      ui.progressDetail.textContent = tf('progress_detail', {
        DONE: humanBytes(done), TOTAL: humanBytes(grandTotal),
        RATE: humanBytes(rate), ETA: humanDuration((grandTotal - done) / rate),
      });
    } else {
      ui.progressDetail.textContent = `${humanBytes(done)} / ${humanBytes(grandTotal)}`;
    }
  };
  paint(0);

  for (const file of files) {
    setFileState(file.index, t('sending'), null);
    // A zero-byte file is sealed when the share is created, so the loop below
    // simply does not run for it.
    let offset = 0;
    let resyncs = 0;

    while (offset < file.blob.size) {
      const end = Math.min(offset + session.partSize, file.blob.size);
      const part = file.blob.slice(offset, end);
      // Bytes of earlier files, which this part's progress is added on top of.
      const priorFiles = completedBytes - offset;

      const res = await sendPartWithRetry(
        session, file.id, offset, part,
        (loaded) => paint(loaded),
        controller.signal,
      );

      if (res.resynced) {
        // A re-sync that does not advance means client and server disagree in
        // a way retrying will not fix; stop rather than loop forever.
        if (res.received <= offset && ++resyncs > 3) {
          throw new Error(t('sync_failed'));
        }
      } else {
        resyncs = 0;
      }

      // The server is authoritative about how much of this file it holds, in
      // both the normal and the re-synced case.
      offset = res.received;
      completedBytes = priorFiles + offset;
      paint(0);
    }

    setFileState(file.index, t('done'), 'done');
  }

  const finish = await fetch(`/api/uploads/${encodeURIComponent(session.sessionId)}/finish`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${session.token}` },
    signal: controller.signal,
  });
  if (!finish.ok) {
    const body = await finish.json().catch(() => ({}));
    throw new Error(body.error || t('finish_failed'));
  }
  return finish.json();
}

// --- submit ----------------------------------------------------------------

ui.form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError();

  // In message mode the text becomes a single file; otherwise the chosen files
  // are sent as-is. Everything downstream works on this one list.
  let localFiles;
  if (mode === 'text') {
    const text = ui.messageInput.value;
    if (text.trim() === '') return;
    localFiles = [new File([text], 'message.txt', { type: 'text/plain' })];
  } else {
    if (selected.length === 0) return;
    localFiles = selected;
  }

  // Pre-check against the dynamic cap so an over-limit upload fails here rather
  // than after allocating a share; the server still enforces it authoritatively.
  const total = localFiles.reduce((sum, f) => sum + f.size, 0);
  const cap = maxBytes();
  if (isFinite(cap) && total > cap) {
    showError(tf('size_over', { TOTAL: humanBytes(total), CAP: humanBytes(cap) }));
    return;
  }

  ui.submit.disabled = true;
  ui.form.hidden = true;
  ui.progressPanel.hidden = false;
  ui.progressText.textContent = t('preparing');
  ui.progressDetail.textContent = '';

  let session;
  try {
    const response = await fetch('/api/uploads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        files: localFiles.map((f) => ({ name: f.name, size: f.size })),
        days: Number(ui.days.value),
        maxDownloads: Number(ui.maxDownloads.value),
        password: ui.password.value,
        allowDelete: ui.allowDelete.checked,
        kind: mode === 'text' ? 'text' : 'file',
        manage: ui.makeManage.checked,
      }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || tf('start_failed', { STATUS: response.status }));
    }
    session = await response.json();
  } catch (err) {
    failTransfer(err);
    return;
  }

  // Pair each server-side file record with the local blob, by position.
  const files = session.files.map((record, index) => ({
    id: record.id,
    index,
    blob: localFiles[index],
  }));

  try {
    const result = await startUpload(session, files);
    showResult(session, result);
  } catch (err) {
    if (err instanceof Cancelled) {
      await fetch(`/api/uploads/${encodeURIComponent(session.sessionId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.token}` },
      }).catch(() => { /* the sweeper will reclaim it */ });
      resetToForm(t('cancelled'));
      return;
    }
    failTransfer(err);
  }
});

function failTransfer(err) {
  transfer = null;
  ui.progressPanel.hidden = true;
  ui.form.hidden = false;
  updateSubmitState();
  showError(err.message || t('upload_failed'));
}

function resetToForm(message) {
  transfer = null;
  ui.progressPanel.hidden = true;
  ui.form.hidden = false;
  updateSubmitState();
  ui.progressFill.style.width = '0%';
  if (message) showError(message);
}

ui.cancel.addEventListener('click', () => {
  ui.cancel.disabled = true;
  transfer?.abort();
});

function showResult(session, result) {
  transfer = null;
  ui.progressPanel.hidden = true;
  ui.resultPanel.hidden = false;

  const baseUrl = result.shareUrl || session.shareUrl;
  const password = session.password;
  const embed = ui.embedPassword.checked;

  // In embed mode the password rides in the URL fragment (#...), which browsers
  // never send to the server, so one link is all the recipient needs. Otherwise
  // the link and password are shown separately for out-of-band delivery.
  const link = embed ? `${baseUrl}#${encodeURIComponent(password)}` : baseUrl;
  ui.shareUrl.value = link;

  ui.passwordField.hidden = embed;
  ui.passwordWarn.hidden = embed;
  if (!embed) ui.sharePassword.value = password;

  const expires = new Date(result.expiresAt || session.expiresAt);
  const maxDownloads = Number(ui.maxDownloads.value);

  // Paste-ready message: link plus retention and remaining-download facts.
  ui.shareMessage.value = tf('msg_template', {
    LINK: link, EXPIRY: expires.toLocaleString(LOCALE), N: maxDownloads,
  });

  renderQr(link);

  // The management link (opt-in) is the sender's alone: it holds the token in
  // its fragment, so it never reaches the server in a request line or log.
  if (ui.manageField) {
    if (session.manageToken) {
      const prefix = LOCALE && LOCALE !== 'ja' ? `/${LOCALE}` : '';
      ui.manageLink.value = `${location.origin}${prefix}/manage#${encodeURIComponent(session.manageToken)}`;
      ui.manageField.hidden = false;
    } else {
      ui.manageField.hidden = true;
    }
  }

  ui.expiryLine.textContent = tf('expiry_note', { EXPIRY: expires.toLocaleString(LOCALE) });

  // Share via email or the OS share sheet, using the paste-ready message.
  const mail = el('mail-share');
  if (mail) {
    mail.href = `mailto:?subject=${encodeURIComponent(t('share_subject'))}&body=${encodeURIComponent(ui.shareMessage.value)}`;
  }
  const nativeShare = el('native-share');
  if (nativeShare) {
    nativeShare.hidden = !navigator.share;
    if (navigator.share) {
      nativeShare.onclick = () =>
        navigator.share({ title: t('share_subject'), text: ui.shareMessage.value }).catch(() => {});
    }
  }

  refreshStatus();
}

// renderQr draws a QR of the share link. The library is vendored locally, so
// nothing loads from a third party. In embed mode the link carries the
// password fragment, which is why the QR must be built in the browser.
function renderQr(link) {
  if (typeof qrcode !== 'function' || !ui.shareQr) return;
  try {
    const qr = qrcode(0, 'M');
    qr.addData(link);
    qr.make();
    ui.shareQr.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
    const svg = ui.shareQr.querySelector('svg');
    if (svg) { svg.removeAttribute('width'); svg.removeAttribute('height'); }
  } catch { ui.shareQr.textContent = ''; }
}

// updateUsage refreshes the counts and the disk-usage bar from a status object.
// The fill gets a small minimum width when anything is stored, so even a
// fraction of a percent shows as a visible sliver rather than an empty track.
function updateUsage(status) {
  const files = el('stat-files');
  const bytes = el('stat-bytes');
  if (files) files.textContent = String(status.files);
  if (bytes) bytes.textContent = humanBytes(status.bytes);

  if (!status.quotaBytes) return;
  const pct = status.bytes / status.quotaBytes * 100;
  const usage = el('stat-usage');
  const percent = el('stat-percent');
  const fill = el('usage-fill');
  if (usage) usage.textContent = humanBytes(status.bytes);
  if (percent) percent.textContent = pct < 1 && pct > 0 ? pct.toFixed(1) : String(Math.round(pct));
  if (fill) fill.style.width = `${status.bytes > 0 ? Math.max(pct, 1) : 0}%`;
  const warn = el('usage-warn');
  if (warn) warn.hidden = pct < 95;
}

/** The status strip is rendered server-side at page load, so it goes stale the
 *  moment this page uploads something. Refresh it after an upload. */
async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) updateUsage(await res.json());
  } catch {
    // Leaving the figure as rendered is fine; it is informational.
  }
}

ui.another.addEventListener('click', () => {
  selected = [];
  renderFileList();
  if (ui.messageInput) ui.messageInput.value = '';
  if (ui.manageField) ui.manageField.hidden = true;
  ui.password.value = generatePassword();
  ui.resultPanel.hidden = true;
  ui.form.hidden = false;
  ui.progressFill.style.width = '0%';
  updateSubmitState();
  clearError();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// --- copy buttons ----------------------------------------------------------

document.addEventListener('click', async (event) => {
  const button = event.target.closest('.btn-copy');
  if (!button) return;

  const input = el(button.dataset.copy);
  if (!input) return;

  try {
    await navigator.clipboard.writeText(input.value);
  } catch {
    // Clipboard access can be refused (insecure origin, permissions); falling
    // back to a selection at least lets the user copy by hand.
    input.select();
    input.setSelectionRange(0, input.value.length);
    return;
  }
  const original = button.textContent;
  button.textContent = t('copied');
  button.classList.add('is-copied');
  setTimeout(() => {
    button.textContent = original;
    button.classList.remove('is-copied');
  }, 1600);
});

// Guard against losing a transfer to an accidental navigation.
window.addEventListener('beforeunload', (event) => {
  if (!transfer) return;
  event.preventDefault();
  event.returnValue = '';
});

// Recompute the cap whenever retention or download count changes.
ui.days.addEventListener('change', updateLimit);
ui.maxDownloads.addEventListener('change', updateLimit);

renderFileList();
loadLimits();

