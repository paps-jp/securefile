// Local page served by the securefile_send helper.
//
// The files were chosen from the Windows right-click menu, so there is no drop
// zone: the helper already holds them. This page shows them, lets the user pick
// the options, and asks the helper to perform the upload to up.paps.jp. The
// helper streams progress back as newline-delimited JSON while it runs, and the
// page turns the final result into a link, a QR code and a paste-ready message
// exactly as the website does.

'use strict';

// The helper opens this page with ?t=<token>; every call back to the helper
// carries it, so nothing else on the machine can drive the local endpoint.
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const api = (path) => `${path}${path.includes('?') ? '&' : '?'}t=${encodeURIComponent(TOKEN)}`;

const el = (id) => document.getElementById(id);
const ui = {
  form: el('send-form'),
  fileList: el('file-list'),
  totalLine: el('total-line'),
  days: el('days'),
  maxDownloads: el('max-downloads'),
  password: el('password'),
  regen: el('regen'),
  embedPassword: el('embed-password'),
  passwordHint: el('password-hint'),
  allowDelete: el('allow-delete'),
  submit: el('submit'),
  progressPanel: el('progress-panel'),
  progressFill: el('progress-fill'),
  progressText: el('progress-text'),
  progressDetail: el('progress-detail'),
  resultPanel: el('result-panel'),
  shareUrl: el('share-url'),
  sharePassword: el('share-password'),
  passwordField: el('password-field'),
  passwordWarn: el('password-warn'),
  shareMessage: el('share-message'),
  shareQr: el('share-qr'),
  expiryLine: el('expiry-line'),
  errorLine: el('error-line'),
};

/** Staged files, as reported by the helper: {name, size}. */
let files = [];
/** Indices the user has kept for this send (a removed file is just excluded). */
let kept = new Set();
/** Server limits from /api/status, used to show the dynamic cap. */
let limits = null;
let sending = false;

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
  if (!isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `約${Math.ceil(seconds)}秒`;
  if (seconds < 3600) return `約${Math.ceil(seconds / 60)}分`;
  return `約${(seconds / 3600).toFixed(1)}時間`;
}

function showError(message) {
  ui.errorLine.textContent = message;
  ui.errorLine.hidden = false;
}
function clearError() {
  ui.errorLine.hidden = true;
  ui.errorLine.textContent = '';
}

// geomLimit / maxBytes mirror the server (service/config.go) so the cap shown
// here matches what the server will enforce.
function geomLimit(x, x0, y0, x1, y1) {
  if (x1 === x0 || x <= x0) return y0;
  if (x >= x1) return y1;
  const t = (x - x0) / (x1 - x0);
  return Math.floor(y0 * Math.pow(y1 / y0, t));
}
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
function updateLimit() {
  const cap = maxBytes();
  if (!isFinite(cap)) return;
  const callout = el('limit-callout-value');
  if (callout) callout.textContent = humanBytes(cap);
}

// --- password (generated in the browser, matching the website) -------------

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
ui.password.value = generatePassword();
ui.embedPassword.checked = false;
ui.allowDelete.checked = false;

ui.embedPassword.addEventListener('change', () => {
  ui.passwordHint.innerHTML = ui.embedPassword.checked
    ? 'リンク1つで開けます。<strong>リンクを知る人は誰でも開ける</strong>ため、'
      + '転送や共有範囲にご注意ください。'
    : '自動生成のままで十分安全です。受け取る人には'
      + '<strong>リンクとは別の手段</strong>（電話・対面など）で伝えてください。';
});

// --- staged file list ------------------------------------------------------

function renderFileList() {
  ui.fileList.replaceChildren();
  files.forEach((file, index) => {
    if (!kept.has(index)) return;
    const item = document.createElement('li');
    item.className = 'file-item';

    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = file.name;

    const size = document.createElement('span');
    size.className = 'file-size';
    size.textContent = humanBytes(file.size);

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'file-remove';
    remove.textContent = '除外';
    remove.setAttribute('aria-label', `${file.name} を送信から除外`);
    remove.addEventListener('click', () => {
      kept.delete(index);
      renderFileList();
    });

    item.append(name, size, remove);
    ui.fileList.append(item);
  });

  const keptFiles = [...kept].map((i) => files[i]);
  const total = keptFiles.reduce((sum, f) => sum + f.size, 0);
  ui.totalLine.hidden = keptFiles.length === 0;
  ui.totalLine.textContent = `${keptFiles.length} ファイル・合計 ${humanBytes(total)}`;
  ui.submit.disabled = keptFiles.length === 0 || sending;
}

async function loadFiles() {
  try {
    const res = await fetch(api('/api/files'));
    if (!res.ok) throw new Error(`files ${res.status}`);
    const data = await res.json();
    files = data.files || [];
    limits = data.limits || null;
    kept = new Set(files.map((_, i) => i));
    renderFileList();
    updateLimit();
  } catch (err) {
    showError('ファイル情報を取得できませんでした。ウィンドウを閉じてやり直してください。');
  }
}

ui.days.addEventListener('change', updateLimit);
ui.maxDownloads.addEventListener('change', updateLimit);

// --- send ------------------------------------------------------------------

ui.form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError();
  if (sending) return;

  const indices = [...kept];
  if (indices.length === 0) return;

  const total = indices.reduce((sum, i) => sum + files[i].size, 0);
  const cap = maxBytes();
  if (isFinite(cap) && total > cap) {
    showError(`合計 ${humanBytes(total)} はこの設定の上限 ${humanBytes(cap)} を超えています。`
      + `保存期間やダウンロード回数を短く（少なく）すると上限が上がります。`);
    return;
  }

  sending = true;
  ui.submit.disabled = true;
  ui.form.hidden = true;
  ui.progressPanel.hidden = false;
  ui.progressText.textContent = '準備しています…';
  ui.progressDetail.textContent = '';

  const password = ui.password.value;
  const body = JSON.stringify({
    indices,
    days: Number(ui.days.value),
    maxDownloads: Number(ui.maxDownloads.value),
    password,
    allowDelete: ui.allowDelete.checked,
  });

  const startedAt = performance.now();
  try {
    const res = await fetch(api('/api/send'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok || !res.body) {
      const t = await res.text().catch(() => '');
      throw new Error(t || `送信を開始できませんでした (${res.status})`);
    }

    // The helper streams newline-delimited JSON: many "progress" objects and a
    // final "done" or "error". Read incrementally so the bar tracks the upload.
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let result = null;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === 'progress') {
          paint(msg.sent, msg.total, startedAt);
        } else if (msg.type === 'error') {
          throw new Error(msg.message || 'アップロードに失敗しました。');
        } else if (msg.type === 'done') {
          result = msg;
        }
      }
    }
    if (!result) throw new Error('サーバーからの応答が不完全です。');
    showResult(result, password);
  } catch (err) {
    sending = false;
    ui.progressPanel.hidden = true;
    ui.form.hidden = false;
    ui.submit.disabled = kept.size === 0;
    showError(err.message || 'アップロードに失敗しました。');
  }
});

function paint(sent, total, startedAt) {
  const pct = total === 0 ? 100 : Math.floor((sent / total) * 100);
  ui.progressFill.style.width = `${pct}%`;
  ui.progressText.textContent = `${pct}%`;
  const elapsed = (performance.now() - startedAt) / 1000;
  if (elapsed > 1 && sent > 0) {
    const rate = sent / elapsed;
    ui.progressDetail.textContent =
      `${humanBytes(sent)} / ${humanBytes(total)}・${humanBytes(rate)}/秒・残り ${humanDuration((total - sent) / rate)}`;
  } else {
    ui.progressDetail.textContent = `${humanBytes(sent)} / ${humanBytes(total)}`;
  }
}

function showResult(result, password) {
  sending = false;
  ui.progressPanel.hidden = true;
  ui.resultPanel.hidden = false;

  const baseUrl = result.shareUrl;
  const embed = ui.embedPassword.checked;
  const link = embed ? `${baseUrl}#${encodeURIComponent(password)}` : baseUrl;
  ui.shareUrl.value = link;

  ui.passwordField.hidden = embed;
  ui.passwordWarn.hidden = embed;
  if (!embed) ui.sharePassword.value = password;

  const expires = new Date(result.expiresAt);
  const maxDownloads = Number(ui.maxDownloads.value);
  ui.shareMessage.value =
    `受け取りリンク：\n${link}\n\n`
    + `保存期限：${expires.toLocaleString('ja-JP')} まで\n`
    + `ダウンロード可能回数：${maxDownloads} 回`;

  renderQr(link);
  ui.expiryLine.textContent =
    `${expires.toLocaleString('ja-JP')} まで保管されます。期限が来ると自動的に削除されます。`;
}

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

// --- copy buttons ----------------------------------------------------------

document.addEventListener('click', async (event) => {
  const button = event.target.closest('.btn-copy');
  if (!button) return;
  const input = el(button.dataset.copy);
  if (!input) return;
  try {
    await navigator.clipboard.writeText(input.value);
  } catch {
    input.select();
    input.setSelectionRange(0, input.value.length);
    return;
  }
  const original = button.textContent;
  button.textContent = 'コピーしました';
  button.classList.add('is-copied');
  setTimeout(() => {
    button.textContent = original;
    button.classList.remove('is-copied');
  }, 1600);
});

loadFiles();
