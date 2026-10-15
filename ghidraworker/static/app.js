/* GhidraWorker UI – plain JavaScript, no build step. */
'use strict';

// ------------------------------------------------------------------ helpers

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const view = $('#view');

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtBytes(n) {
  if (n == null) return '–';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtNum(n) { return n == null ? '–' : Number(n).toLocaleString('de-DE'); }
function fmtPct(x) { return `${(100 * (x || 0)).toFixed(1).replace('.', ',')} %`; }

function fmtTime(ts) {
  if (!ts) return '–';
  return new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
}

function fmtDuration(secs) {
  secs = Math.max(0, Math.round(secs));
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor(secs % 3600 / 60)}m`;
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function toast(msg, kind = 'info', ms = 4500) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

async function api(path, opts = {}) {
  const o = { ...opts };
  if (o.json !== undefined) {
    o.body = JSON.stringify(o.json);
    o.headers = { 'Content-Type': 'application/json', ...(o.headers || {}) };
    delete o.json;
  }
  const res = await fetch(path, o);
  const type = res.headers.get('content-type') || '';
  const body = type.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (body && body.detail) || (typeof body === 'string' && body) || res.statusText;
    const err = new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    err.status = res.status;
    throw err;
  }
  return body;
}

async function tryApi(path, opts) {
  try { return await api(path, opts); } catch (e) { toast(e.message, 'err', 7000); throw e; }
}

const storage = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};

// ------------------------------------------------------------------ state

const S = {
  status: null,
  projects: [],
  project: null,
  functions: null,
  fnIndex: null,
  data: {},
  route: null,
  fnFilter: storage.get('gw.fnFilter', { q: '', status: 'all', hideSkip: true, sort: 'address', dir: 1 }),
  fnLimit: 400,
  codeMode: storage.get('gw.codeMode', 'c'),
  applyRenames: storage.get('gw.applyRenames', true),
  uploads: [],
  logTimer: null,
};

const STATUS_LABEL = { todo: 'Offen', progress: 'In Arbeit', done: 'Fertig', skip: 'Ignoriert' };
const PROJECT_STATUS = {
  new: ['Neu', 'plain'], queued: ['Wartend', 'info'], running: ['Analysiert…', 'warn'],
  done: ['Analysiert', 'ok'], failed: ['Fehler', 'err'], cancelled: ['Abgebrochen', 'plain'],
};

function statusPill(meta) {
  const [label, cls] = PROJECT_STATUS[meta.status] || [meta.status, 'plain'];
  return `<span class="pill ${cls}">${esc(label)}</span>`;
}

const svg = d => `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const ICONS = {
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  upload: '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>',
  clock: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  spark: svg('<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6"/>'),
  gear: svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
};

function fileExt(name) {
  const m = /\.([A-Za-z0-9]{1,4})$/.exec(name || '');
  return m ? m[1].toUpperCase() : 'BIN';
}

function isBusy(meta) { return meta && (meta.status === 'queued' || meta.status === 'running'); }

// ------------------------------------------------------------------ theme

(function initTheme() {
  const saved = storage.get('gw.theme', null);
  if (saved) document.documentElement.dataset.theme = saved;
  $('#theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme
      || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    storage.set('gw.theme', next);
  });
})();

// ------------------------------------------------------------------ environment status

async function refreshStatus() {
  try {
    S.status = await api('/api/status');
  } catch { return; }
  const env = S.status.environment;
  const pill = $('#env-pill');
  if (env.ready) {
    pill.className = 'pill ok';
    pill.textContent = `Ghidra ${env.ghidra_version || ''}`;
    pill.title = `${env.ghidra_dir}\nJava ${env.java_version}: ${env.java}`;
  } else {
    pill.className = 'pill err';
    pill.textContent = 'Ghidra nicht bereit';
    pill.title = env.problems.join('\n');
  }
  pill.style.cursor = 'pointer';
  pill.onclick = () => { location.hash = '#/settings'; };
}

function envBanner() {
  const env = S.status && S.status.environment;
  if (!env || env.ready) return '';
  return `<div class="banner warn" style="margin-bottom:16px">
    <div><b>Ghidra ist noch nicht einsatzbereit.</b>
      <ul>${env.problems.map(p => `<li>${esc(p)}</li>`).join('')}</ul>
      <div style="margin-top:8px"><a class="btn small" href="#/settings">Zu den Einstellungen</a></div>
    </div></div>`;
}

// ------------------------------------------------------------------ routing

function parseRoute() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
  if (parts[0] === 'settings') return { view: 'settings' };
  if (parts[0] === 'p' && parts[1]) {
    return { view: 'project', id: parts[1], tab: parts[2] || 'overview', arg: parts.slice(3).join('/') || null };
  }
  return { view: 'dashboard' };
}

function setHashSilently(hash) {
  history.replaceState(null, '', hash);
  S.route = parseRoute();
}

async function render() {
  const prev = S.route;
  S.route = parseRoute();
  const r = S.route;
  clearInterval(S.logTimer);
  $$('.topnav a').forEach(a => a.classList.toggle('active',
    (a.dataset.nav === 'projects' && r.view !== 'settings') || (a.dataset.nav === 'settings' && r.view === 'settings')));
  view.classList.toggle('full', r.view === 'project');
  try {
    if (r.view === 'settings') return await renderSettings();
    if (r.view === 'project') {
      const sameProject = prev && prev.view === 'project' && prev.id === r.id && S.project && S.project.id === r.id;
      return await renderProject(sameProject);
    }
    return await renderDashboard();
  } catch (e) {
    view.innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  }
}

window.addEventListener('hashchange', render);

// ------------------------------------------------------------------ uploads

const fileInput = $('#file-input');
fileInput.addEventListener('change', () => {
  const files = Array.from(fileInput.files || []);
  fileInput.value = '';
  uploadFiles(files);
});

function pickFiles() { fileInput.click(); }

function uploadFiles(files) {
  if (!files.length) return;
  if (S.route.view !== 'dashboard') location.hash = '#/';
  let chain = Promise.resolve();
  const created = [];
  for (const file of files) {
    const up = { name: file.name, size: file.size, progress: 0, state: 'wartet' };
    S.uploads.push(up);
    chain = chain.then(() => uploadOne(file, up).then(meta => created.push(meta)).catch(err => {
      toast(`${file.name}: ${err.message}`, 'err', 8000);
    }));
  }
  renderUploads();
  chain.then(() => {
    S.uploads = S.uploads.filter(u => u.state !== 'fertig');
    if (created.length === 1) location.hash = `#/p/${created[0].id}`;
    else render();
  });
}

function uploadOne(file, up) {
  return new Promise((resolve, reject) => {
    const fd = new FormData();
    fd.append('file', file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/projects');
    up.state = 'lädt hoch';
    xhr.upload.onprogress = e => { if (e.lengthComputable) { up.progress = e.loaded / e.total; renderUploads(); } };
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) {
        up.state = 'fertig'; up.progress = 1; renderUploads(); resolve(body);
      } else {
        up.state = 'fehler'; renderUploads();
        reject(new Error((body && body.detail) || xhr.statusText || 'Upload fehlgeschlagen'));
      }
    };
    xhr.onerror = () => { up.state = 'fehler'; renderUploads(); reject(new Error('Netzwerkfehler')); };
    xhr.send(fd);
    renderUploads();
  });
}

function renderUploads() {
  const box = $('#uploads');
  if (!box) return;
  box.innerHTML = S.uploads.filter(u => u.state !== 'fertig').map(u => `
    <div class="card upload-row">
      ${u.state === 'fehler' ? '<span class="pill err">Fehler</span>' : '<span class="spinner"></span>'}
      <span class="mono">${esc(u.name)}</span><span class="muted">${fmtBytes(u.size)}</span>
      <div class="progress"><div style="width:${(u.progress * 100).toFixed(1)}%"></div></div>
      <span class="muted">${esc(u.state)}</span>
    </div>`).join('');
}

// global drag & drop
(function initDrop() {
  const overlay = $('#drop-overlay');
  let depth = 0;
  const hasFiles = e => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
  window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; depth++; overlay.hidden = false; });
  window.addEventListener('dragleave', e => { if (!hasFiles(e)) return; depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true; });
  window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; overlay.hidden = true;
    uploadFiles(Array.from(e.dataTransfer.files));
  });
})();

// ------------------------------------------------------------------ dashboard

async function renderDashboard() {
  S.projects = await api('/api/projects');
  const projects = S.projects;
  view.innerHTML = `
    ${envBanner()}
    <div class="page-head">
      <div>
        <div class="eyebrow">${ICONS.spark} ${projects.length ? `${projects.length} ${projects.length === 1 ? 'Projekt' : 'Projekte'}` : 'Willkommen'}</div>
        <h1>Reverse-Engineering-Projekte</h1>
        <p>EXE/DLL auswählen – Ghidra analysiert und dekompiliert sie und bereitet ein Rebuild-Projekt vor.</p>
      </div>
      <div class="spacer"></div>
      ${projects.length ? `<button class="btn primary big" id="btn-pick">${ICONS.plus} Datei öffnen…</button>` : ''}
    </div>
    <div id="uploads" class="uploads"></div>
    ${projects.length ? `<div class="project-grid">${projects.map(projectCard).join('')}
        <button class="new-card" id="btn-new"><span class="plus">${ICONS.plus}</span>Neue Datei analysieren</button></div>` : `
      <div class="dropzone" id="dropzone" role="button" tabindex="0">
        <div class="big-icon">${ICONS.upload}</div>
        <h2>Programm zum Analysieren auswählen</h2>
        <p>Klicken, um den Datei-Explorer zu öffnen – oder eine .exe/.dll hierher ziehen.</p>
        <span class="btn primary big">Datei auswählen…</span>
        <div class="hint">Unterstützt alles, was Ghidra lädt: PE (.exe, .dll, .sys), ELF, Mach-O, Rohdaten …</div>
      </div>`}
  `;
  renderUploads();
  for (const el of [$('#btn-pick'), $('#btn-new'), $('#dropzone')]) {
    if (!el) continue;
    el.addEventListener('click', pickFiles);
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') pickFiles(); });
  }
}

function projectCard(p) {
  const s = p.summary || {};
  const pe = (p.binary && p.binary.pe) || {};
  const job = p.job || {};
  let body;
  if (isBusy(p)) {
    body = `<div class="row muted" style="font-size:12.5px"><span class="spinner"></span>${esc(job.message || '')}</div>
      <div class="progress"><div style="width:${((job.progress || 0) * 100).toFixed(1)}%"></div></div>`;
  } else if (p.status === 'failed') {
    body = `<div class="muted" style="font-size:12.5px;color:var(--err)">${esc(p.error || 'Fehler')}</div>`;
  } else if (s.functions) {
    body = `<div class="kv-inline">
        <span><b>${fmtNum(s.relevant)}</b> Funktionen</span>
        <span><b>${fmtNum(s.counts.done)}</b> fertig</span>
        <span><b>${fmtNum(s.imports)}</b> Imports</span>
      </div>
      <div class="progress ok" title="Rebuild-Fortschritt"><div style="width:${(s.progress * 100).toFixed(1)}%"></div></div>`;
  } else {
    body = '<div class="muted" style="font-size:12.5px">Noch nicht analysiert.</div>';
  }
  return `<a class="card project-card" href="#/p/${esc(p.id)}">
    <div class="head">
      <div class="icon">${esc(fileExt(p.binary.filename))}</div>
      <div style="min-width:0;flex:1">
        <div class="title">${esc(p.name)}</div>
        <div class="file">${esc(p.binary.filename)} · ${fmtBytes(p.binary.size)}${pe.machine ? ` · ${esc(pe.machine)}` : ''}${pe.subsystem ? ` · ${esc(pe.subsystem)}` : ''}</div>
      </div>
      ${statusPill(p)}
    </div>
    ${body}
    <div class="foot">${ICONS.clock} Zuletzt geändert ${fmtTime(p.updated)}</div>
  </a>`;
}

// ------------------------------------------------------------------ project view

const TABS = [
  ['overview', 'Übersicht'], ['functions', 'Funktionen'], ['strings', 'Strings'], ['imports', 'Imports'],
  ['globals', 'Daten'], ['types', 'Typen'], ['rebuild', 'Rebuild'], ['log', 'Log'],
];

async function loadProject(id) {
  S.project = await api(`/api/projects/${encodeURIComponent(id)}`);
  return S.project;
}

async function loadFunctions(force = false) {
  if (S.functions && !force) return S.functions;
  if (!S.project.summary || !S.project.summary.functions) { S.functions = []; S.fnIndex = buildIndex([]); return []; }
  S.functions = await api(`/api/projects/${S.project.id}/data/functions`);
  S.fnIndex = buildIndex(S.functions);
  return S.functions;
}

function normAddr(a) { return String(a).toLowerCase().replace(/^0x/, '').replace(/^0+(?=.)/, ''); }

function buildIndex(funcs) {
  const byAddr = new Map(), byName = new Map(), byNorm = new Map();
  for (const f of funcs) {
    byAddr.set(f.address, f);
    byNorm.set(normAddr(f.address), f);
    byName.set(f.name, f);
    byName.set(f.fullName, f);
  }
  return { byAddr, byName, byNorm };
}

async function loadData(kind) {
  const key = `${S.project.id}:${kind}:${S.project.analyzed}`;
  if (S.data[key]) return S.data[key];
  const d = await api(`/api/projects/${S.project.id}/data/${kind}`);
  S.data[key] = d;
  return d;
}

async function renderProject(sameProject) {
  const r = S.route;
  if (!sameProject) {
    S.functions = null; S.fnIndex = null; S.data = {};
    await loadProject(r.id);
  }
  const p = S.project;
  view.innerHTML = `
    <div class="project-head" id="project-head"></div>
    <div id="job-slot"></div>
    <nav class="tabs" id="tabs"></nav>
    <section id="tab-body"></section>`;
  renderProjectHead();
  renderTabs();
  const body = $('#tab-body');
  const hasAnalysis = p.summary && p.summary.functions;
  const needsAnalysis = ['functions', 'strings', 'imports', 'globals', 'types', 'rebuild'];
  if (needsAnalysis.includes(r.tab) && !hasAnalysis) {
    body.innerHTML = noAnalysisHint();
    return;
  }
  const renderers = {
    overview: renderOverview, functions: renderFunctions, strings: renderStrings, imports: renderImports,
    globals: renderGlobals, types: renderTypes, rebuild: renderRebuild, log: renderLog,
  };
  await (renderers[r.tab] || renderOverview)(body);
}

function noAnalysisHint() {
  const p = S.project;
  if (isBusy(p)) return '<div class="empty"><span class="spinner"></span> Die Analyse läuft – die Daten erscheinen hier, sobald sie fertig ist.</div>';
  return `<div class="empty">Noch keine Analyse vorhanden.<div style="margin-top:12px">
    <button class="btn primary" data-job="analyze">Analyse starten</button></div></div>`;
}

function renderProjectHead() {
  const p = S.project;
  const pe = p.binary.pe || {};
  $('#project-head').innerHTML = `
    <div class="file-icon">${esc(fileExt(p.binary.filename))}</div>
    <div class="title-block">
      <h1><span class="editable" id="project-name" title="Zum Umbenennen klicken">${esc(p.name)}</span> ${statusPill(p)}</h1>
      <div class="sub">${esc(p.binary.filename)} · ${fmtBytes(p.binary.size)}${pe.machine ? ` · ${esc(pe.machine)} ${pe.bits}-Bit` : ''}${pe.subsystem ? ` · ${esc(pe.subsystem)}` : ''}${pe.dll ? ' · DLL' : ''}</div>
    </div>
    <div class="spacer"></div>
    <div class="row">
      ${isBusy(p) ? '' : `<button class="btn primary" data-job="analyze">${p.summary && p.summary.functions ? 'Neu analysieren' : 'Analyse starten'}</button>`}
      <button class="btn" data-open="ghidra" ${p.summary && p.summary.functions ? '' : 'disabled'} title="Ghidra-Projekt in der Ghidra-GUI öffnen">In Ghidra öffnen</button>
      <button class="btn" data-open="folder" title="Projektordner im Datei-Explorer öffnen">Ordner</button>
    </div>`;
  renderJobBanner();
  $('#project-name').addEventListener('click', async () => {
    const name = prompt('Projektname', p.name);
    if (name && name.trim() && name !== p.name) {
      S.project = await tryApi(`/api/projects/${p.id}`, { method: 'PATCH', json: { name } });
      renderProjectHead();
    }
  });
}

function renderJobBanner() {
  const p = S.project;
  const slot = $('#job-slot');
  if (!slot) return;
  const job = p.job || {};
  if (isBusy(p)) {
    const elapsed = job.started ? fmtDuration(Date.now() / 1000 - job.started) : '';
    slot.innerHTML = `<div class="card job-banner">
      <div class="row"><span class="spinner"></span><b>${esc(job.label || 'Job')}</b>
        <span class="muted">${esc(job.message || '')}</span><div class="spacer"></div>
        <span class="muted mono">${elapsed}</span>
        <span class="mono">${((job.progress || 0) * 100).toFixed(0)} %</span>
        <button class="btn small danger" id="btn-cancel">Abbrechen</button></div>
      <div class="progress"><div style="width:${((job.progress || 0) * 100).toFixed(1)}%"></div></div>
    </div>`;
    $('#btn-cancel').onclick = async () => {
      if (!confirm('Laufenden Job abbrechen?')) return;
      await tryApi(`/api/projects/${p.id}/cancel`, { method: 'POST' });
      toast('Abbruch angefordert');
    };
  } else if (p.status === 'failed' || p.status === 'cancelled') {
    slot.innerHTML = `<div class="banner ${p.status === 'failed' ? 'err' : 'info'}" style="margin-bottom:14px">
      <div style="flex:1"><b>${p.status === 'failed' ? 'Der letzte Job ist fehlgeschlagen' : 'Der letzte Job wurde abgebrochen'}.</b>
      <div>${esc(p.error || '')}</div></div>
      <a class="btn small" href="#/p/${esc(p.id)}/log">Log ansehen</a></div>`;
  } else {
    slot.innerHTML = '';
  }
}

function renderTabs() {
  const p = S.project, s = p.summary || {};
  const counts = { functions: s.relevant, strings: s.strings, imports: s.imports };
  $('#tabs').innerHTML = TABS.map(([k, label]) =>
    `<a href="#/p/${esc(p.id)}/${k}" class="${S.route.tab === k ? 'active' : ''}">${label}${counts[k] != null ? `<span class="count">${fmtNum(counts[k])}</span>` : ''}</a>`).join('');
}

// actions (event delegation)
view.addEventListener('click', async e => {
  const jobBtn = e.target.closest('[data-job]');
  if (jobBtn && S.project) {
    const type = jobBtn.dataset.job;
    if (type === 'analyze' && S.project.summary && S.project.summary.functions &&
      !confirm('Komplett neu analysieren? Das Ghidra-Projekt wird neu erstellt (Änderungen, die du direkt in Ghidra gemacht hast, gehen verloren). Status, Notizen und Namen in GhidraWorker bleiben erhalten.')) return;
    S.project = await tryApi(`/api/projects/${S.project.id}/jobs/${type}`, { method: 'POST' });
    toast('Job gestartet', 'ok');
    renderProjectHead();
    startPolling();
    return;
  }
  const openBtn = e.target.closest('[data-open]');
  if (openBtn && S.project) {
    await tryApi(`/api/projects/${S.project.id}/open/${openBtn.dataset.open}`, { method: 'POST' });
    toast(openBtn.dataset.open === 'ghidra' ? 'Ghidra wird gestartet…' : 'Wird geöffnet…', 'ok');
    return;
  }
  const fnLink = e.target.closest('[data-fn]');
  if (fnLink && S.project) {
    e.preventDefault();
    if (S.route.tab === 'functions' && $('#fn-detail')) selectFunction(fnLink.dataset.fn);
    else location.hash = `#/p/${S.project.id}/functions/${encodeURIComponent(fnLink.dataset.fn)}`;
  }
});

// ------------------------------------------------------------------ overview

async function renderOverview(body) {
  const p = S.project, s = p.summary || {}, pe = p.binary.pe || {};
  const hasAnalysis = !!s.functions;
  let program = {}, sections = [];
  if (hasAnalysis) {
    [program, sections] = await Promise.all([loadData('program'), loadData('sections')]);
    await loadFunctions();
  }
  const c = s.counts || { todo: 0, progress: 0, done: 0, skip: 0 };
  const rel = s.relevant || 0;
  const seg = (n, color) => rel ? `<div style="width:${(100 * n / rel).toFixed(2)}%;background:${color}"></div>` : '';
  body.innerHTML = `
    ${envBanner()}
    ${hasAnalysis ? `
    <div class="stat-row" style="margin-bottom:16px">
      <div class="card stat"><div class="label">Nachzubauende Funktionen</div><div class="value">${fmtNum(rel)}</div><div class="sub">von ${fmtNum(s.functions)} insgesamt</div></div>
      <div class="card stat"><div class="label">Fertig</div><div class="value" style="color:var(--ok)">${fmtNum(c.done)}</div></div>
      <div class="card stat"><div class="label">In Arbeit</div><div class="value" style="color:var(--warn)">${fmtNum(c.progress)}</div></div>
      <div class="card stat"><div class="label">Umbenannt</div><div class="value">${fmtNum(s.renamed)}</div></div>
      <div class="card stat highlight"><div class="label">Rebuild-Fortschritt</div><div class="value">${fmtPct(s.progress)}</div>
        <div class="sub">${fmtPct(s.progressBytes)} des Codes</div></div>
    </div>
    <div class="card card-body" style="margin-bottom:16px">
      <div class="row"><h3>Fortschritt</h3></div>
      <div class="progress stacked" style="height:10px;margin-top:10px">${seg(c.done, 'var(--ok)')}${seg(c.progress, 'var(--warn)')}</div>
      <div class="legend">
        <span><i class="status-dot st-done"></i>Fertig ${fmtNum(c.done)}</span>
        <span><i class="status-dot st-progress"></i>In Arbeit ${fmtNum(c.progress)}</span>
        <span><i class="status-dot st-todo"></i>Offen ${fmtNum(c.todo)}</span>
        <span><i class="status-dot st-skip"></i>Ignoriert (Thunks/Bibliothek) ${fmtNum(c.skip)}</span>
      </div>
    </div>` : ''}
    <div class="grid cols-2">
      <div class="card">
        <div class="card-head"><h2>Binärdatei</h2></div>
        <div class="card-body"><dl class="kv">
          <dt>Datei</dt><dd class="mono">${esc(p.binary.filename)}</dd>
          <dt>Größe</dt><dd>${fmtBytes(p.binary.size)} (${fmtNum(p.binary.size)} Bytes)</dd>
          <dt>SHA-256</dt><dd class="mono">${esc(p.binary.sha256)}</dd>
          ${program.md5 ? `<dt>MD5</dt><dd class="mono">${esc(program.md5)}</dd>` : ''}
          ${program.executableFormat ? `<dt>Format</dt><dd>${esc(program.executableFormat)}</dd>` : ''}
          ${program.language ? `<dt>Architektur</dt><dd class="mono">${esc(program.language)} · ${esc(program.compilerSpec)}</dd>` : ''}
          ${program.compiler ? `<dt>Compiler</dt><dd>${esc(program.compiler)}</dd>` : ''}
          ${program.imageBase ? `<dt>Image Base</dt><dd class="mono">${esc(program.imageBase)}</dd>` : ''}
          ${pe.subsystem ? `<dt>Subsystem</dt><dd>${esc(pe.subsystem)}${pe.dll ? ' (DLL)' : ''}</dd>` : ''}
          ${pe.linkerVersion ? `<dt>Linker</dt><dd>${esc(pe.linkerVersion)}</dd>` : ''}
          ${pe.timestampIso ? `<dt>Build-Zeitstempel</dt><dd>${esc(new Date(pe.timestampIso).toLocaleString('de-DE'))}</dd>` : ''}
          <dt>Hinzugefügt</dt><dd>${fmtTime(p.created)}</dd>
          <dt>Letzte Analyse</dt><dd>${fmtTime(p.analyzed)}${program.ghidraVersion ? ` · Ghidra ${esc(program.ghidraVersion)}` : ''}</dd>
        </dl>
        ${pe.dotnet ? '<div class="banner warn" style="margin-top:12px">Das ist eine .NET-Assembly. Ghidra sieht hier nur den nativen Stub – für .NET sind ILSpy oder dnSpy die bessere Wahl.</div>' : ''}
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Aktionen</h2></div>
        <div class="card-body stack">
          <div class="row">
            <button class="btn" data-job="export" ${hasAnalysis && !isBusy(p) ? '' : 'disabled'}>Export aktualisieren</button>
            <span class="muted" style="font-size:12.5px">nach Änderungen in der Ghidra-GUI (Ghidra vorher schließen)</span>
          </div>
          <div class="row">
            <button class="btn" data-job="sync" ${hasAnalysis && !isBusy(p) && s.pendingRenames ? '' : 'disabled'}>Umbenennungen nach Ghidra übertragen</button>
            <span class="muted" style="font-size:12.5px">${s.pendingRenames ? `${fmtNum(s.pendingRenames)} neue Namen ins Ghidra-Projekt schreiben` : 'alle Namen sind bereits in Ghidra'}</span>
          </div>
          <div class="row">
            <a class="btn" href="/api/projects/${esc(p.id)}/download/rebuild" ${hasAnalysis ? '' : 'hidden'}>Rebuild-Projekt (ZIP)</a>
            <a class="btn" href="/api/projects/${esc(p.id)}/download/analysis" ${hasAnalysis ? '' : 'hidden'}>Analyse-Export (ZIP)</a>
            <a class="btn" href="/api/projects/${esc(p.id)}/download/binary">Original-Datei</a>
          </div>
          <div class="row">
            <button class="btn danger" id="btn-delete">Projekt löschen</button>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Projektnotizen</h2><div class="spacer"></div><span class="save-state" id="notes-state"></span></div>
        <div class="card-body"><textarea id="project-notes" rows="8" placeholder="Ziele, Erkenntnisse, offene Fragen…">${esc(p.notes || '')}</textarea></div>
      </div>
      ${hasAnalysis ? `
      <div class="card">
        <div class="card-head"><h2>Einstiegspunkte</h2></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Adresse</th><th>Name</th></tr></thead><tbody>
          ${(program.entryPoints || []).map(ep => {
            const f = S.fnIndex.byAddr.get(ep.address);
            return `<tr><td class="mono">${esc(ep.address)}</td><td class="mono">${f ? `<a href="#" data-fn="${esc(f.address)}">${esc(f.displayName)}</a>` : esc(ep.name || '')}</td></tr>`;
          }).join('') || '<tr><td colspan="2" class="muted">keine</td></tr>'}
        </tbody></table></div>
      </div>
      <div class="card" style="grid-column:1/-1">
        <div class="card-head"><h2>Sektionen</h2></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Name</th><th>Start</th><th>Ende</th><th class="num">Größe</th><th>Rechte</th><th>Initialisiert</th></tr></thead><tbody>
          ${sections.map(b => `<tr><td class="mono">${esc(b.name)}</td><td class="mono">${esc(b.start)}</td><td class="mono">${esc(b.end)}</td>
            <td class="num">${fmtBytes(b.size)}</td><td class="mono">${b.read ? 'r' : '-'}${b.write ? 'w' : '-'}${b.execute ? 'x' : '-'}</td><td>${b.initialized ? 'ja' : 'nein'}</td></tr>`).join('')}
        </tbody></table></div>
      </div>` : ''}
    </div>`;

  const notes = $('#project-notes');
  const saveNotes = debounce(async () => {
    $('#notes-state').textContent = 'speichere…';
    S.project = await tryApi(`/api/projects/${p.id}`, { method: 'PATCH', json: { notes: notes.value } });
    $('#notes-state').textContent = 'gespeichert';
  }, 700);
  notes.addEventListener('input', () => { $('#notes-state').textContent = '…'; saveNotes(); });
  $('#btn-delete').addEventListener('click', async () => {
    if (!confirm(`Projekt „${p.name}" mit allen Analysedaten, Notizen und dem Rebuild-Ordner endgültig löschen?`)) return;
    await tryApi(`/api/projects/${p.id}`, { method: 'DELETE' });
    toast('Projekt gelöscht', 'ok');
    location.hash = '#/';
  });
}

// ------------------------------------------------------------------ functions

function filteredFunctions() {
  const f = S.fnFilter;
  const q = f.q.trim().toLowerCase();
  let list = S.functions.filter(fn => {
    if (f.hideSkip && fn.status === 'skip' && f.status !== 'skip') return false;
    if (f.status !== 'all' && fn.status !== f.status) return false;
    if (q) {
      const hay = `${fn.displayName} ${fn.name} ${fn.address} ${fn.notes}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const key = f.sort, dir = f.dir;
  const order = { todo: 1, progress: 0, done: 2, skip: 3 };
  list = list.slice().sort((a, b) => {
    let x, y;
    if (key === 'name') { x = a.displayName.toLowerCase(); y = b.displayName.toLowerCase(); }
    else if (key === 'size') { x = a.size; y = b.size; }
    else if (key === 'status') { x = order[a.status]; y = order[b.status]; }
    else if (key === 'callers') { x = a.callers.length; y = b.callers.length; }
    else { x = parseInt(a.address, 16) || a.address; y = parseInt(b.address, 16) || b.address; }
    return x < y ? -dir : x > y ? dir : 0;
  });
  return list;
}

async function renderFunctions(body) {
  await loadFunctions();
  const f = S.fnFilter;
  body.innerHTML = `
    <div class="explorer">
      <div class="card">
        <div class="toolbar">
          <input type="search" id="fn-q" placeholder="Suchen (Name, Adresse, Notiz)…" value="${esc(f.q)}">
          <select id="fn-status">
            <option value="all">Alle Status</option>
            ${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}" ${f.status === k ? 'selected' : ''}>${v}</option>`).join('')}
          </select>
        </div>
        <div class="toolbar" style="padding-top:6px;padding-bottom:6px">
          <label class="check" style="font-size:12.5px"><input type="checkbox" id="fn-hideskip" ${f.hideSkip ? 'checked' : ''}> Thunks/Bibliothek ausblenden</label>
          <div class="spacer"></div>
          <span class="muted" id="fn-count" style="font-size:12.5px"></span>
          <select id="fn-bulk" title="Alle gefilterten Funktionen auf einen Status setzen" style="font-size:12.5px;padding:3px 6px">
            <option value="">Alle gefilterten…</option>
            ${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}">→ ${v}</option>`).join('')}
          </select>
        </div>
        <div class="list" id="fn-list"></div>
      </div>
      <div class="card detail" id="fn-detail"><div class="empty">Funktion links auswählen.</div></div>
    </div>`;
  const rerender = () => { storage.set('gw.fnFilter', S.fnFilter); S.fnLimit = 400; renderFnList(); };
  $('#fn-q').addEventListener('input', debounce(e => { S.fnFilter.q = e.target.value; rerender(); }, 150));
  $('#fn-status').addEventListener('change', e => { S.fnFilter.status = e.target.value; rerender(); });
  $('#fn-hideskip').addEventListener('change', e => { S.fnFilter.hideSkip = e.target.checked; rerender(); });
  $('#fn-bulk').addEventListener('change', async e => {
    const status = e.target.value;
    e.target.value = '';
    if (!status) return;
    const list = filteredFunctions();
    if (!confirm(`${list.length} Funktionen auf „${STATUS_LABEL[status]}" setzen?`)) return;
    await tryApi(`/api/projects/${S.project.id}/functions/bulk`, { method: 'POST', json: { addresses: list.map(x => x.address), status } });
    await loadFunctions(true);
    await refreshProjectMeta();
    renderFnList();
    toast(`${list.length} Funktionen aktualisiert`, 'ok');
  });
  renderFnList();
  if (S.route.arg) selectFunction(S.route.arg);
}

function renderFnList() {
  const list = filteredFunctions();
  const shown = list.slice(0, S.fnLimit);
  const f = S.fnFilter;
  const arrow = k => f.sort === k ? (f.dir > 0 ? ' ▲' : ' ▼') : '';
  $('#fn-count').textContent = `${fmtNum(list.length)} Treffer`;
  $('#fn-list').innerHTML = `<table class="data"><thead><tr>
      <th class="sortable" data-sort="status" style="width:28px" title="Status">●${arrow('status')}</th>
      <th class="sortable" data-sort="name">Name${arrow('name')}</th>
      <th class="sortable" data-sort="address">Adresse${arrow('address')}</th>
      <th class="sortable num" data-sort="size">Größe${arrow('size')}</th>
      <th class="sortable num" data-sort="callers" title="Anzahl Aufrufer">⇠${arrow('callers')}</th>
    </tr></thead><tbody>
    ${shown.map(fn => `<tr class="clickable ${S.route.arg === fn.address ? 'selected' : ''}" data-addr="${esc(fn.address)}">
      <td><i class="status-dot st-${fn.status}" title="${STATUS_LABEL[fn.status]}"></i></td>
      <td class="fn-name">${esc(fn.displayName)}${fn.newName && fn.newName !== fn.name ? `<span class="orig">${esc(fn.name)}</span>` : ''}
        ${fn.thunk ? ' <span class="tag thunk">thunk</span>' : ''}${fn.library ? ' <span class="tag lib">lib</span>' : ''}${fn.decompiled ? '' : ' <span class="tag err">!</span>'}</td>
      <td class="mono faint">${esc(fn.address)}</td>
      <td class="num mono">${fmtNum(fn.size)}</td>
      <td class="num mono">${fn.callers.length}</td>
    </tr>`).join('')}
    </tbody></table>
    ${list.length > shown.length ? `<div class="empty" style="padding:14px"><button class="btn small" id="fn-more">${fmtNum(list.length - shown.length)} weitere anzeigen</button></div>` : ''}
    ${!list.length ? '<div class="empty">Keine Funktionen gefunden.</div>' : ''}`;
  $$('#fn-list th.sortable').forEach(th => th.addEventListener('click', () => {
    const k = th.dataset.sort;
    if (S.fnFilter.sort === k) S.fnFilter.dir *= -1; else { S.fnFilter.sort = k; S.fnFilter.dir = k === 'size' || k === 'callers' ? -1 : 1; }
    storage.set('gw.fnFilter', S.fnFilter);
    renderFnList();
  }));
  $$('#fn-list tr[data-addr]').forEach(tr => tr.addEventListener('click', () => selectFunction(tr.dataset.addr)));
  const more = $('#fn-more');
  if (more) more.addEventListener('click', () => { S.fnLimit += 1000; renderFnList(); });
}

async function selectFunction(addr) {
  setHashSilently(`#/p/${S.project.id}/functions/${encodeURIComponent(addr)}`);
  $$('#fn-list tr.selected').forEach(tr => tr.classList.remove('selected'));
  const row = $(`#fn-list tr[data-addr="${CSS.escape(addr)}"]`);
  if (row) { row.classList.add('selected'); row.scrollIntoView({ block: 'nearest' }); }
  const detail = $('#fn-detail');
  detail.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
  let fn;
  try {
    fn = await api(`/api/projects/${S.project.id}/functions/${encodeURIComponent(addr)}`);
  } catch (e) {
    detail.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    return;
  }
  if (S.route.arg !== addr) return; // user clicked elsewhere meanwhile
  renderFnDetail(fn);
}

function fnChips(addrs) {
  if (!addrs.length) return '<span class="faint">–</span>';
  return `<div class="chips">${addrs.slice(0, 80).map(a => {
    const f = S.fnIndex.byAddr.get(a);
    return `<span class="chip" data-fn="${esc(a)}" title="${esc(a)}">${esc(f ? f.displayName : a)}</span>`;
  }).join('')}${addrs.length > 80 ? `<span class="faint">+${addrs.length - 80}</span>` : ''}</div>`;
}

function renderFnDetail(fn) {
  const detail = $('#fn-detail');
  const renamed = fn.newName && fn.newName !== fn.name;
  detail.innerHTML = `
    <div class="detail-head">
      <div class="row" style="flex-wrap:nowrap">
        <input type="text" id="fn-rename" value="${esc(fn.newName || fn.name)}" style="flex:1;font-family:var(--mono);font-weight:600" title="Name (Enter speichert)">
        <button class="btn small" id="fn-rename-save">Umbenennen</button>
        ${renamed ? '<button class="btn small" id="fn-rename-reset" title="Auf Ghidra-Namen zurücksetzen">↺</button>' : ''}
      </div>
      <div class="sig">${esc(fn.signature)}</div>
      <div class="row">
        <div class="segmented status" id="fn-status-seg">
          ${Object.entries(STATUS_LABEL).map(([k, v]) => `<button data-v="${k}" class="${fn.status === k ? 'on' : ''}">${v}</button>`).join('')}
        </div>
        <span class="muted mono" style="font-size:12px">${esc(fn.address)} · ${fmtNum(fn.size)} Bytes · ${esc(fn.callingConvention || '')}</span>
        ${fn.thunk ? `<span class="tag thunk">thunk → ${esc(fn.thunkTarget || '?')}</span>` : ''}
        ${fn.library ? '<span class="tag lib">Bibliotheksfunktion (FID)</span>' : ''}
        ${renamed ? `<span class="tag">Ghidra: ${esc(fn.name)}</span>` : ''}
      </div>
    </div>
    <div class="detail-body">
      <div class="code-pane">
        <div class="toolbar">
          <div class="segmented" id="code-mode">
            <button data-v="c" class="${S.codeMode === 'c' ? 'on' : ''}">C (Decompiler)</button>
            <button data-v="asm" class="${S.codeMode === 'asm' ? 'on' : ''}">Assembler</button>
          </div>
          <label class="check" style="font-size:12.5px"><input type="checkbox" id="apply-renames" ${S.applyRenames ? 'checked' : ''}> eigene Namen anzeigen</label>
          <div class="spacer"></div>
          <button class="btn small" id="copy-code">Kopieren</button>
        </div>
        <div id="code-slot" style="flex:1;display:flex;min-height:0"></div>
      </div>
      <div class="detail-side">
        <div class="side-section">
          <div class="row"><h3>Notizen</h3><div class="spacer"></div><span class="save-state" id="fn-notes-state"></span></div>
          <textarea id="fn-notes" rows="6" placeholder="Was macht die Funktion? Offene Punkte…">${esc(fn.notes || '')}</textarea>
        </div>
        <div class="side-section"><h3>Aufgerufen von (${fn.callers.length})</h3>${fnChips(fn.callers)}</div>
        <div class="side-section"><h3>Ruft auf (${fn.callees.length})</h3>${fnChips(fn.callees)}</div>
        <div class="side-section"><h3>API-Aufrufe (${fn.externalCalls.length})</h3>
          ${fn.externalCalls.length ? `<div class="chips">${fn.externalCalls.map(x => `<span class="chip ext" title="${esc(x)}">${esc(x.split('::').pop())}</span>`).join('')}</div>` : '<span class="faint">–</span>'}</div>
        <div class="side-section"><h3>Strings (${fn.strings.length})</h3>
          ${fn.strings.length ? fn.strings.slice(0, 40).map(s => `<div class="mono" style="font-size:12px;overflow-wrap:anywhere">"${esc(s.value)}"</div>`).join('') : '<span class="faint">–</span>'}</div>
        ${fn.decompileError ? `<div class="banner err" style="font-size:12.5px">${esc(fn.decompileError)}</div>` : ''}
      </div>
    </div>`;

  const showCode = () => {
    const slot = $('#code-slot');
    slot.innerHTML = '';
    const text = (S.codeMode === 'asm' ? fn.asm : fn.code).replace(/^\s*\n/, '');
    slot.appendChild(codeBlock(text, S.codeMode === 'asm' ? 'asm' : 'c'));
  };
  showCode();

  $$('#code-mode button').forEach(b => b.addEventListener('click', () => {
    S.codeMode = b.dataset.v; storage.set('gw.codeMode', S.codeMode);
    $$('#code-mode button').forEach(x => x.classList.toggle('on', x === b));
    showCode();
  }));
  $('#apply-renames').addEventListener('change', e => { S.applyRenames = e.target.checked; storage.set('gw.applyRenames', S.applyRenames); showCode(); });
  $('#copy-code').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(S.codeMode === 'asm' ? fn.asm : fn.code); toast('Kopiert', 'ok', 1500); } catch { toast('Kopieren nicht möglich', 'err'); }
  });

  const update = async changes => {
    const updated = await tryApi(`/api/projects/${S.project.id}/functions/${encodeURIComponent(fn.address)}`, { method: 'PUT', json: changes });
    const idx = S.functions.findIndex(x => x.address === fn.address);
    if (idx >= 0) S.functions[idx] = updated;
    S.fnIndex = buildIndex(S.functions);
    Object.assign(fn, updated);
    refreshProjectMeta();
    return updated;
  };

  $$('#fn-status-seg button').forEach(b => b.addEventListener('click', async () => {
    await update({ status: b.dataset.v });
    $$('#fn-status-seg button').forEach(x => x.classList.toggle('on', x === b));
    renderFnList();
  }));

  const doRename = async name => {
    await update({ newName: name === fn.name ? '' : name });
    renderFnList();
    renderFnDetail(fn);
    toast('Name gespeichert', 'ok', 1500);
  };
  $('#fn-rename-save').addEventListener('click', () => doRename($('#fn-rename').value.trim()));
  $('#fn-rename').addEventListener('keydown', e => { if (e.key === 'Enter') doRename(e.target.value.trim()); });
  const reset = $('#fn-rename-reset');
  if (reset) reset.addEventListener('click', () => doRename(fn.name));

  const notes = $('#fn-notes');
  const saveNotes = debounce(async () => {
    $('#fn-notes-state').textContent = 'speichere…';
    await update({ notes: notes.value });
    $('#fn-notes-state').textContent = 'gespeichert';
  }, 700);
  notes.addEventListener('input', () => { $('#fn-notes-state').textContent = '…'; saveNotes(); });
}

// keyboard navigation in the function list
document.addEventListener('keydown', e => {
  if (!S.route || S.route.view !== 'project' || S.route.tab !== 'functions' || !S.functions) return;
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
  if (e.key !== 'j' && e.key !== 'k' && e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const list = filteredFunctions().slice(0, S.fnLimit);
  const idx = list.findIndex(f => f.address === S.route.arg);
  const next = list[(e.key === 'j' || e.key === 'ArrowDown') ? idx + 1 : Math.max(0, idx - 1)];
  if (next) { e.preventDefault(); selectFunction(next.address); }
});

// ------------------------------------------------------------------ code rendering

const C_KEYWORDS = new Set(('auto break case char const continue default do double else enum extern float for goto if inline int long ' +
  'register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while bool true false ' +
  'NULL __cdecl __stdcall __fastcall __thiscall __vectorcall __declspec').split(' '));
const C_TYPES = /^(undefined\d?|byte|sbyte|word|dword|qword|uchar|ushort|uint|ulong|longlong|ulonglong|float\d+|wchar_t|wchar16|wchar32|code|pointer\d*|string|u?int\d+_t|size_t|BOOL|BYTE|WORD|DWORD\d*|QWORD|LONG|ULONG|HANDLE|HWND|HMODULE|HINSTANCE|LPCSTR|LPSTR|LPCWSTR|LPWSTR|LPVOID|PVOID|UINT|LPARAM|WPARAM|LRESULT)$/;
const C_TOKEN = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|(\b0x[0-9a-fA-F]+\b|\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[uUlLfF]*\b)|([A-Za-z_][A-Za-z0-9_]*)|(^#[^\n]*)/gm;

function displayName(f) { return (S.applyRenames && f.newName) ? f.newName : f.name; }

function highlightC(text, linkFns = true) {
  let out = '', last = 0, m;
  C_TOKEN.lastIndex = 0;
  while ((m = C_TOKEN.exec(text))) {
    out += esc(text.slice(last, m.index));
    last = C_TOKEN.lastIndex;
    const [tok, com, str, num, ident, pre] = m;
    if (com) out += `<span class="tok-com">${esc(com)}</span>`;
    else if (str) out += `<span class="tok-str">${esc(str)}</span>`;
    else if (num) out += `<span class="tok-num">${esc(num)}</span>`;
    else if (pre) out += `<span class="tok-kw">${esc(pre)}</span>`;
    else if (ident) {
      const f = linkFns && S.fnIndex && S.fnIndex.byName.get(ident);
      if (f) out += `<a class="tok-link" data-fn="${esc(f.address)}" title="${esc(f.address)}">${esc(displayName(f))}</a>`;
      else if (C_KEYWORDS.has(ident)) out += `<span class="tok-kw">${ident}</span>`;
      else if (C_TYPES.test(ident)) out += `<span class="tok-type">${ident}</span>`;
      else if (/^\s*\(/.test(text.slice(last, last + 8))) out += `<span class="tok-fn">${esc(ident)}</span>`;
      else out += esc(ident);
    } else out += esc(tok);
  }
  return out + esc(text.slice(last));
}

function highlightAsm(text) {
  return text.split('\n').map(line => {
    if (/^\s*;/.test(line)) return `<span class="tok-com">${esc(line)}</span>`;
    const m = /^(\s+)([0-9a-fA-F:]+)(\s+)(\S+)(\s+)(\S+)(.*)$/.exec(line);
    if (!m) return /^\S.*:$/.test(line) ? `<span class="tok-fn">${esc(line)}</span>` : esc(line);
    const [, s1, addr, s2, bytes, s3, mnem, rest] = m;
    const ops = esc(rest).replace(/0x([0-9a-fA-F]+)/g, (all, hex) => {
      const f = S.fnIndex && S.fnIndex.byNorm.get(normAddr(hex));
      return f ? `<a class="tok-link" data-fn="${esc(f.address)}" title="${esc(all)}">${esc(displayName(f))}</a>` : `<span class="tok-num">${all}</span>`;
    });
    return `${s1}<span class="tok-addr">${esc(addr)}</span>${s2}<span class="faint">${esc(bytes)}</span>${s3}<span class="tok-kw">${esc(mnem)}</span>${ops}`;
  }).join('\n');
}

function codeBlock(text, lang) {
  const pre = document.createElement('pre');
  pre.className = 'code';
  text = text || '';
  const big = text.length > 600000;
  let html;
  if (lang === 'c' && !big) html = highlightC(text);
  else if (lang === 'asm' && !big) html = highlightAsm(text);
  else html = esc(text);
  const lines = text.split('\n').length;
  const gutter = Array.from({ length: lines }, (_, i) => i + 1).join('\n');
  pre.innerHTML = `<div style="display:flex"><span class="ln" style="white-space:pre">${gutter}</span><span style="flex:1">${html}</span></div>`;
  return pre;
}

// ------------------------------------------------------------------ strings / imports / globals / types

function searchTable({ body, rows, columns, placeholder, filter, rowHtml, limit = 500, extra = '' }) {
  body.innerHTML = `<div class="card">
    <div class="toolbar"><input type="search" id="t-q" placeholder="${esc(placeholder)}">${extra}<span class="muted" id="t-count"></span></div>
    <div class="table-wrap" style="max-height:calc(100vh - 270px)"><table class="data"><thead><tr>${columns.map(c => `<th class="${c.cls || ''}">${c.label}</th>`).join('')}</tr></thead>
    <tbody id="t-body"></tbody></table><div id="t-more"></div></div></div>`;
  let max = limit;
  const draw = () => {
    const q = $('#t-q').value.trim().toLowerCase();
    const list = q ? rows.filter(r => filter(r).toLowerCase().includes(q)) : rows;
    $('#t-count').textContent = `${fmtNum(list.length)} Einträge`;
    $('#t-body').innerHTML = list.slice(0, max).map(rowHtml).join('');
    $('#t-more').innerHTML = list.length > max ? `<div class="empty" style="padding:12px"><button class="btn small">${fmtNum(list.length - max)} weitere anzeigen</button></div>` : '';
    const btn = $('#t-more button');
    if (btn) btn.onclick = () => { max += 2000; draw(); };
  };
  $('#t-q').addEventListener('input', debounce(() => { max = limit; draw(); }, 150));
  draw();
}

function usedByChips(names) {
  if (!names || !names.length) return '<span class="faint">–</span>';
  return `<div class="chips">${names.slice(0, 8).map(n => {
    const f = S.fnIndex.byName.get(n);
    return f ? `<span class="chip" data-fn="${esc(f.address)}">${esc(f.displayName)}</span>` : `<span class="chip ext">${esc(n)}</span>`;
  }).join('')}${names.length > 8 ? `<span class="faint">+${names.length - 8}</span>` : ''}</div>`;
}

async function renderStrings(body) {
  await loadFunctions();
  const rows = await loadData('strings');
  searchTable({
    body, rows, placeholder: 'Strings durchsuchen…',
    columns: [{ label: 'Adresse' }, { label: 'Wert' }, { label: 'Typ' }, { label: 'Refs', cls: 'num' }, { label: 'Verwendet in' }],
    filter: r => `${r.value} ${r.address}`,
    rowHtml: r => `<tr><td class="mono faint">${esc(r.address)}</td><td class="mono" style="overflow-wrap:anywhere;max-width:600px">${esc(r.value)}</td>
      <td class="faint">${esc(r.type)}</td><td class="num">${r.refCount}</td><td>${usedByChips(r.usedBy)}</td></tr>`,
  });
}

async function renderImports(body) {
  await loadFunctions();
  const [imports, exports] = await Promise.all([loadData('imports'), loadData('exports')]);
  const libs = {};
  imports.forEach(i => { libs[i.library] = (libs[i.library] || 0) + 1; });
  body.innerHTML = `
    <div class="row" style="margin-bottom:12px">${Object.entries(libs).sort().map(([l, n]) => `<span class="pill info plain">${esc(l)} · ${n}</span>`).join('')}</div>
    <div id="imp"></div>
    ${exports.length ? `<div class="card" style="margin-top:16px"><div class="card-head"><h2>Exports (${exports.length})</h2></div>
      <div class="table-wrap" style="max-height:340px"><table class="data"><thead><tr><th>Adresse</th><th>Name</th><th>Typ</th></tr></thead><tbody>
      ${exports.map(x => { const f = S.fnIndex.byAddr.get(x.address); return `<tr><td class="mono faint">${esc(x.address)}</td>
        <td class="mono">${f ? `<a href="#" data-fn="${esc(f.address)}">${esc(x.name)}</a>` : esc(x.name)}</td><td class="faint">${esc(x.type)}</td></tr>`; }).join('')}
      </tbody></table></div></div>` : ''}`;
  searchTable({
    body: $('#imp'), rows: imports, placeholder: 'Imports durchsuchen…',
    columns: [{ label: 'Bibliothek' }, { label: 'Funktion' }, { label: 'Signatur' }, { label: 'Refs', cls: 'num' }, { label: 'Verwendet in' }],
    filter: r => `${r.library} ${r.name}`,
    rowHtml: r => `<tr><td class="mono">${esc(r.library)}</td><td class="mono"><b>${esc(r.name)}</b></td>
      <td class="mono faint" style="font-size:12px;max-width:420px;overflow-wrap:anywhere">${esc(r.signature || '')}</td>
      <td class="num">${r.refCount}</td><td>${usedByChips(r.usedBy)}</td></tr>`,
  });
}

async function renderGlobals(body) {
  const rows = await loadData('globals');
  searchTable({
    body, rows, placeholder: 'Globale Daten durchsuchen…',
    columns: [{ label: 'Adresse' }, { label: 'Name' }, { label: 'Datentyp' }, { label: 'Größe', cls: 'num' }, { label: 'Sektion' }, { label: 'Quelle' }],
    filter: r => `${r.name} ${r.address} ${r.dataType}`,
    rowHtml: r => `<tr><td class="mono faint">${esc(r.address)}</td><td class="mono">${esc(r.name)}</td><td class="mono">${esc(r.dataType)}</td>
      <td class="num">${fmtNum(r.length)}</td><td class="mono faint">${esc(r.block || '')}</td><td class="faint">${esc(r.source)}</td></tr>`,
  });
}

async function renderTypes(body) {
  await loadFunctions();
  const text = await api(`/api/projects/${S.project.id}/types`);
  body.innerHTML = `<div class="card" style="display:flex;flex-direction:column;height:calc(100vh - 230px);min-height:400px">
    <div class="toolbar"><span class="muted">Von Ghidra rekonstruierte Datentypen (C-Header) – Basis für <span class="mono">include/gw_types.h</span> im Rebuild.</span></div>
    <div id="types-slot" style="flex:1;display:flex;min-height:0"></div></div>`;
  $('#types-slot').appendChild(codeBlock(text, 'c'));
}

// ------------------------------------------------------------------ rebuild

async function renderRebuild(body) {
  await loadFunctions();
  const p = S.project, s = p.summary || {};
  const tree = await api(`/api/projects/${p.id}/rebuild`);
  const files = tree.files;
  const dirs = {};
  files.forEach(f => { const i = f.path.lastIndexOf('/'); const d = i < 0 ? '' : f.path.slice(0, i); (dirs[d] = dirs[d] || []).push(f); });
  const current = S.route.arg || (files.find(f => f.path === 'PLAN.md') || files[0] || {}).path;
  body.innerHTML = `
    <div class="card card-body" style="margin-bottom:14px">
      <div class="row">
        <div><b>Rebuild-Projekt</b> <span class="muted">– CMake-C-Projekt, eine Datei pro Funktion, vorbefüllt mit dem Decompiler-Code.
          Nur Funktionen mit Status „Fertig" werden kompiliert.</span>
          <div class="mono faint" style="font-size:12px;margin-top:4px">${esc(tree.root)}</div></div>
      </div>
      <div class="row" style="margin-top:12px">
        <button class="btn primary" id="btn-regen">Gerüst neu erzeugen</button>
        <button class="btn" data-open="rebuild">Ordner öffnen</button>
        <a class="btn" href="/api/projects/${esc(p.id)}/download/rebuild">Als ZIP herunterladen</a>
      </div>
      <div class="legend">
        <span>${fmtNum((s.counts || {}).done)} / ${fmtNum(s.relevant)} Funktionen fertig (${fmtPct(s.progress)})</span>
        <span>${fmtNum(files.length)} Dateien</span>
        <span>Von dir geänderte Dateien werden beim Neu-Erzeugen nie überschrieben.</span>
      </div>
    </div>
    <div class="files">
      <div class="card"><div class="file-list">
        ${Object.keys(dirs).sort().map(d => `${d ? `<div class="dir">${esc(d)}/</div>` : ''}${dirs[d].map(f => `
          <a href="#/p/${esc(p.id)}/rebuild/${encodeURIComponent(f.path)}" class="${f.path === current ? 'active' : ''}">
            <span>${esc(f.path.slice(d ? d.length + 1 : 0))}</span><span class="size">${fmtBytes(f.size)}</span></a>`).join('')}`).join('')}
        ${files.length ? '' : '<div class="empty">Noch nichts erzeugt.</div>'}
      </div></div>
      <div class="card" style="display:flex;flex-direction:column">
        <div class="toolbar"><span class="mono" id="rb-path"></span></div>
        <div id="rb-slot" style="flex:1;display:flex;min-height:0"></div>
      </div>
    </div>`;
  $('#btn-regen').addEventListener('click', async () => {
    const res = await tryApi(`/api/projects/${p.id}/rebuild`, { method: 'POST' });
    toast(`Gerüst erzeugt: ${res.written} Dateien geschrieben, ${res.kept.length} eigene Änderungen behalten, ${res.sources} Funktionen im Build.`, 'ok', 6000);
    render();
  });
  if (current) {
    $('#rb-path').textContent = current;
    const text = await api(`/api/projects/${p.id}/rebuild/file?path=${encodeURIComponent(current)}`);
    const lang = /\.(c|h|cpp|hpp)$/.test(current) ? 'c' : 'text';
    $('#rb-slot').appendChild(codeBlock(text, lang));
  }
}

// ------------------------------------------------------------------ log

async function renderLog(body) {
  body.innerHTML = '<div class="row" style="margin-bottom:8px"><span class="muted">Ausgabe von Ghidra headless (letzte 2000 Zeilen)</span></div><pre class="log" id="log"></pre>';
  const draw = async () => {
    let text;
    try { text = await api(`/api/projects/${S.project.id}/log?tail=2000`); } catch { return; }
    const el = $('#log');
    if (!el) return;
    const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 30;
    el.innerHTML = text ? text.split('\n').map(l => {
      const cls = /^ERROR|Exception|SEVERE/.test(l) ? 'l-err' : /^WARN/.test(l) ? 'l-warn' : /GW_|^#/.test(l) ? 'l-gw' : '';
      return cls ? `<span class="${cls}">${esc(l)}</span>` : esc(l);
    }).join('\n') : '<span class="faint">Noch kein Log vorhanden.</span>';
    if (atBottom) el.scrollTop = el.scrollHeight;
  };
  await draw();
  $('#log').scrollTop = 1e9;
  S.logTimer = setInterval(() => { if (isBusy(S.project)) draw(); }, 2000);
}

// ------------------------------------------------------------------ settings

async function renderSettings() {
  await refreshStatus();
  const settings = await api('/api/settings');
  const env = S.status.environment;
  const inst = S.status.installer;
  view.innerHTML = `
    <div class="page-head"><div><div class="eyebrow">${ICONS.gear} Konfiguration</div><h1>Einstellungen</h1><p>Workspace: <span class="mono">${esc(S.status.workspace)}</span></p></div></div>
    <div class="grid cols-2">
      <div class="card">
        <div class="card-head"><h2>Ghidra &amp; Java</h2><div class="spacer"></div>${env.ready ? '<span class="pill ok">bereit</span>' : '<span class="pill err">nicht bereit</span>'}</div>
        <div class="card-body stack">
          <dl class="kv">
            <dt>Ghidra</dt><dd class="mono">${env.ghidra_dir ? `${esc(env.ghidra_dir)}` : '<span class="faint">nicht gefunden</span>'}</dd>
            <dt>Version</dt><dd>${esc(env.ghidra_version || '–')}</dd>
            <dt>Java</dt><dd class="mono">${env.java ? esc(env.java) : '<span class="faint">nicht gefunden</span>'}</dd>
            <dt>Java-Version</dt><dd>${env.java_version || '–'}${env.java_min ? ` <span class="faint">(benötigt ≥ ${env.java_min})</span>` : ''}${env.java && !env.javac ? ' <span class="tag err">kein JDK</span>' : ''}</dd>
          </dl>
          ${env.problems.length ? `<div class="banner warn"><ul style="margin:0">${env.problems.map(p => `<li>${esc(p)}</li>`).join('')}</ul></div>` : ''}
          <div class="stack" style="gap:8px">
            <div class="row">
              <button class="btn ${env.ghidra_dir ? '' : 'primary'}" id="btn-install" ${inst.running ? 'disabled' : ''}>${env.ghidra_dir ? 'Neuestes Ghidra-Release installieren' : 'Ghidra automatisch installieren'}</button>
              <button class="btn" id="btn-open-ghidra" ${env.ghidra_dir ? '' : 'disabled'}>Ghidra starten</button>
            </div>
            <div class="muted" style="font-size:12.5px">Lädt das aktuelle offizielle Release von <a href="https://github.com/NationalSecurityAgency/ghidra/releases" target="_blank" rel="noopener">github.com/NationalSecurityAgency/ghidra</a> (~500 MB) in den Ordner <span class="mono">tools/</span>.
              Java (JDK 21+, z. B. <a href="https://adoptium.net/" target="_blank" rel="noopener">Eclipse Temurin</a>) muss separat installiert sein.</div>
            <div id="install-state">${installState(inst)}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Analyse</h2><div class="spacer"></div><span class="save-state" id="set-state"></span></div>
        <form class="card-body stack" id="settings-form">
          <label class="field">Ghidra-Installationsordner <small>leer = automatisch (tools/, GHIDRA_INSTALL_DIR)</small>
            <input type="text" name="ghidra_dir" value="${esc(settings.ghidra_dir)}" placeholder="C:\\Tools\\ghidra_12.1_PUBLIC"></label>
          <label class="field">JDK-Ordner (JAVA_HOME) <small>leer = JAVA_HOME bzw. java aus dem PATH</small>
            <input type="text" name="java_home" value="${esc(settings.java_home)}" placeholder="C:\\Program Files\\Eclipse Adoptium\\jdk-21"></label>
          <div class="grid cols-3" style="gap:12px">
            <label class="field">Parallele Analysen <small>Neustart nötig</small><input type="number" min="1" max="16" name="max_parallel_jobs" value="${settings.max_parallel_jobs}"></label>
            <label class="field">CPU-Kerne je Analyse <small>0 = alle</small><input type="number" min="0" name="max_cpu" value="${settings.max_cpu}"></label>
            <label class="field">Analyse-Timeout (s) <small>0 = unbegrenzt</small><input type="number" min="0" name="analysis_timeout" value="${settings.analysis_timeout}"></label>
            <label class="field">Max. Arbeitsspeicher <small>z. B. 8G, leer = Standard</small><input type="text" name="max_memory" value="${esc(settings.max_memory)}"></label>
          </div>
          <label class="check"><input type="checkbox" name="thorough_analysis" ${settings.thorough_analysis ? 'checked' : ''}>
            <span>Gründliche Analyse<small>Aktiviert „Decompiler Parameter ID" u. a. – langsamer, aber deutlich bessere Funktionssignaturen.</small></span></label>
          <label class="check"><input type="checkbox" name="auto_start" ${settings.auto_start ? 'checked' : ''}>
            <span>Analyse automatisch starten<small>sobald eine Datei hinzugefügt wurde</small></span></label>
          <div><button class="btn primary" type="submit">Speichern</button></div>
        </form>
      </div>
    </div>`;

  $('#settings-form').addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const data = Object.fromEntries(fd.entries());
    ['max_parallel_jobs', 'max_cpu', 'analysis_timeout'].forEach(k => { data[k] = parseInt(data[k] || '0', 10); });
    data.thorough_analysis = fd.has('thorough_analysis');
    data.auto_start = fd.has('auto_start');
    await tryApi('/api/settings', { method: 'PUT', json: data });
    toast('Einstellungen gespeichert', 'ok');
    renderSettings();
  });
  $('#btn-install').addEventListener('click', async () => {
    await tryApi('/api/ghidra/install', { method: 'POST' });
    pollInstall();
  });
  $('#btn-open-ghidra').addEventListener('click', async () => {
    await tryApi('/api/ghidra/open', { method: 'POST' });
    toast('Ghidra wird gestartet…', 'ok');
  });
  if (inst.running) pollInstall();
}

function installState(inst) {
  if (!inst || (!inst.running && !inst.message)) return '';
  if (inst.error) return `<div class="banner err">${esc(inst.message)}: ${esc(inst.error)}</div>`;
  return `<div class="stack" style="gap:6px"><div class="row" style="font-size:12.5px">${inst.running ? '<span class="spinner"></span>' : ''}${esc(inst.message)}</div>
    <div class="progress"><div style="width:${(inst.progress * 100).toFixed(1)}%"></div></div></div>`;
}

function pollInstall() {
  const t = setInterval(async () => {
    const st = await api('/api/status').catch(() => null);
    if (!st) return;
    const box = $('#install-state');
    if (!box || S.route.view !== 'settings') { clearInterval(t); return; }
    box.innerHTML = installState(st.installer);
    if (!st.installer.running) { clearInterval(t); renderSettings(); }
  }, 1000);
}

// ------------------------------------------------------------------ polling

async function refreshProjectMeta() {
  if (!S.project) return;
  try { S.project = await api(`/api/projects/${S.project.id}`); } catch { return; }
  renderTabs();
}

let pollTimer = null;
function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(poll, 1500);
}

async function poll() {
  const r = S.route;
  if (!r) return;
  if (r.view === 'dashboard') {
    if (!S.projects.some(isBusy)) return;
    const projects = await api('/api/projects').catch(() => null);
    if (!projects || S.route.view !== 'dashboard') return;
    S.projects = projects;
    for (const p of projects) {
      const card = $(`.project-card[href="#/p/${CSS.escape(p.id)}"]`);
      if (card) card.outerHTML = projectCard(p);
    }
  } else if (r.view === 'project' && S.project && isBusy(S.project)) {
    const before = S.project;
    let meta;
    try { meta = await api(`/api/projects/${before.id}`); } catch { return; }
    if (S.route.view !== 'project' || S.route.id !== meta.id) return;
    S.project = meta;
    if (!isBusy(meta)) {
      // job finished -> reload everything
      if (meta.status === 'done') toast('Analyse abgeschlossen', 'ok');
      else if (meta.status === 'failed') toast('Job fehlgeschlagen – Details im Log', 'err', 8000);
      S.functions = null; S.data = {};
      await refreshStatus();
      render();
    } else {
      renderJobBanner();
    }
  }
}

// ------------------------------------------------------------------ boot

(async function boot() {
  await refreshStatus();
  await render();
  startPolling();
  setInterval(refreshStatus, 15000);
})();
