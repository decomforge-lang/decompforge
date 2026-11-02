const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const status = $('#status');
function setStatus(msg, kind = '') {
  status.textContent = msg;
  status.className = 'status' + (kind ? ' ' + kind : '');
}

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) {}
  return { ok: res.ok, status: res.status, text, json };
}

function showOut(el, text) {
  if (typeof el === 'string') el = $(el);
  el.textContent = text || '';
}

function setTab(name) {
  $$('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.panel').forEach(p => p.classList.toggle('active', p.id === name));
}

// ---------- Proyectos ----------
$('#btnListProj').addEventListener('click', async () => {
  const dir = $('#projDir').value || '.';
  const r = await api('/api/projects?dir=' + encodeURIComponent(dir));
  if (!r.ok) { showOut('#projOut', r.text); return; }
  showOut('#projOut', 'Directorio: ' + r.json.dir + '\\n' + (r.json.files.join('\\n') || '(sin .dfproj)'));
  const list = $('#projFiles');
  list.innerHTML = '';
  for (const f of r.json.files) {
    const chip = document.createElement('div');
    chip.className = 'chip';
    chip.textContent = f.split(/[\\/]/).pop();
    chip.title = f;
    chip.addEventListener('click', () => { $('#projPath').value = f; $('#anProj').value = f; $('#nfProj').value = f; $('#exProj').value = f; $('#apProj').value = f; $('#nfListFunc').value && 0; });
    list.appendChild(chip);
  }
});

$('#btnInit').addEventListener('click', async () => {
  const body = { name: $('#projName').value, platform: $('#projPlatform').value, dir: $('#projDir').value, sample: $('#projSample').checked };
  setStatus('creando proyecto…');
  const r = await api('/api/init', body);
  setStatus(r.ok ? 'proyecto creado' : 'error', r.ok ? 'ok' : 'err');
  showOut('#projOut', r.text + (r.json && r.json.stdout ? '\\n' + r.json.stdout : ''));
  if (r.json && r.json.info) $('#projPath').value = (r.json.project || $('#projPath').value);
});

// ---------- Análisis ----------
$('#btnDetect').addEventListener('click', async () => {
  const p = $('#binPath').value.trim();
  if (!p) { showOut('#anOut', 'indica una ruta'); return; }
  const r = await api('/api/detect?path=' + encodeURIComponent(p));
  if (!r.ok) { showOut('#anOut', r.text); return; }
  const d = r.json;
  const lines = [
    'Archivo: ' + d.path,
    'Tamaño: ' + d.size + ' bytes',
    'Formato: ' + d.format,
    'Arquitectura: ' + (d.arch || 'desconocida'),
    'Bits: ' + (d.bits || '?'),
    'Endianness: ' + (d.endian || '?'),
    'Plataforma probable: ' + (d.platform || 'desconocida'),
  ];
  if (d.notes && d.notes.length) lines.push('Avisos: ' + d.notes.join('; '));
  showOut('#anOut', lines.join('\\n'));
  $('#detectInfo').textContent = (d.platform || d.format || '?') + ' · ' + (d.arch || '?') + ' · ' + (d.bits ? d.bits + ' bits' : '');
});
  const body = { binary: $('#binPath').value, project: $('#anProj').value || $('#projPath').value, arch: $('#anArch').value || undefined, endian: $('#anEndian').value || undefined, base: $('#anBase').value || undefined };
  setStatus('cargando…');
  const r = await api('/api/load', body);
  setStatus(r.ok ? 'cargado' : 'error', r.ok ? 'ok' : 'err');
  showOut('#anOut', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

$('#btnAnalyze').addEventListener('click', async () => {
  const body = { binary: $('#binPath').value, project: $('#anProj').value || $('#projPath').value };
  setStatus('analizando…');
  const r = await api('/api/analyze', body);
  setStatus(r.ok ? 'analizado' : 'error', r.ok ? 'ok' : 'err');
  showOut('#anOut', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

$('#btnInfo').addEventListener('click', async () => {
  const body = { project: $('#anProj').value || $('#projPath').value };
  const r = await api('/api/info', body);
  if (r.json && r.json.info) {
    showOut('#anOut', JSON.stringify(r.json.info, null, 2));
  } else {
    showOut('#anOut', r.text);
  }
});

// ---------- NameForge ----------
function renderNameTable(rows) {
  const wrap = $('#nfTable');
  if (!rows || !rows.length) { wrap.innerHTML = '<p class="hint">sin propuestas</p>'; return; }
  let html = '<table><thead><tr><th>id</th><th>función</th><th>nombre</th><th>conf</th><th>estado</th><th>motivo</th></tr></thead><tbody>';
  for (const r of rows) {
    html += `<tr><td>${r.id}</td><td>0x${r.function.toString(16).padStart(8,'0')}</td><td>${r.name}</td><td>${r.confidence.toFixed(2)}</td><td>${r.state}</td><td>${r.reason}</td></tr>`;
  }
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

$('#btnName').addEventListener('click', async () => {
  const body = {
    binary: $('#nfBin').value,
    project: $('#nfProj').value || $('#projPath').value,
    config: $('#nfConfig').value || undefined,
    batch: $('#nfBatch').checked,
    limit: Number($('#nfLimit').value) || 0,
    function: $('#nfFunc').value || undefined,
    json: true,
  };
  setStatus('proponiendo nombres…');
  const r = await api('/api/name', body);
  setStatus(r.ok ? 'listo' : 'error', r.ok ? 'ok' : 'err');
  let text = r.json && r.json.stdout ? r.json.stdout : r.text;
  if (r.json && r.json.data) {
    text += '\\n\\n' + JSON.stringify(r.json.data, null, 2);
    if (r.json.data.records) renderNameTable(r.json.data.records);
  }
  if (r.json && r.json.stderr) text += '\\n' + r.json.stderr;
  showOut('#nfOut', text);
});

$('#btnNameList').addEventListener('click', async () => {
  const body = { project: $('#nfProj').value || $('#projPath').value, state: $('#nfState').value, function: $('#nfListFunc').value || undefined };
  const r = await api('/api/name-list', body);
  if (r.json && r.json.data) {
    renderNameTable(r.json.data);
    showOut('#nfOut', JSON.stringify(r.json.data, null, 2));
  } else {
    showOut('#nfOut', r.text);
  }
});

$('#btnNameAccept').addEventListener('click', async () => {
  const body = { id: Number($('#nfId').value), project: $('#nfProj').value || $('#projPath').value, force: $('#nfForce').checked };
  const r = await api('/api/name-accept', body);
  setStatus(r.ok ? 'aceptada' : 'error', r.ok ? 'ok' : 'err');
  showOut('#nfOut', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

$('#btnNameReject').addEventListener('click', async () => {
  const body = { id: Number($('#nfId').value), project: $('#nfProj').value || $('#projPath').value };
  const r = await api('/api/name-reject', body);
  setStatus(r.ok ? 'rechazada' : 'error', r.ok ? 'ok' : 'err');
  showOut('#nfOut', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

$('#btnNameConfig').addEventListener('click', async () => {
  const r = await api('/api/name-config', {});
  showOut('#nfOut', r.text);
});

// ---------- Exportar ----------
$('#btnExport').addEventListener('click', async () => {
  const body = { project: $('#exProj').value || $('#projPath').value, format: $('#exFmt').value, output: $('#exOut').value || undefined };
  const r = await api('/api/export', body);
  setStatus(r.ok ? 'exportado' : 'error', r.ok ? 'ok' : 'err');
  showOut('#exOutPre', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

$('#btnApply').addEventListener('click', async () => {
  const body = { file: $('#apFile').value, project: $('#apProj').value || $('#projPath').value };
  const r = await api('/api/apply', body);
  setStatus(r.ok ? 'aplicado' : 'error', r.ok ? 'ok' : 'err');
  showOut('#exOutPre', (r.json && r.json.stdout ? r.json.stdout : r.text) + (r.json && r.json.stderr ? '\\n' + r.json.stderr : ''));
});

// ---------- Config ----------
async function loadBinInfo() {
  const r = await api('/api/bin');
  if (r.ok) $('#cfgBin').textContent = r.json.bin;
}
loadBinInfo();

$('#cfgOut').textContent = 'Servidor Node activo. Usa las pestañas para operar.';

// ---------- Tabs ----------
$$('.tabs button').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));

// ---------- Sync inputs ----------
function syncProjectInputs(v) {
  if (!v) return;
  $('#projPath').value = v;
  $('#anProj').value = v;
  $('#nfProj').value = v;
  $('#exProj').value = v;
  $('#apProj').value = v;
}
$('#projPath').addEventListener('change', e => syncProjectInputs(e.target.value));