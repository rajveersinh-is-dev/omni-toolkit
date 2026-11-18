// OMNI Frontend Client Application (Local-First, XSS-Safe, Full Backend Integration)
const urlParams = new URLSearchParams(window.location.search);
let apiBase = (window.location.origin && window.location.origin.startsWith('http'))
  ? window.location.origin
  : 'http://127.0.0.1:8080';
let authToken = urlParams.get('token') || '';

// Remove token from address bar if passed via query string
if (urlParams.has('token') && window.history && window.history.replaceState) {
  const cleanUrl = `${window.location.pathname}${window.location.hash}`;
  window.history.replaceState({}, document.title, cleanUrl);
}

let operations = [];
let activeOperation = null;
let pipelineStages = [];
let lastOutputText = '';
let activeAbortController = null;
let ws = null;

function authHeaders(extra = {}) {
  const headers = { ...extra };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  return headers;
}

document.addEventListener('DOMContentLoaded', async () => {
  const epInput = document.getElementById('settings-endpoint');
  const tokInput = document.getElementById('settings-token');
  if (epInput) epInput.value = apiBase;
  if (tokInput) tokInput.value = authToken;

  setupNavigation();
  setupTheme();
  setupSidebarFilter();
  setupCommandPalette();
  setupIOActions();
  setupPipelineActions();
  setupSettingsActions();
  setupJobsActions();

  await refreshAll();
});

async function refreshAll() {
  await loadOperations();
  await loadJobHistory();
  await loadSavedPipelines();
  connectWebSocket();
}

function setupNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const view = tab.getAttribute('data-view');
      document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
      const activePanel = document.getElementById(`view-${view}`);
      if (activePanel) activePanel.classList.add('active');

      if (view === 'jobs') loadJobHistory();
      if (view === 'pipeline') loadSavedPipelines();
    });
  });
}

function setupTheme() {
  const toggleBtn = document.getElementById('theme-toggle');
  toggleBtn.addEventListener('click', () => {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    toggleBtn.innerHTML = newTheme === 'dark' ? '&#9790;' : '&#9788;';
  });
}

function setupSidebarFilter() {
  const filterInput = document.getElementById('op-filter');
  if (!filterInput) return;
  filterInput.addEventListener('input', () => {
    const q = filterInput.value.trim().toLowerCase();
    if (!q) {
      renderCategoryTree(operations);
      return;
    }
    const filtered = operations.filter(op =>
      op.id.toLowerCase().includes(q) ||
      op.name.toLowerCase().includes(q) ||
      (op.description || '').toLowerCase().includes(q) ||
      (op.category || '').toLowerCase().includes(q)
    );
    renderCategoryTree(filtered);
  });
}

function setupCommandPalette() {
  const modal = document.getElementById('cmd-modal');
  const trigger = document.getElementById('cmd-trigger');
  const backdrop = document.getElementById('cmd-backdrop');
  const input = document.getElementById('cmd-input');
  const results = document.getElementById('cmd-results');

  function openPalette() {
    modal.style.display = 'flex';
    input.value = '';
    renderPaletteResults('');
    input.focus();
  }

  function closePalette() {
    modal.style.display = 'none';
  }

  function renderPaletteResults(query) {
    results.textContent = '';
    const q = query.trim().toLowerCase();
    const matches = operations
      .filter(op => !q || op.id.toLowerCase().includes(q) || op.name.toLowerCase().includes(q) || (op.category || '').toLowerCase().includes(q))
      .slice(0, 25);

    if (matches.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'cmd-result-item';
      empty.textContent = 'No matching operations found.';
      results.appendChild(empty);
      return;
    }

    matches.forEach(op => {
      const item = document.createElement('div');
      item.className = 'cmd-result-item';

      const left = document.createElement('span');
      left.textContent = `${op.name} (${op.id})`;

      const badge = document.createElement('span');
      badge.className = `badge status-${op.status || 'implemented'}`;
      badge.textContent = op.status || 'implemented';

      item.appendChild(left);
      item.appendChild(badge);
      item.addEventListener('click', () => {
        selectOperation(op.id);
        closePalette();
      });
      results.appendChild(item);
    });
  }

  trigger.addEventListener('click', openPalette);
  backdrop.addEventListener('click', closePalette);
  input.addEventListener('input', () => renderPaletteResults(input.value));

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (modal.style.display === 'none') openPalette();
      else closePalette();
    } else if (e.key === 'Escape' && modal.style.display !== 'none') {
      closePalette();
    }
  });
}

async function loadOperations() {
  try {
    const res = await fetch(`${apiBase}/api/v1/operations`, { headers: authHeaders() });
    if (res.ok) {
      operations = await res.json();
      renderCategoryTree(operations);
      updateStatus(true, `Connected (${operations.length} Ops)`);
      if (operations.length > 0 && !activeOperation) {
        selectOperation(operations[0].id);
      }
    } else if (res.status === 401) {
      updateStatus(false, 'Auth Token Required');
    } else {
      updateStatus(false, `Backend Error (${res.status})`);
    }
  } catch (err) {
    console.warn('Backend not responding:', err);
    updateStatus(false, 'Disconnected');
  }
}

function updateStatus(online, text) {
  const pill = document.getElementById('status-pill');
  if (pill) {
    pill.className = `status-indicator ${online ? 'online' : 'offline'}`;
    pill.querySelector('.status-text').textContent = text;
  }
}

function renderCategoryTree(ops) {
  const treeEl = document.getElementById('category-tree');
  treeEl.textContent = '';

  const groups = {};
  ops.forEach(op => {
    const cat = op.category || 'General';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(op);
  });

  for (const [catName, catOps] of Object.entries(groups)) {
    const catHeader = document.createElement('div');
    catHeader.className = 'category-item';
    const nameSpan = document.createElement('span');
    nameSpan.textContent = catName;
    const countSpan = document.createElement('span');
    countSpan.className = 'badge';
    countSpan.textContent = String(catOps.length);
    catHeader.appendChild(nameSpan);
    catHeader.appendChild(countSpan);

    const sublist = document.createElement('div');
    sublist.className = 'op-sublist';

    catOps.forEach(op => {
      const opItem = document.createElement('div');
      opItem.className = 'op-item';
      if (activeOperation && activeOperation.id === op.id) opItem.classList.add('active');
      opItem.setAttribute('data-id', op.id);
      opItem.textContent = op.name;
      opItem.addEventListener('click', () => selectOperation(op.id));
      sublist.appendChild(opItem);
    });

    treeEl.appendChild(catHeader);
    treeEl.appendChild(sublist);
  }
}

function selectOperation(id) {
  activeOperation = operations.find(o => o.id === id);
  if (!activeOperation) return;

  document.querySelectorAll('.op-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-id') === id);
  });

  document.getElementById('op-name').textContent = `${activeOperation.name} (${activeOperation.id})`;
  document.getElementById('op-desc').textContent = activeOperation.description;

  const badgesEl = document.getElementById('op-badges');
  badgesEl.textContent = '';

  const statusVal = activeOperation.status || 'implemented';
  const statusBadge = document.createElement('span');
  statusBadge.className = `badge status-${statusVal}`;
  statusBadge.textContent = statusVal;
  badgesEl.appendChild(statusBadge);

  const secBadge = document.createElement('span');
  secBadge.className = 'badge safe';
  secBadge.textContent = activeOperation.security_level || 'Safe';
  badgesEl.appendChild(secBadge);

  const typesBadge = document.createElement('span');
  typesBadge.className = 'badge';
  typesBadge.textContent = `${(activeOperation.input_types || []).join('/')} -> ${(activeOperation.output_types || []).join('/')}`;
  badgesEl.appendChild(typesBadge);

  const limEl = document.getElementById('op-limitations');
  limEl.textContent = '';
  if (activeOperation.limitations && activeOperation.limitations.length > 0) {
    limEl.style.display = 'block';
    const strong = document.createElement('strong');
    strong.textContent = 'Notes & Limitations: ';
    limEl.appendChild(strong);
    limEl.appendChild(document.createTextNode(activeOperation.limitations.join(' • ')));
  } else {
    limEl.style.display = 'none';
  }

  renderConfigForm(activeOperation);
}

function renderConfigForm(op) {
  const formEl = document.getElementById('config-form');
  formEl.textContent = '';

  if (op.id.startsWith('encode.')) {
    const div = document.createElement('div');
    div.className = 'form-group';
    const lbl = document.createElement('label');
    lbl.textContent = 'Mode';
    const sel = document.createElement('select');
    sel.id = 'cfg-mode';
    const optEnc = document.createElement('option');
    optEnc.value = 'encode';
    optEnc.textContent = 'Encode';
    const optDec = document.createElement('option');
    optDec.value = 'decode';
    optDec.textContent = 'Decode';
    sel.appendChild(optEnc);
    sel.appendChild(optDec);
    div.appendChild(lbl);
    div.appendChild(sel);
    formEl.appendChild(div);
  }

  const jsonDiv = document.createElement('div');
  jsonDiv.className = 'form-group';
  jsonDiv.style.flex = '1';
  const lbl = document.createElement('label');
  lbl.textContent = 'JSON Config (optional)';
  const cfgInput = document.createElement('input');
  cfgInput.type = 'text';
  cfgInput.id = 'cfg-json-raw';
  cfgInput.className = 'input-field';
  cfgInput.placeholder = '{}';
  cfgInput.value = '{}';
  jsonDiv.appendChild(lbl);
  jsonDiv.appendChild(cfgInput);
  formEl.appendChild(jsonDiv);
}

function hexToBytes(hexStr) {
  const clean = hexStr.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex input: must have even number of hex characters');
  }
  const arr = [];
  for (let i = 0; i < clean.length; i += 2) {
    arr.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return arr;
}

function setupIOActions() {
  const runBtn = document.getElementById('run-btn');
  const cancelBtn = document.getElementById('cancel-run-btn');
  const inputArea = document.getElementById('input-textarea');
  const clearBtn = document.getElementById('clear-input');
  const copyBtn = document.getElementById('copy-output-btn');
  const downloadBtn = document.getElementById('download-output-btn');
  const fileInput = document.getElementById('file-input');
  const dropZone = document.getElementById('drop-zone');

  runBtn.addEventListener('click', executeActiveTool);
  cancelBtn.addEventListener('click', () => {
    if (activeAbortController) {
      activeAbortController.abort();
      activeAbortController = null;
    }
  });
  clearBtn.addEventListener('click', () => { inputArea.value = ''; });

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(lastOutputText || document.getElementById('output-pre').textContent);
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    } catch {
      copyBtn.textContent = 'Copy Failed';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    }
  });

  downloadBtn.addEventListener('click', () => {
    const content = lastOutputText || document.getElementById('output-pre').textContent;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeOperation ? activeOperation.id : 'omni_output'}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  function loadFileObject(file) {
    if (!file) return;
    const mode = document.getElementById('input-mode').value;
    const reader = new FileReader();
    if (mode === 'hex') {
      reader.onload = (evt) => {
        const bytes = new Uint8Array(evt.target.result);
        inputArea.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      };
      reader.readAsArrayBuffer(file);
    } else {
      reader.onload = (evt) => { inputArea.value = evt.target.result; };
      reader.readAsText(file);
    }
  }

  fileInput.addEventListener('change', (e) => loadFileObject(e.target.files[0]));

  // Drag-and-drop support
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
      loadFileObject(e.dataTransfer.files[0]);
    }
  });

  const viewTextBtn = document.getElementById('view-text-btn');
  const viewHexBtn = document.getElementById('view-hex-btn');
  const preEl = document.getElementById('output-pre');
  const hexEl = document.getElementById('output-hex');

  viewTextBtn.addEventListener('click', () => {
    viewTextBtn.classList.add('active');
    viewHexBtn.classList.remove('active');
    preEl.style.display = 'block';
    hexEl.style.display = 'none';
  });

  viewHexBtn.addEventListener('click', () => {
    viewHexBtn.classList.add('active');
    viewTextBtn.classList.remove('active');
    preEl.style.display = 'none';
    hexEl.style.display = 'grid';
  });
}

async function executeActiveTool() {
  if (!activeOperation) return;

  const inputVal = document.getElementById('input-textarea').value;
  const inputMode = document.getElementById('input-mode').value;
  const metricsEl = document.getElementById('exec-metrics');
  const cancelBtn = document.getElementById('cancel-run-btn');

  let config = {};
  const rawCfgEl = document.getElementById('cfg-json-raw');
  if (rawCfgEl && rawCfgEl.value.trim()) {
    try {
      config = JSON.parse(rawCfgEl.value);
    } catch (e) {
      document.getElementById('output-pre').textContent = `Invalid JSON Config:\n${e.message}`;
      metricsEl.textContent = 'Config Error';
      return;
    }
  }
  const cfgMode = document.getElementById('cfg-mode');
  if (cfgMode) {
    config.decode = cfgMode.value === 'decode';
  }

  let payload;
  try {
    payload = inputMode === 'hex'
      ? { type: 'Bytes', data: hexToBytes(inputVal) }
      : { type: 'Text', data: inputVal };
  } catch (e) {
    document.getElementById('output-pre').textContent = e.message;
    metricsEl.textContent = 'Input Error';
    return;
  }

  activeAbortController = new AbortController();
  cancelBtn.style.display = 'inline-block';
  metricsEl.textContent = 'Running...';

  const start = performance.now();
  try {
    const res = await fetch(`${apiBase}/api/v1/execute`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      signal: activeAbortController.signal,
      body: JSON.stringify({
        operation_id: activeOperation.id,
        input: payload,
        config
      })
    });

    const elapsed = Math.round(performance.now() - start);
    const json = await res.json();

    if (json.success && json.output) {
      displayOutput(json.output);
      metricsEl.textContent = `Completed in ${elapsed} ms`;
    } else {
      lastOutputText = `Execution Error:\n${json.error || 'Unknown error'}`;
      document.getElementById('output-pre').textContent = lastOutputText;
      metricsEl.textContent = 'Failed';
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      metricsEl.textContent = 'Cancelled';
      document.getElementById('output-pre').textContent = 'Request cancelled by user.';
    } else {
      metricsEl.textContent = 'Backend connection error';
      document.getElementById('output-pre').textContent = String(err);
    }
  } finally {
    cancelBtn.style.display = 'none';
    activeAbortController = null;
  }
}

function displayOutput(output) {
  const preEl = document.getElementById('output-pre');
  const hexEl = document.getElementById('output-hex');

  const isBytes = output && output.type === 'Bytes' && Array.isArray(output.data);
  const data = output && typeof output === 'object' && 'data' in output ? output.data : output;

  let text;
  let bytes;
  if (isBytes) {
    bytes = new Uint8Array(data);
    text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } else {
    text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    bytes = new TextEncoder().encode(text);
  }
  lastOutputText = text;
  preEl.textContent = text;

  hexEl.textContent = '';
  let hexDump = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, '0');
    const hexParts = [];
    let asciiParts = '';

    for (let j = 0; j < 16; j++) {
      if (j < chunk.length) {
        hexParts.push(chunk[j].toString(16).padStart(2, '0'));
        asciiParts += (chunk[j] >= 32 && chunk[j] <= 126) ? String.fromCharCode(chunk[j]) : '.';
      } else {
        hexParts.push('  ');
      }
    }
    hexDump += `${offset}  ${hexParts.join(' ')}  |${asciiParts}|\n`;
  }
  hexEl.textContent = hexDump;
}

function buildCurrentPipelineDefinition() {
  const nameInput = document.getElementById('pipeline-name-input');
  const name = (nameInput && nameInput.value.trim()) || 'Interactive Pipeline';
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'ui_pipeline';
  const nodes = pipelineStages.map((op, idx) => ({
    id: `stage_${idx}`,
    operation_id: op.id,
    config: {}
  }));
  const edges = [];
  for (let i = 0; i < nodes.length - 1; i++) {
    edges.push({ from_node: nodes[i].id, to_node: nodes[i + 1].id });
  }
  return { id, name, description: 'Created in OMNI Pipeline Studio', nodes, edges };
}

function setupPipelineActions() {
  const addBtn = document.getElementById('add-stage-btn');
  const runPipeBtn = document.getElementById('run-pipeline-btn');
  const valPipeBtn = document.getElementById('validate-pipeline-btn');
  const savePipeBtn = document.getElementById('save-pipeline-btn');
  const exportPipeBtn = document.getElementById('export-pipeline-btn');
  const outPre = document.getElementById('pipeline-output-pre');

  addBtn.addEventListener('click', () => {
    if (!activeOperation) return;
    pipelineStages.push({ ...activeOperation });
    renderPipelineStages();
  });

  valPipeBtn.addEventListener('click', async () => {
    const pipeline = buildCurrentPipelineDefinition();
    const res = await fetch(`${apiBase}/api/v1/pipelines/validate`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(pipeline)
    });
    const json = await res.json();
    outPre.textContent = JSON.stringify(json, null, 2);
  });

  savePipeBtn.addEventListener('click', async () => {
    if (pipelineStages.length === 0) {
      outPre.textContent = 'Add at least one stage before saving.';
      return;
    }
    const pipeline = buildCurrentPipelineDefinition();
    const res = await fetch(`${apiBase}/api/v1/pipelines`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(pipeline)
    });
    const json = await res.json();
    outPre.textContent = JSON.stringify(json, null, 2);
    await loadSavedPipelines();
  });

  exportPipeBtn.addEventListener('click', () => {
    const pipeline = buildCurrentPipelineDefinition();
    const blob = new Blob([JSON.stringify(pipeline, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${pipeline.id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  runPipeBtn.addEventListener('click', async () => {
    if (pipelineStages.length === 0) {
      outPre.textContent = 'Add at least one stage to the pipeline first.';
      return;
    }
    const pipeline = buildCurrentPipelineDefinition();
    const inputVal = document.getElementById('input-textarea').value;
    outPre.textContent = 'Executing pipeline DAG...';

    try {
      const res = await fetch(`${apiBase}/api/v1/pipelines/execute`, {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
          pipeline,
          input: { type: 'Text', data: inputVal }
        })
      });
      const json = await res.json();
      outPre.textContent = JSON.stringify(json, null, 2);
      await loadJobHistory();
    } catch (e) {
      outPre.textContent = `Pipeline error: ${e}`;
    }
  });
}

function renderPipelineStages() {
  const listEl = document.getElementById('pipeline-stages-list');
  const graphEl = document.getElementById('pipeline-graph');
  listEl.textContent = '';
  graphEl.textContent = '';

  pipelineStages.forEach((op, i) => {
    const item = document.createElement('div');
    item.className = 'op-item active';
    item.style.display = 'flex';
    item.style.justifyContent = 'space-between';
    item.style.alignItems = 'center';

    const label = document.createElement('span');
    label.textContent = `${i + 1}. ${op.name} (${op.id})`;

    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn-sm';
    removeBtn.textContent = 'x';
    removeBtn.addEventListener('click', () => {
      pipelineStages.splice(i, 1);
      renderPipelineStages();
    });

    item.appendChild(label);
    item.appendChild(removeBtn);
    listEl.appendChild(item);

    // Visual graph node
    const nodeBox = document.createElement('div');
    nodeBox.className = 'pipeline-node-card';
    nodeBox.textContent = `Stage ${i + 1}: ${op.id}`;
    graphEl.appendChild(nodeBox);

    if (i < pipelineStages.length - 1) {
      const arrow = document.createElement('div');
      arrow.className = 'pipeline-arrow';
      arrow.textContent = '→';
      graphEl.appendChild(arrow);
    }
  });
}

async function loadSavedPipelines() {
  const listEl = document.getElementById('saved-pipelines-list');
  if (!listEl) return;
  try {
    const res = await fetch(`${apiBase}/api/v1/pipelines`, { headers: authHeaders() });
    if (!res.ok) return;
    const saved = await res.json();
    listEl.textContent = '';
    if (saved.length === 0) {
      const p = document.createElement('div');
      p.style.fontSize = '12px';
      p.style.color = 'var(--text-muted)';
      p.textContent = 'No saved pipelines yet.';
      listEl.appendChild(p);
      return;
    }
    saved.forEach(p => {
      const row = document.createElement('div');
      row.className = 'op-item';
      row.textContent = p.name;
      row.addEventListener('click', async () => {
        const detailRes = await fetch(`${apiBase}/api/v1/pipelines/${encodeURIComponent(p.id)}`, { headers: authHeaders() });
        if (detailRes.ok) {
          const def = await detailRes.json();
          document.getElementById('pipeline-name-input').value = def.name;
          pipelineStages = (def.nodes || []).map(n => {
            const found = operations.find(o => o.id === n.operation_id);
            return found || { id: n.operation_id, name: n.operation_id };
          });
          renderPipelineStages();
        }
      });
      listEl.appendChild(row);
    });
  } catch {
    // offline
  }
}

function setupJobsActions() {
  const refreshBtn = document.getElementById('refresh-jobs-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadJobHistory);
}

async function loadJobHistory() {
  const tbody = document.getElementById('jobs-tbody');
  if (!tbody) return;
  try {
    const res = await fetch(`${apiBase}/api/v1/jobs?limit=50`, { headers: authHeaders() });
    if (!res.ok) return;
    const jobs = await res.json();
    tbody.textContent = '';
    if (jobs.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.textContent = 'No jobs recorded yet.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    jobs.forEach(job => {
      tbody.appendChild(buildJobRow(job));
    });
  } catch {
    // offline
  }
}

function buildJobRow(job) {
  const tr = document.createElement('tr');

  const tdId = document.createElement('td');
  const code = document.createElement('code');
  code.textContent = `${(job.id || '').substring(0, 8)}...`;
  tdId.appendChild(code);

  const tdOp = document.createElement('td');
  tdOp.textContent = job.operation_or_pipeline_id || '';

  const tdStatus = document.createElement('td');
  const badge = document.createElement('span');
  badge.className = `badge status-${job.status || 'unknown'}`;
  badge.textContent = job.status || 'unknown';
  tdStatus.appendChild(badge);

  const tdCreated = document.createElement('td');
  tdCreated.textContent = job.created_at || '';

  const tdDur = document.createElement('td');
  tdDur.textContent = job.duration_ms != null ? `${job.duration_ms} ms` : '—';

  const tdAction = document.createElement('td');
  if (job.status === 'running' || job.status === 'queued') {
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn-sm';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', async () => {
      await fetch(`${apiBase}/api/v1/jobs/${encodeURIComponent(job.id)}`, {
        method: 'DELETE',
        headers: authHeaders()
      });
      await loadJobHistory();
    });
    tdAction.appendChild(cancelBtn);
  } else {
    tdAction.textContent = job.error_message || 'OK';
  }

  tr.append(tdId, tdOp, tdStatus, tdCreated, tdDur, tdAction);
  return tr;
}

function setupSettingsActions() {
  const saveBtn = document.getElementById('save-settings-btn');
  const statusEl = document.getElementById('settings-status');
  if (!saveBtn) return;

  saveBtn.addEventListener('click', async () => {
    const ep = document.getElementById('settings-endpoint').value.trim().replace(/\/+$/, '');
    const tok = document.getElementById('settings-token').value.trim();
    if (ep) apiBase = ep;
    authToken = tok;
    statusEl.textContent = 'Reconnecting...';
    await refreshAll();
    statusEl.textContent = 'Settings applied.';
  });
}

function connectWebSocket() {
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }
  try {
    const wsBase = apiBase.replace(/^http/, 'ws');
    const qs = authToken ? `?token=${encodeURIComponent(authToken)}` : '';
    ws = new WebSocket(`${wsBase}/api/v1/ws/jobs${qs}`);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleJobEvent(data);
      } catch (e) {
        console.error('Error parsing WS event', e);
      }
    };
  } catch {
    // WebSocket unavailable
  }
}

function handleJobEvent(event) {
  const tbody = document.getElementById('jobs-tbody');
  if (!tbody) return;
  if (event.Completed || event.Failed || event.TimedOut || event.Cancelled) {
    loadJobHistory();
  }
}
