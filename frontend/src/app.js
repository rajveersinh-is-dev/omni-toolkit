// OMNI Frontend Client Application
const API_BASE = 'http://127.0.0.1:8080';

let operations = [];
let activeOperation = null;
let pipelineStages = [];
let ws = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupTheme();
  setupIOActions();
  setupPipelineActions();
  await loadOperations();
  connectWebSocket();
});

// Navigation
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
    });
  });
}

// Theme
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

// Load operations from API
async function loadOperations() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/operations`);
    if (res.ok) {
      operations = await res.json();
      renderCategoryTree(operations);
      updateStatus(true, `${operations.length} Operations Ready`);
      if (operations.length > 0) {
        selectOperation(operations[0].id);
      }
    } else {
      updateStatus(false, 'Backend Offline');
    }
  } catch (err) {
    console.warn('Backend not responding, using offline catalog.', err);
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

// Render category tree
function renderCategoryTree(ops) {
  const treeEl = document.getElementById('category-tree');
  treeEl.innerHTML = '';

  const groups = {};
  ops.forEach(op => {
    const cat = op.category || 'General';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(op);
  });

  for (const [catName, catOps] of Object.entries(groups)) {
    const catHeader = document.createElement('div');
    catHeader.className = 'category-item';
    catHeader.innerHTML = `<span>${catName}</span> <span class="badge">${catOps.length}</span>`;

    const sublist = document.createElement('div');
    sublist.className = 'op-sublist';

    catOps.forEach(op => {
      const opItem = document.createElement('div');
      opItem.className = 'op-item';
      opItem.setAttribute('data-id', op.id);
      opItem.textContent = op.name;
      opItem.addEventListener('click', () => selectOperation(op.id));
      sublist.appendChild(opItem);
    });

    treeEl.appendChild(catHeader);
    treeEl.appendChild(sublist);
  }
}

// Select active tool
function selectOperation(id) {
  activeOperation = operations.find(o => o.id === id);
  if (!activeOperation) return;

  document.querySelectorAll('.op-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-id') === id);
  });

  document.getElementById('op-name').textContent = activeOperation.name;
  document.getElementById('op-desc').textContent = activeOperation.description;

  const badgesEl = document.getElementById('op-badges');
  badgesEl.innerHTML = `
    <span class="badge safe">${activeOperation.security_level || 'Safe'}</span>
    <span class="badge">v${activeOperation.version || '0.1.0'}</span>
    <span class="badge">${(activeOperation.input_types || []).join(' / ')}</span>
  `;

  renderConfigForm(activeOperation);
}

function renderConfigForm(op) {
  const formEl = document.getElementById('config-form');
  formEl.innerHTML = '';

  if (op.id.startsWith('encode.')) {
    const div = document.createElement('div');
    div.className = 'form-group';
    div.innerHTML = `
      <label>Mode</label>
      <select id="cfg-mode">
        <option value="encode">Encode</option>
        <option value="decode">Decode</option>
      </select>
    `;
    formEl.appendChild(div);
  } else {
    formEl.innerHTML = '<span style="color:var(--text-muted);font-size:12px;">Standard default configuration</span>';
  }
}

// Input/Output Actions & Execution
function setupIOActions() {
  const runBtn = document.getElementById('run-btn');
  const inputArea = document.getElementById('input-textarea');
  const clearBtn = document.getElementById('clear-input');
  const copyBtn = document.getElementById('copy-output-btn');
  const fileInput = document.getElementById('file-input');

  runBtn.addEventListener('click', executeActiveTool);
  clearBtn.addEventListener('click', () => inputArea.value = '');

  copyBtn.addEventListener('click', () => {
    const text = document.getElementById('output-pre').textContent;
    navigator.clipboard.writeText(text);
    copyBtn.textContent = 'Copied!';
    setTimeout(() => copyBtn.textContent = 'Copy', 1500);
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (evt) => {
        inputArea.value = evt.target.result;
      };
      reader.readAsText(file);
    }
  });

  // Toggle Hex vs Text output
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
  const metricsEl = document.getElementById('exec-metrics');
  metricsEl.textContent = 'Running...';

  const cfgMode = document.getElementById('cfg-mode');
  const config = cfgMode ? { decode: cfgMode.value === 'decode' } : {};

  const start = performance.now();
  try {
    const res = await fetch(`${API_BASE}/api/v1/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        operation_id: activeOperation.id,
        input: {
          type: 'Text',
          data: inputVal
        },
        config
      })
    });

    const elapsed = Math.round(performance.now() - start);
    const json = await res.json();

    if (json.success && json.output) {
      const outData = json.output.data;
      displayOutput(outData);
      metricsEl.textContent = `Completed in ${elapsed} ms`;
    } else {
      document.getElementById('output-pre').textContent = `Execution Error:\n${json.error || 'Unknown error'}`;
      metricsEl.textContent = 'Failed';
    }
  } catch (err) {
    metricsEl.textContent = 'Error connecting to backend';
    document.getElementById('output-pre').textContent = err.toString();
  }
}

function displayOutput(data) {
  const preEl = document.getElementById('output-pre');
  const hexEl = document.getElementById('output-hex');

  let text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  preEl.textContent = text;

  // Generate Hex Dump
  hexEl.innerHTML = '';
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  let hexDump = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, '0');
    let hexParts = [];
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

// Pipeline Studio Actions
function setupPipelineActions() {
  const addBtn = document.getElementById('add-stage-btn');
  const listEl = document.getElementById('pipeline-stages-list');
  const runPipeBtn = document.getElementById('run-pipeline-btn');

  addBtn.addEventListener('click', () => {
    if (!activeOperation) return;
    pipelineStages.push({ ...activeOperation });
    renderPipelineStages();
  });

  runPipeBtn.addEventListener('click', async () => {
    if (pipelineStages.length === 0) {
      alert('Add at least one stage to the pipeline.');
      return;
    }

    const nodes = pipelineStages.map((op, idx) => ({
      id: `stage_${idx}`,
      operation_id: op.id,
      config: {}
    }));

    const edges = [];
    for (let i = 0; i < nodes.length - 1; i++) {
      edges.push({ from_node: nodes[i].id, to_node: nodes[i + 1].id });
    }

    const pipeline = {
      id: 'ui_pipeline',
      name: 'Interactive UI Pipeline',
      nodes,
      edges
    };

    const inputVal = document.getElementById('input-textarea').value;
    try {
      const res = await fetch(`${API_BASE}/api/v1/pipelines/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pipeline,
          input: { type: 'Text', data: inputVal }
        })
      });

      const json = await res.json();
      if (json.success) {
        alert('Pipeline execution succeeded! Check Job Monitor for artifacts.');
      } else {
        alert(`Pipeline failed: ${json.error}`);
      }
    } catch (e) {
      alert(`Pipeline error: ${e}`);
    }
  });
}

function renderPipelineStages() {
  const listEl = document.getElementById('pipeline-stages-list');
  listEl.innerHTML = '';
  pipelineStages.forEach((op, i) => {
    const item = document.createElement('div');
    item.className = 'op-item active';
    item.textContent = `${i + 1}. ${op.name} (${op.id})`;
    listEl.appendChild(item);
  });
}

// WebSocket job progress streaming
function connectWebSocket() {
  try {
    ws = new WebSocket(`ws://127.0.0.1:8080/api/v1/ws/jobs`);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        console.log('WS Event:', data);
        handleJobEvent(data);
      } catch (e) {
        console.error('Error parsing WS event', e);
      }
    };
  } catch (e) {
    console.warn('WebSocket connection not available');
  }
}

function handleJobEvent(event) {
  const tbody = document.getElementById('jobs-tbody');
  if (!tbody) return;

  const row = document.createElement('tr');
  if (event.Completed) {
    const { job_id, duration_ms, output_preview } = event.Completed;
    row.innerHTML = `
      <td><code>${job_id.substring(0, 8)}...</code></td>
      <td>Completed</td>
      <td><span class="badge safe">Success</span></td>
      <td>Just now</td>
      <td>${duration_ms} ms</td>
      <td>${output_preview}</td>
    `;
    tbody.prepend(row);
  }
}
