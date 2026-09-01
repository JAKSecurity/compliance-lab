// Compliance Lab — Web Dashboard
// Rendering engine + replay controller + containment modal + live WebSocket mode

// ── State ──
let snapshots = [];
let currentStep = 0;
let playing = false;
let playTimer = null;
const PLAY_INTERVAL = 2000; // ms between auto-steps

// ── Live mode state ──
let mode = 'static';  // 'static' or 'live'
let ws = null;
let liveRunning = false;

// ── DAG node definitions (matches workflow.py graph) ──
const DAG_NODES = [
  { id: 'load_target',          label: 'Load Target' },
  { id: 'check_phase',          label: 'Control Check' },
  { id: 'report_phase',         label: 'Report Generation' },
  { id: 'containment_phase',    label: 'Containment Gate' },
  { id: 'execute_containment',  label: 'Execute Containment' },
];

// ── Agent display config ──
const AGENTS = {
  validator: { name: 'Validator', css: 'validator', perm: 'control_check',       key: 'a4f2...e8c1' },
  reporter:  { name: 'Reporter',  css: 'reporter',  perm: 'generate_report',     key: 'b7d3...f4a2' },
  human:     { name: 'Human',     css: 'human',     perm: 'approve_containment', key: 'c9e1...d6b3' },
};

// ── DOM refs ──
const $dagNodes      = document.getElementById('dag-nodes');
const $center        = document.getElementById('center-panel');
const $auditEntries  = document.getElementById('audit-entries');
const $agentBar      = document.getElementById('agent-bar');
const $pathSelect    = document.getElementById('path-select');
const $btnPrev       = document.getElementById('btn-prev');
const $btnPlay       = document.getElementById('btn-play');
const $btnNext       = document.getElementById('btn-next');
const $stepLabel     = document.getElementById('step-label');
const $modalOverlay  = document.getElementById('modal-overlay');
const $modalBody     = document.getElementById('modal-body');
const $btnApprove    = document.getElementById('btn-approve');
const $btnDeny       = document.getElementById('btn-deny');
const $connStatus    = document.getElementById('connection-status');

// ── Init ──
async function init() {
  renderAgents();
  renderDAG(null, []);
  bindControls();
  await tryWebSocket();
  await loadPath($pathSelect.value);
}

// ── WebSocket connection ──
async function tryWebSocket() {
  return new Promise((resolve) => {
    try {
      const url = `ws://${window.location.host}/ws`;
      const testWs = new WebSocket(url);
      const timeout = setTimeout(() => {
        testWs.close();
        setStaticMode();
        resolve();
      }, 2000);

      testWs.onopen = () => {
        clearTimeout(timeout);
        testWs.close();
        // Server supports WebSocket — enable live mode option
        enableLiveOption();
        resolve();
      };

      testWs.onerror = () => {
        clearTimeout(timeout);
        setStaticMode();
        resolve();
      };
    } catch {
      setStaticMode();
      resolve();
    }
  });
}

function enableLiveOption() {
  // Add "Live Run" option to path selector
  const opt = document.createElement('option');
  opt.value = 'live';
  opt.textContent = 'Live Run (Ollama)';
  $pathSelect.appendChild(opt);
}

function setStaticMode() {
  mode = 'static';
  $connStatus.textContent = 'Static Replay';
  $connStatus.className = 'badge pending';
}

function setLiveMode() {
  mode = 'live';
  $connStatus.textContent = 'Live';
  $connStatus.className = 'badge allowed';
}

// ── Data loading ──
async function loadPath(name) {
  stopPlay();
  currentStep = 0;

  if (name === 'live') {
    // Switch to live mode — don't load static data, wait for Play
    setLiveMode();
    snapshots = [];
    updateStepLabel();
    renderDAG(null, []);
    renderAudit([]);
    $center.innerHTML = '<div class="empty-state">Press Play to start a live run against Ollama.</div>';
    return;
  }

  setStaticMode();
  try {
    const resp = await fetch(`data/${name}.json`);
    snapshots = await resp.json();
  } catch (e) {
    snapshots = [];
    $center.innerHTML = '<div class="empty-state">Failed to load data file.</div>';
  }
  updateStepLabel();
  if (snapshots.length > 0) {
    renderSnapshot(snapshots[0]);
  }
}

// ── Controls ──
function bindControls() {
  $pathSelect.addEventListener('change', () => loadPath($pathSelect.value));
  $btnPrev.addEventListener('click', stepPrev);
  $btnNext.addEventListener('click', stepNext);
  $btnPlay.addEventListener('click', togglePlay);
  $btnApprove.addEventListener('click', () => handleContainmentDecision(true));
  $btnDeny.addEventListener('click', () => handleContainmentDecision(false));

  document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft')  stepPrev();
    if (e.key === 'ArrowRight') stepNext();
    if (e.key === ' ') { e.preventDefault(); togglePlay(); }
  });
}

function stepNext() {
  if (currentStep < snapshots.length - 1) {
    // If current snapshot is containment awaiting approval, show modal instead of advancing
    const snap = snapshots[currentStep];
    if (snap.workflow_state?.awaiting_human_approval && !$modalOverlay.classList.contains('visible')) {
      showContainmentModal(snap);
      return;
    }
    currentStep++;
    renderSnapshot(snapshots[currentStep]);
    updateStepLabel();
  } else {
    stopPlay();
  }
}

function stepPrev() {
  if (currentStep > 0) {
    currentStep--;
    hideContainmentModal();
    renderSnapshot(snapshots[currentStep]);
    updateStepLabel();
  }
}

function togglePlay() {
  if (mode === 'live' && !liveRunning) {
    startLiveRun();
    return;
  }
  if (playing) {
    stopPlay();
  } else {
    startPlay();
  }
}

function startPlay() {
  playing = true;
  $btnPlay.textContent = 'Pause';
  $btnPlay.classList.add('active');
  playTimer = setInterval(() => {
    // Pause on containment modal
    const snap = snapshots[currentStep];
    if (snap.workflow_state?.awaiting_human_approval) {
      if (!$modalOverlay.classList.contains('visible')) {
        showContainmentModal(snap);
      }
      stopPlay();
      return;
    }
    stepNext();
  }, PLAY_INTERVAL);
}

function stopPlay() {
  playing = false;
  $btnPlay.textContent = 'Play';
  $btnPlay.classList.remove('active');
  if (playTimer) {
    clearInterval(playTimer);
    playTimer = null;
  }
}

function updateStepLabel() {
  const total = snapshots.length || 0;
  const current = total > 0 ? currentStep + 1 : 0;
  $stepLabel.textContent = `${current} / ${total}`;
}

// ── Live mode ──
function startLiveRun() {
  if (liveRunning) return;

  snapshots = [];
  currentStep = 0;
  liveRunning = true;
  $btnPlay.textContent = 'Running...';
  $btnPlay.classList.add('active');
  $pathSelect.disabled = true;

  renderDAG(null, []);
  renderAudit([]);
  $center.innerHTML = '<div class="empty-state">Connecting to server...</div>';

  const url = `ws://${window.location.host}/ws`;
  ws = new WebSocket(url);

  ws.onopen = () => {
    $center.innerHTML = '<div class="empty-state">Starting workflow...</div>';
    ws.send(JSON.stringify({
      action: 'start',
      control_id: 'IA-5(1)',
      target_id: 'synth-web-001',
    }));
  };

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    handleLiveMessage(msg);
  };

  ws.onerror = () => {
    $center.innerHTML = '<div class="empty-state" style="color: var(--red);">WebSocket error. Is Ollama running?</div>';
    endLiveRun();
  };

  ws.onclose = () => {
    endLiveRun();
  };
}

function endLiveRun() {
  liveRunning = false;
  ws = null;
  $btnPlay.textContent = 'Play';
  $btnPlay.classList.remove('active');
  $pathSelect.disabled = false;
  updateStepLabel();
}

function handleLiveMessage(msg) {
  switch (msg.type) {
    case 'agents':
      // Update agent keys with real values from server
      for (const [id, info] of Object.entries(msg.agents)) {
        if (AGENTS[id]) {
          AGENTS[id].key = info.key;
        }
      }
      renderAgents();
      break;

    case 'status':
      $center.innerHTML = `<div class="empty-state">${msg.message}</div>`;
      break;

    case 'snapshot':
      snapshots.push(msg.snapshot);
      currentStep = snapshots.length - 1;
      renderSnapshot(msg.snapshot);
      updateStepLabel();
      break;

    case 'containment_proposal':
      // Server is waiting for our decision — show modal
      showLiveContainmentModal(msg.proposal);
      break;

    case 'complete':
      endLiveRun();
      break;

    case 'error':
      $center.innerHTML = `<div class="empty-state" style="color: var(--red);">Error: ${msg.message}</div>`;
      endLiveRun();
      break;
  }
}

function showLiveContainmentModal(proposal) {
  $modalBody.innerHTML = `
    <div class="modal-field">
      <span class="modal-field-label">Control</span>
      ${proposal.control_id}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Target</span>
      ${proposal.target_id}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Finding</span>
      <span class="badge fail">${proposal.finding}</span>
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Containment Action</span>
      ${proposal.containment_action}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Justification</span>
      ${proposal.containment_justification}
    </div>`;
  $modalOverlay.classList.add('visible');
}

// ── Render: full snapshot ──
function renderSnapshot(snap) {
  const completedNodes = getCompletedNodes(snap);
  renderDAG(snap.active_node, completedNodes);
  renderCenter(snap);
  renderAudit(snap.audit_entries || []);
}

function getCompletedNodes(snap) {
  const all = DAG_NODES.map(n => n.id);
  const activeIdx = all.indexOf(snap.active_node);
  if (activeIdx < 0 && snap.phase === 'complete') return all;
  if (activeIdx < 0) return [];
  return all.slice(0, activeIdx);
}

// ── Render: DAG ──
function renderDAG(activeNode, completedNodes) {
  const isComplete = activeNode === null && completedNodes.length === DAG_NODES.length;

  $dagNodes.innerHTML = DAG_NODES.map(node => {
    let cls = 'dag-node pending';
    let icon = '\u25cb'; // circle outline
    if (isComplete || completedNodes.includes(node.id)) {
      cls = 'dag-node completed';
      icon = '\u2713'; // checkmark
    }
    if (node.id === activeNode) {
      cls = 'dag-node active';
      icon = '\u25cf'; // filled circle
    }
    return `<div class="${cls}"><span class="node-icon">${icon}</span>${node.label}</div>`;
  }).join('');
}

// ── Render: Center panel ──
function renderCenter(snap) {
  let html = '';

  // Phase label
  const phaseLabel = getPhaseLabel(snap.phase);
  html += `<div class="phase-label">${phaseLabel}</div>`;

  // Active agent card
  if (snap.active_agent) {
    const agent = AGENTS[snap.active_agent];
    html += `<div class="agent-card ${agent.css}">${agent.name}</div>`;
  }

  // Authz decision
  if (snap.authz_decision) {
    const d = snap.authz_decision;
    const badgeCls = d.allowed ? 'allowed' : 'denied';
    const badgeText = d.allowed ? 'ALLOWED' : 'DENIED';
    html += `
      <div class="info-panel">
        <h3>Authorization</h3>
        <div class="field">
          <span class="field-label">Agent</span>
          ${d.agent_id}
        </div>
        <div class="field">
          <span class="field-label">Action</span>
          ${d.action}
        </div>
        <div class="field">
          <span class="field-label">Decision</span>
          <span class="badge ${badgeCls}">${badgeText}</span>
        </div>
        <div class="field">
          <span class="field-label">Reason</span>
          ${d.reason}
        </div>
      </div>`;
  }

  // Finding
  const wfState = snap.workflow_state || {};
  if (wfState.finding) {
    const findingCls = wfState.finding === 'PASS' ? 'finding-pass' : 'finding-fail';
    const findingBadge = wfState.finding === 'PASS' ? 'pass' : 'fail';
    html += `
      <div class="info-panel ${findingCls}">
        <h3>Control Check Result</h3>
        <div class="field">
          <span class="field-label">Finding</span>
          <span class="badge ${findingBadge}">${wfState.finding}</span>
        </div>
        ${wfState.evidence ? `<div class="field"><span class="field-label">Evidence</span>${wfState.evidence}</div>` : ''}
      </div>`;
  }

  // Report
  if (wfState.report_summary) {
    html += `
      <div class="info-panel report">
        <h3>Report</h3>
        <div class="field">
          <span class="field-label">Summary</span>
          ${wfState.report_summary}
        </div>
        ${wfState.report_recommendation ? `<div class="field"><span class="field-label">Recommendation</span>${wfState.report_recommendation}</div>` : ''}
      </div>`;
  }

  // Containment result (after approval)
  if (wfState.containment_approved === true) {
    html += `
      <div class="info-panel finding-pass">
        <h3>Containment</h3>
        <div class="field">
          <span class="field-label">Action</span>
          ${wfState.containment_action}
        </div>
        <div class="field">
          <span class="field-label">Status</span>
          <span class="badge allowed">APPROVED</span>
          ${wfState.containment_executed ? '<span class="badge pass" style="margin-left:6px">SIMULATED</span>' : ''}
        </div>
      </div>`;
  } else if (wfState.containment_approved === false) {
    html += `
      <div class="info-panel finding-fail">
        <h3>Containment</h3>
        <div class="field">
          <span class="field-label">Action</span>
          ${wfState.containment_action}
        </div>
        <div class="field">
          <span class="field-label">Status</span>
          <span class="badge denied">DENIED</span>
        </div>
      </div>`;
  }

  // Complete state
  if (snap.phase === 'complete') {
    html += `
      <div class="info-panel" style="border-color: var(--cyan); text-align: center;">
        <h3 style="color: var(--cyan)">Workflow Complete</h3>
        <div class="field" style="color: var(--text-dim)">
          All phases executed. Audit trail finalized.
        </div>
      </div>`;
  }

  $center.innerHTML = html;
}

function getPhaseLabel(phase) {
  const labels = {
    'load_target':          'Loading Target Configuration',
    'check_phase':          'Phase 1: Control Check (RAG-grounded)',
    'report_phase':         'Phase 2: Report Generation',
    'containment_phase':    'Phase 3: Containment Gate',
    'containment_approved': 'Phase 3: Containment Approved',
    'complete':             'Workflow Complete',
  };
  return labels[phase] || phase;
}

// ── Render: Audit trail ──
function renderAudit(entries) {
  if (entries.length === 0) {
    $auditEntries.innerHTML = '<div class="empty-state" style="padding: 24px 0;">No audit entries yet.</div>';
    return;
  }

  $auditEntries.innerHTML = entries.map((entry, i) => {
    const agentCss = AGENTS[entry.agent_id]?.css || '';
    const sigBadge = entry.signature_present
      ? '<span class="badge valid">SIGNATURE ATTACHED</span>'
      : '<span class="badge invalid">NO SIGNATURE</span>';
    const hash = entry.entry_hash ? entry.entry_hash.substring(0, 12) + '...' : '';
    const prevHash = entry.previous_hash ? entry.previous_hash.substring(0, 12) + '...' : '';
    const isNew = i === entries.length - 1;

    return `
      <div class="audit-entry${isNew ? ' new' : ''}">
        <div class="entry-header">
          <span class="entry-agent ${agentCss}">${entry.agent_id}</span>
          ${sigBadge}
        </div>
        <div class="entry-action">${entry.action}</div>
        <div class="entry-hash">
          <span>${prevHash}</span>
          <span class="hash-arrow">&rarr;</span>
          <span>${hash}</span>
        </div>
      </div>`;
  }).join('');

  // Scroll to bottom
  $auditEntries.scrollTop = $auditEntries.scrollHeight;
}

// ── Render: Agent bar ──
function renderAgents() {
  $agentBar.innerHTML = Object.entries(AGENTS).map(([id, agent]) => `
    <div class="agent-identity">
      <div class="agent-dot ${agent.css}"></div>
      <span class="agent-name">${agent.name}</span>
      <span class="agent-key">${agent.key}</span>
      <span class="agent-perm">${agent.perm}</span>
    </div>
  `).join('');
}

// ── Containment modal ──
function showContainmentModal(snap) {
  const wfState = snap.workflow_state;
  $modalBody.innerHTML = `
    <div class="modal-field">
      <span class="modal-field-label">Control</span>
      ${wfState.control_id}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Target</span>
      ${wfState.target_id}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Finding</span>
      <span class="badge fail">${wfState.finding}</span>
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Containment Action</span>
      ${wfState.containment_action}
    </div>
    <div class="modal-field">
      <span class="modal-field-label">Justification</span>
      ${wfState.containment_justification}
    </div>`;
  $modalOverlay.classList.add('visible');
}

function hideContainmentModal() {
  $modalOverlay.classList.remove('visible');
}

function handleContainmentDecision(approved) {
  hideContainmentModal();

  // In live mode, send decision via WebSocket
  if (mode === 'live' && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ action: approved ? 'approve' : 'deny' }));
    return;
  }

  // In static mode, advance to next step
  if (currentStep < snapshots.length - 1) {
    currentStep++;
    renderSnapshot(snapshots[currentStep]);
    updateStepLabel();
  }
}

// ── Boot ──
init();
