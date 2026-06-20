// ============================================
// CyberShield — Incident Response Platform
// JavaScript Application Logic
// ============================================

// ===================== STATE =====================
let currentUser = null;
let allData = [];
let assetGraphData = {};
let assetEventLogs = {};
let threatData = [];
let scanResults = {};

const logMsgs = [
  'Scanning port 443...', 'Firewall rules validated', 'Traffic analysis: nominal',
  'TLS handshake verified', 'DNS resolution OK', 'Packet inspection passed',
  'Certificate valid until 2027', 'No anomalies detected', 'Heartbeat received',
  'Endpoint /api/health: 200 OK', 'Bandwidth within threshold', 'IDS signature update applied'
];

// ===================== INIT =====================

document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();

  const saved = sessionStorage.getItem('cybershield_session');
  if (saved) {
    const users = getUsers();
    if (users[saved]) {
      currentUser = { email: saved, ...users[saved] };
      showApp();
    }
  }

  setInterval(createMatrixChar, 120);
  setInterval(simulateScan, 2500);
  setInterval(updateAllGraphs, 900);
  setInterval(updateThreatGraph, 1200);

  if (!sessionStorage.getItem('cybershield_session')) {
    document.getElementById('auth-modal').style.display = 'flex';
  }
});

// ===================== AUTH SYSTEM =====================

function getUsers() {
  const raw = localStorage.getItem('cybershield_users');
  if (raw) return JSON.parse(raw);
  const defaults = { 'admin@cybershield.io': { name: 'Admin', password: 'password123', assets: [], incidents: [] } };
  localStorage.setItem('cybershield_users', JSON.stringify(defaults));
  return defaults;
}

function saveUsers(users) {
  localStorage.setItem('cybershield_users', JSON.stringify(users));
}

function switchAuthTab(tab) {
  document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
  if (tab === 'login') {
    document.getElementById('tab-login').classList.add('active');
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('signup-form').style.display = 'none';
  } else {
    document.getElementById('tab-signup').classList.add('active');
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('signup-form').style.display = 'block';
  }
}

function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim().toLowerCase();
  const password = document.getElementById('login-password').value;
  const users = getUsers();
  if (users[email] && users[email].password === password) {
    currentUser = { email, ...users[email] };
    sessionStorage.setItem('cybershield_session', email);
    showToast('Welcome back, ' + users[email].name + '!', 'success');
    showApp();
  } else {
    showToast('Invalid email or password', 'error');
  }
}

function handleSignup(e) {
  e.preventDefault();
  const name = document.getElementById('signup-name').value.trim();
  const email = document.getElementById('signup-email').value.trim().toLowerCase();
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  if (password !== confirm) {
    showToast('Passwords do not match', 'error');
    return;
  }
  const users = getUsers();
  if (users[email]) {
    showToast('An account with this email already exists', 'error');
    return;
  }
  users[email] = { name, password, assets: [], incidents: [] };
  saveUsers(users);
  currentUser = { email, ...users[email] };
  sessionStorage.setItem('cybershield_session', email);
  showToast('Account created! Welcome, ' + name, 'success');
  showApp();
}

function logout() {
  currentUser = null;
  sessionStorage.removeItem('cybershield_session');
  document.getElementById('app-main').style.display = 'none';
  document.getElementById('auth-modal').style.display = 'flex';
  document.getElementById('login-form').reset();
  document.getElementById('signup-form').reset();
  showToast('Signed out', 'success');
}

function showApp() {
  document.getElementById('auth-modal').style.display = 'none';
  document.getElementById('app-main').style.display = 'block';
  document.getElementById('user-display').textContent = currentUser.name;
  loadUserData();
  renderAll();
  setTimeout(() => lucide.createIcons(), 100);
}

// ===================== DATA PERSISTENCE =====================

function loadUserData() {
  const users = getUsers();
  const data = users[currentUser.email];
  allData = [
    ...(data.assets || []).map(a => ({ ...a, __backendId: a.id })),
    ...(data.incidents || []).map(i => ({ ...i, __backendId: i.id }))
  ];
  const savedLogs = localStorage.getItem('cybershield_events_' + currentUser.email);
  if (savedLogs) {
    try { assetEventLogs = JSON.parse(savedLogs); } catch(e) { assetEventLogs = {}; }
  }
  const savedGraphs = localStorage.getItem('cybershield_graphs_' + currentUser.email);
  if (savedGraphs) {
    try { assetGraphData = JSON.parse(savedGraphs); } catch(e) { assetGraphData = {}; }
  }
  const savedScans = localStorage.getItem('cybershield_scans_' + currentUser.email);
  if (savedScans) {
    try { scanResults = JSON.parse(savedScans); } catch(e) { scanResults = {}; }
  }
}

function saveUserData() {
  const users = getUsers();
  const assets = allData.filter(d => d.type !== 'incident').map(a => {
    const { __backendId, ...rest } = a;
    return { ...rest, id: __backendId };
  });
  const incidents = allData.filter(d => d.type === 'incident').map(i => {
    const { __backendId, ...rest } = i;
    return { ...rest, id: __backendId };
  });
  users[currentUser.email].assets = assets;
  users[currentUser.email].incidents = incidents;
  saveUsers(users);
  localStorage.setItem('cybershield_events_' + currentUser.email, JSON.stringify(assetEventLogs));
  localStorage.setItem('cybershield_graphs_' + currentUser.email, JSON.stringify(assetGraphData));
  localStorage.setItem('cybershield_scans_' + currentUser.email, JSON.stringify(scanResults));
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// ===================== LINK FIELD =====================

function toggleLinkField() {
  const type = document.getElementById('asset-type').value;
  const hint = document.getElementById('link-hint');
  const input = document.getElementById('asset-link');

  const placeholders = {
    'server':    'IP address (e.g. 192.168.1.100)',
    'website':   'URL (e.g. https://example.com)',
    'device':    'Serial number or IP',
    'firewall':  'IP address (e.g. 10.0.0.1)',
    'router':    'IP address (e.g. 192.168.1.1)',
    'iot':       'Device ID or IP',
    'mobile':    'Phone number or IMEI',
    'wireless':  'MAC address or IP',
    'switch':    'IP address (e.g. 10.0.0.2)',
    'phone':     'Phone number with country code'
  };

  const hints = {
    'server':    'Enter the IP address of the server',
    'website':   'Enter the full URL of the website',
    'device':    'Enter serial number, manufacturing number, or IP',
    'firewall':  'Enter the management IP address',
    'router':    'Enter the gateway IP address',
    'iot':       'Enter the device ID, serial number, or IP',
    'mobile':    'Enter phone number (+919011339309) or IMEI (15 digits)',
    'wireless':  'Enter the MAC address or management IP',
    'switch':    'Enter the management IP address',
    'phone':     'Enter the phone number with country code (e.g. +919011339309)'
  };

  input.placeholder = placeholders[type] || 'Identifier (URL, IP, serial, etc.)';
  hint.textContent = hints[type] || 'Enter the identifier for this asset';
  input.value = '';
}

// ===================== ASSETS =====================

function toggleAssetForm() {
  const f = document.getElementById('asset-form');
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

function handleAddAsset(e) {
  e.preventDefault();
  const name = document.getElementById('asset-name').value.trim();
  const type = document.getElementById('asset-type').value;
  const link = document.getElementById('asset-link').value.trim();
  if (!name || !link) return;

  const asset = {
    __backendId: generateId(),
    name,
    type,
    description: link,
    linkType: getLinkType(type, link),
    status: 'monitoring',
    severity: '',
    timestamp: new Date().toISOString(),
    linked_asset: ''
  };
  allData.push(asset);

  if (!assetEventLogs[asset.__backendId]) assetEventLogs[asset.__backendId] = [];
  if (!assetGraphData[asset.__backendId]) assetGraphData[asset.__backendId] = [];
  if (!scanResults[asset.__backendId]) scanResults[asset.__backendId] = [];

  assetEventLogs[asset.__backendId].push({
    time: new Date().toLocaleTimeString(),
    text: '🔗 Asset linked to CyberShield',
    badge: 'info'
  });

  saveUserData();
  document.getElementById('asset-form').reset();
  document.getElementById('asset-form').style.display = 'none';
  renderAll();
  showToast('✅ ' + name + ' linked successfully', 'success');
  setTimeout(() => lucide.createIcons(), 50);
}

function getLinkType(type, link) {
  if (link.startsWith('http://') || link.startsWith('https://') || link.match(/^[\w\-\.]+\.\w{2,}/)) {
    return 'url';
  }
  if (link.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
    return 'ip';
  }
  if (link.match(/^\+?\d{7,15}$/) || link.match(/^[\+\d\s\-\(\)]{7,20}$/)) {
    return 'phone';
  }
  if (link.match(/^\d{15}$/)) {
    return 'imei';
  }
  if (link.match(/^[A-Za-z0-9\-]{5,}$/)) {
    return 'serial';
  }
  return 'other';
}

// ===================== INCIDENTS =====================

function toggleIncidentForm() {
  const f = document.getElementById('incident-form');
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
  if (f.style.display === 'block') populateAssetSelect();
}

function populateAssetSelect() {
  const sel = document.getElementById('inc-asset');
  sel.innerHTML = '<option value="">Link to asset...</option>';
  allData.filter(d => d.type !== 'incident').forEach(a => {
    sel.innerHTML += `<option value="${a.name}">${a.name} (${a.type})</option>`;
  });
}

function handleAddIncident(e) {
  e.preventDefault();
  const name = document.getElementById('inc-name').value.trim();
  if (!name) return;
  const severity = document.getElementById('inc-severity').value;
  const linked_asset = document.getElementById('inc-asset').value;
  const description = document.getElementById('inc-desc').value.trim();
  const incident = {
    __backendId: generateId(),
    name, type: 'incident', status: 'active',
    severity, timestamp: new Date().toISOString(),
    description, linked_asset
  };
  allData.push(incident);

  if (linked_asset) {
    const target = allData.find(d => d.name === linked_asset && d.type !== 'incident');
    if (target && assetEventLogs[target.__backendId]) {
      assetEventLogs[target.__backendId].push({
        time: new Date().toLocaleTimeString(),
        text: '🚨 Incident: ' + name + ' (' + severity + ')',
        badge: 'fail'
      });
      if (assetEventLogs[target.__backendId].length > 20) assetEventLogs[target.__backendId].shift();
    }
  }

  saveUserData();
  document.getElementById('incident-form').reset();
  document.getElementById('incident-form').style.display = 'none';
  renderAll();
  showToast('🚨 ALERT: ' + name + ' reported', 'error');
  setTimeout(() => lucide.createIcons(), 50);
}

// ===================== ACTIONS =====================

function startMonitoring(id) {
  const rec = allData.find(d => d.__backendId === id);
  if (!rec) return;
  const isActive = rec.status === 'monitoring' && rec.severity === 'active';

  if (isActive) {
    rec.severity = '';
    showToast('Monitoring stopped for ' + rec.name, 'success');
  } else {
    rec.severity = 'active';
    if (!assetEventLogs[id]) assetEventLogs[id] = [];
    if (!assetGraphData[id]) assetGraphData[id] = [];
    if (!scanResults[id]) scanResults[id] = [];

    assetEventLogs[id].push({
      time: new Date().toLocaleTimeString(),
      text: '▶ Monitoring started',
      badge: 'info'
    });
    if (assetEventLogs[id].length > 20) assetEventLogs[id].shift();

    showToast('🔴 Monitoring started for ' + rec.name, 'success');
  }
  saveUserData();
  renderAll();
  setTimeout(() => lucide.createIcons(), 50);
}

function stopMonitor(id) {
  const rec = allData.find(d => d.__backendId === id);
  if (!rec) return;
  rec.severity = '';
  if (assetEventLogs[id]) {
    assetEventLogs[id].push({
      time: new Date().toLocaleTimeString(),
      text: '⏹ Monitoring stopped',
      badge: 'info'
    });
    if (assetEventLogs[id].length > 20) assetEventLogs[id].shift();
  }
  saveUserData();
  renderAll();
  showToast('Monitoring stopped for ' + rec.name, 'success');
  setTimeout(() => lucide.createIcons(), 50);
}

function resolveRecord(id) {
  const rec = allData.find(d => d.__backendId === id);
  if (!rec || rec.status === 'resolved') return;
  rec.status = 'resolved';

  if (rec.type === 'incident' && rec.linked_asset) {
    const target = allData.find(d => d.name === rec.linked_asset && d.type !== 'incident');
    if (target && assetEventLogs[target.__backendId]) {
      assetEventLogs[target.__backendId].push({
        time: new Date().toLocaleTimeString(),
        text: '✅ Incident resolved: ' + rec.name,
        badge: 'pass'
      });
      if (assetEventLogs[target.__backendId].length > 20) assetEventLogs[target.__backendId].shift();
    }
  }

  saveUserData();
  renderAll();
  showToast('✅ ' + rec.name + ' resolved', 'success');
  setTimeout(() => lucide.createIcons(), 50);
}

function deleteRecord(id) {
  const rec = allData.find(d => d.__backendId === id);
  if (!rec) return;
  if (!confirm('Delete "' + rec.name + '"?')) return;
  allData = allData.filter(d => d.__backendId !== id);
  delete scanResults[id];
  delete assetEventLogs[id];
  delete assetGraphData[id];
  saveUserData();
  renderAll();
  showToast('🗑️ ' + rec.name + ' deleted', 'success');
  setTimeout(() => lucide.createIcons(), 50);
}

// ===================== PER-ASSET MONITOR RENDER =====================

function renderPerAssetMonitors() {
  const container = document.getElementById('per-asset-monitors');
  const activeAssets = allData.filter(d => d.type !== 'incident' && d.severity === 'active');

  if (activeAssets.length === 0) {
    container.innerHTML = `
      <div id="no-active-monitors" class="text-gray-500 text-sm text-center py-8">
        <i data-lucide="radio" style="width:32px;height:32px;color:#4ade80;display:block;margin:0 auto 12px;"></i>
        No assets being monitored.<br>Click "Monitor" on an asset to begin.
      </div>`;
    return;
  }

  let html = '';
  activeAssets.forEach(asset => {
    if (!assetEventLogs[asset.__backendId]) assetEventLogs[asset.__backendId] = [];
    if (!assetGraphData[asset.__backendId]) assetGraphData[asset.__backendId] = [];

    const events = assetEventLogs[asset.__backendId].slice(-5).reverse();
    const graphId = 'pagraph-' + asset.__backendId;

    let eventHtml = '';
    if (events.length === 0) {
      eventHtml = '<div class="text-gray-600 text-[10px] text-center py-2">No events yet</div>';
    } else {
      events.forEach(ev => {
        const badgeClass = ev.badge || 'info';
        eventHtml += `
          <div class="asset-event-item">
            <span class="event-time">${ev.time}</span>
            <span class="event-text">${escapeHtml(ev.text)}</span>
            <span class="event-badge ${badgeClass}">${badgeClass.toUpperCase()}</span>
          </div>`;
      });
    }

    html += `
      <div class="asset-monitor-card">
        <div class="monitor-header">
          <div class="flex items-center gap-2">
            <i data-lucide="monitor" style="width:14px;height:14px;color:#4ade80;"></i>
            <span class="text-sm font-medium text-green-300">${escapeHtml(asset.name)}</span>
            <span class="text-[10px] text-gray-500">(${asset.type})</span>
          </div>
          <span class="status-dot ok"></span>
        </div>
        <div class="monitor-graph">
          <svg id="${graphId}" class="w-full h-full" viewBox="0 0 300 48" preserveAspectRatio="none">
            <defs>
              <linearGradient id="pag-${asset.__backendId}" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" style="stop-color:#4ade80;stop-opacity:0.3" />
                <stop offset="100%" style="stop-color:#4ade80;stop-opacity:0" />
              </linearGradient>
            </defs>
            <polyline id="${graphId}-area" points="0,48 0,48" fill="url(#pag-${asset.__backendId})" stroke="none" />
            <polyline id="${graphId}-line" points="0,48 0,48" fill="none" stroke="#4ade80" stroke-width="1.5" stroke-linejoin="round" />
          </svg>
        </div>
        <div class="asset-event-feed">
          <div class="feed-body">
            ${eventHtml}
          </div>
        </div>
        <div class="monitor-footer">
          <span class="text-[10px] text-gray-600">Last event: ${events.length > 0 ? events[0].time : '—'}</span>
          <button onclick="stopMonitor('${asset.__backendId}')" class="text-[10px] text-red-400 hover:text-red-300 transition-colors">Stop</button>
        </div>
      </div>`;
  });

  container.innerHTML = html;
  document.getElementById('monitor-count').textContent = activeAssets.length + ' active';
}

// ===================== RENDER =====================

function renderAll() {
  renderAssets();
  renderIncidents();
  renderResults();
  renderPerAssetMonitors();
  updateStats();
  updateSystemAlert();
  setTimeout(() => lucide.createIcons(), 50);
}

function renderAssets() {
  const list = document.getElementById('asset-list');
  const assets = allData.filter(d => d.type !== 'incident');
  document.getElementById('asset-empty').style.display = assets.length ? 'none' : 'block';
  list.innerHTML = '';
  assets.forEach(a => {
    const icon = a.type === 'device' ? 'monitor' : a.type === 'website' ? 'globe' : a.type === 'firewall' ? 'shield' : 'hard-drive';
    const isActive = a.status === 'monitoring' && a.severity === 'active';
    list.innerHTML += `
      <div class="flex items-center gap-3 bg-gray-900/40 rounded-xl px-4 py-3 border ${isActive ? 'border-green-900/30' : 'border-gray-800/30'} hover:border-gray-700/50 transition-all">
        <div class="w-8 h-8 rounded-lg bg-gray-800/60 flex items-center justify-center flex-shrink-0">
          <i data-lucide="${icon}" style="width:16px;height:16px;color:#4ade80;"></i>
        </div>
        <div class="flex-1 min-w-0">
          <div class="text-sm font-medium text-gray-200 truncate">${escapeHtml(a.name)}</div>
          <div class="text-xs text-gray-500 truncate mt-0.5">${escapeHtml(a.description || '—')}</div>
          <div class="mt-1.5">
            <span class="badge ${isActive ? 'badge-green' : 'badge-blue'} text-[10px]">
              <span class="w-1.5 h-1.5 rounded-full ${isActive ? 'bg-green-400 pulse-dot' : 'bg-blue-400'}"></span>
              ${isActive ? 'Scanning' : 'Idle'}
            </span>
            <span class="text-[10px] text-gray-600 ml-2 uppercase">${escapeHtml(a.type)}</span>
          </div>
        </div>
        <div class="flex items-center gap-1.5 flex-shrink-0">
          <button onclick="startMonitoring('${a.__backendId}')" class="${isActive ? 'btn-ghost text-green-400 border-green-900/30' : 'btn-ghost'} text-xs px-2.5 py-1">
            ${isActive ? 'Stop' : 'Monitor'}
          </button>
          <button onclick="deleteRecord('${a.__backendId}')" class="text-gray-600 hover:text-red-400 transition-colors p-1">
            <i data-lucide="trash-2" style="width:14px;height:14px;"></i>
          </button>
        </div>
      </div>`;
  });
}

function renderIncidents() {
  const list = document.getElementById('incident-list');
  const incidents = allData.filter(d => d.type === 'incident');
  document.getElementById('incident-empty').style.display = incidents.length ? 'none' : 'block';
  list.innerHTML = '';
  incidents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  incidents.forEach(inc => {
    const colors = { low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#ef4444' };
    const c = colors[inc.severity] || '#6b7280';
    const sevLabels = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
    const isResolved = inc.status === 'resolved';
    const sevColors = { low: 'badge-green', medium: 'badge-yellow', high: 'badge-yellow', critical: 'badge-red' };
    list.innerHTML += `
      <div class="bg-gray-900/40 rounded-xl px-4 py-3 border-l-4 transition-all hover:bg-gray-900/60" style="border-color:${c};">
        <div class="flex justify-between items-start">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <div class="text-sm font-medium text-gray-200 truncate">${escapeHtml(inc.name)}</div>
              <span class="badge ${sevColors[inc.severity] || 'badge-blue'} text-[10px]">${sevLabels[inc.severity]}</span>
            </div>
            <div class="text-xs text-gray-500 mt-0.5">
              ${inc.linked_asset ? '🔗 ' + escapeHtml(inc.linked_asset) + ' · ' : ''}
              ${inc.description ? escapeHtml(inc.description) : ''}
            </div>
          </div>
          <button onclick="resolveRecord('${inc.__backendId}')" class="text-xs flex-shrink-0 ml-2 ${isResolved ? 'text-blue-400' : 'text-gray-500 hover:text-green-400'} transition-colors px-2 py-1">
            ${isResolved ? '✓ Resolved' : 'Resolve'}
          </button>
        </div>
      </div>`;
  });
}

function renderResults() {
  const panel = document.getElementById('results-panel');
  let hasContent = false;
  let html = '';

  allData.filter(d => d.type !== 'incident' && d.severity === 'active').forEach(asset => {
    if (!scanResults[asset.__backendId] || scanResults[asset.__backendId].length === 0) return;
    const results = scanResults[asset.__backendId];
    const recent = results.slice(-3).reverse();
    recent.forEach(r => {
      hasContent = true;
      const cls = r.status === 'fail' ? 'critical' : r.status === 'warn' ? 'warning' : '';
      const statusLabel = r.status === 'pass' ? 'PASS' : r.status === 'warn' ? 'WARN' : 'FAIL';
      html += `
        <div class="result-item ${cls}">
          <span class="result-time">${r.time}</span>
          <span class="result-text">[${escapeHtml(asset.name)}] ${escapeHtml(r.text)}</span>
          <span class="result-status ${r.status}">${statusLabel}</span>
        </div>`;
    });
  });

  if (!hasContent) {
    html = '<div class="text-gray-600 text-xs text-center py-4">No scan results yet.<br>Monitor an asset to see results here.</div>';
  }
  panel.innerHTML = html;
}

function updateStats() {
  const assets = allData.filter(d => d.type !== 'incident');
  const incidents = allData.filter(d => d.type === 'incident');
  document.getElementById('stat-assets').textContent = assets.length;
  document.getElementById('stat-active').textContent = assets.filter(a => a.severity === 'active').length;
  document.getElementById('stat-critical').textContent = incidents.filter(i => i.severity === 'critical' && i.status === 'active').length;
  document.getElementById('stat-resolved').textContent = incidents.filter(i => i.status === 'resolved').length;
}

function updateSystemAlert() {
  const activeIncidents = allData.filter(d => d.type === 'incident' && d.status === 'active');
  const alertDiv = document.getElementById('alert-content');
  const alertText = document.getElementById('alert-text');
  if (activeIncidents.length > 0) {
    alertDiv.className = 'rounded-xl px-5 py-3 flex items-center gap-3 bg-red-950/40 border border-red-500/20 text-red-300 text-sm';
    alertText.textContent = '🚨 ' + activeIncidents.length + ' active incident' + (activeIncidents.length > 1 ? 's' : '') + ' — immediate attention required';
  } else {
    alertDiv.className = 'rounded-xl px-5 py-3 flex items-center gap-3 bg-green-950/40 border border-green-500/20 text-green-300 text-sm';
    alertText.textContent = '✓ All systems operational — no active incidents';
  }
}

// ===================== SCAN SIMULATION =====================

function simulateScan() {
  const activeAssets = allData.filter(d => d.type !== 'incident' && d.status === 'monitoring' && d.severity === 'active');
  if (activeAssets.length === 0) return;

  const asset = activeAssets[Math.floor(Math.random() * activeAssets.length)];
  const msg = logMsgs[Math.floor(Math.random() * logMsgs.length)];

  if (!scanResults[asset.__backendId]) scanResults[asset.__backendId] = [];
  const scanStatuses = ['pass', 'pass', 'pass', 'pass', 'warn', 'warn', 'fail'];
  const status = scanStatuses[Math.floor(Math.random() * scanStatuses.length)];

  scanResults[asset.__backendId].push({
    time: new Date().toLocaleTimeString(),
    type: 'scan',
    text: msg,
    status: status
  });
  if (scanResults[asset.__backendId].length > 50) scanResults[asset.__backendId].shift();

  if (!assetEventLogs[asset.__backendId]) assetEventLogs[asset.__backendId] = [];
  const badgeMap = { pass: 'pass', warn: 'warn', fail: 'fail' };
  assetEventLogs[asset.__backendId].push({
    time: new Date().toLocaleTimeString(),
    text: msg,
    badge: badgeMap[status] || 'info'
  });
  if (assetEventLogs[asset.__backendId].length > 20) assetEventLogs[asset.__backendId].shift();

  renderResults();
  renderPerAssetMonitors();
}

// ===================== GRAPH UPDATES =====================

function updateAllGraphs() {
  const activeAssets = allData.filter(d => d.type !== 'incident' && d.severity === 'active');
  activeAssets.forEach(asset => {
    const data = assetGraphData[asset.__backendId] || [];
    const val = Math.random() * 80 + 15;
    data.push(val);
    if (data.length > 50) data.shift();
    assetGraphData[asset.__backendId] = data;

    const graphId = 'pagraph-' + asset.__backendId;
    const line = document.getElementById(graphId + '-line');
    const area = document.getElementById(graphId + '-area');
    if (!line || !area) return;

    const w = 300, h = 48;
    const pts = data.map((v, i) => {
      const x = (i / Math.max(1, data.length - 1)) * w;
      const y = h - (v / 120) * h;
      return x + ',' + y;
    }).join(' ');
    line.setAttribute('points', pts);
    area.setAttribute('points', '0,' + h + ' ' + pts + ' ' + w + ',' + h);
  });
}

function updateThreatGraph() {
  const activeIncidents = allData.filter(d => d.type === 'incident' && d.status === 'active');
  const threatVal = activeIncidents.length * (Math.random() * 40 + 5);
  threatData.push(threatVal);
  if (threatData.length > 50) threatData.shift();

  const w = 400, h = 100;
  const pts = threatData.map((v, i) => {
    const x = (i / Math.max(1, threatData.length - 1)) * w;
    const y = h - Math.min(v, 140) / 140 * h;
    return x + ',' + y;
  }).join(' ');

  const line = document.getElementById('threat-line');
  const area = document.getElementById('threat-area');
  if (line && area) {
    line.setAttribute('points', pts);
    area.setAttribute('points', '0,' + h + ' ' + pts + ' ' + w + ',' + h);
  }
}

// ===================== MATRIX RAIN =====================

function createMatrixChar() {
  const bg = document.getElementById('matrix-bg');
  if (!bg) return;
  const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
  const el = document.createElement('div');
  el.className = 'matrix-char';
  el.textContent = chars[Math.floor(Math.random() * chars.length)];
  el.style.left = Math.random() * 100 + '%';
  el.style.animationDuration = (Math.random() * 4 + 3) + 's';
  el.style.animationDelay = Math.random() * 2 + 's';
  bg.appendChild(el);
  setTimeout(() => el.remove(), 8000);
}

// ===================== TOAST =====================

function showToast(msg, type) {
  const container = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast toast-' + type;
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.3s';
    setTimeout(() => t.remove(), 300);
  }, 4000);
}

// ===================== HELPERS =====================

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Open auth modal if not logged in
if (!sessionStorage.getItem('cybershield_session')) {
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('auth-modal').style.display = 'flex';
  });
}