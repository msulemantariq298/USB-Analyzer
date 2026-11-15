/**
 * USB ANALYZER — ENDPOINT HARDWARE DEFENSE CONSOLE
 * Clean Architecture & Real-Time Event Bus Controller
 * Author: Muhammad Suleman Tariq <msulemantariq298@gmail.com>
 */

(function () {
  'use strict';

  // --- Configuration & Global State ---
  const CONFIG = {
    API_PREFIX: '/api/v1',
    POLL_INTERVAL_MS: 2500,
    HEARTBEAT_INTERVAL_MS: 5000,
    CLIENT_ID: 'dash_' + Math.random().toString(36).substring(2, 10),
  };

  const state = {
    events: [],
    whitelist: [],
    viewMode: 'connected', // 'connected' | 'all'
    searchTerm: '',
    soundEnabled: true,
    lastEventCount: 0,
    activeDeviceModal: null,
    theme: localStorage.getItem('usb_analyzer_theme') || 'dark',
  };

  // --- Web Audio Synthesizer (Zero-latency alert chimes) ---
  const soundEngine = {
    ctx: null,
    init() {
      if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        this.ctx = new AudioCtx();
      }
    },
    playTone(freq, type, duration, delay = 0) {
      if (!state.soundEnabled) return;
      try {
        this.init();
        if (!this.ctx) return;
        if (this.ctx.state === 'suspended') this.ctx.resume();

        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, this.ctx.currentTime + delay);
        gain.gain.setValueAtTime(0.08, this.ctx.currentTime + delay);
        gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + delay + duration);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(this.ctx.currentTime + delay);
        osc.stop(this.ctx.currentTime + delay + duration);
      } catch (e) {
        // Audio policy ignore
      }
    },
    playThreatAlert() {
      this.playTone(880, 'sawtooth', 0.15, 0);
      this.playTone(440, 'sawtooth', 0.25, 0.12);
    },
    playWarningAlert() {
      this.playTone(587.33, 'triangle', 0.2, 0);
      this.playTone(440, 'triangle', 0.2, 0.15);
    },
    playSuccessChime() {
      this.playTone(523.25, 'sine', 0.15, 0);
      this.playTone(659.25, 'sine', 0.2, 0.12);
    },
    playHapticClick() {
      this.playTone(750, 'sine', 0.04, 0);
    }
  };

  // --- Simple & Buttery-Smooth Theme Transition Controller ---
  function applyTheme(targetTheme, animate = false) {
    const root = document.documentElement;
    const toggleLabel = document.getElementById('theme-toggle-label');

    const updateDOM = () => {
      root.setAttribute('data-theme', targetTheme);
      state.theme = targetTheme;
      localStorage.setItem('usb_analyzer_theme', targetTheme);

      if (toggleLabel) {
        toggleLabel.textContent = targetTheme === 'dark' ? 'Dark Theme' : 'Light Theme';
      }

      updateChartThemes(targetTheme);
    };

    if (!animate) {
      updateDOM();
      return;
    }

    // Use native View Transitions API when available for 60/120fps crossfade
    if (document.startViewTransition) {
      document.startViewTransition(() => {
        updateDOM();
      });
    } else {
      root.classList.add('theme-transitioning');
      updateDOM();
      setTimeout(() => {
        root.classList.remove('theme-transitioning');
      }, 220);
    }
  }

  function initTheme() {
    applyTheme(state.theme, false);

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        soundEngine.playHapticClick();
        const next = state.theme === 'dark' ? 'light' : 'dark';
        applyTheme(next, true);
      });
    }
  }

  // --- Toast System ---
  function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  // --- Chart.js Controllers ---
  let threatChart = null;
  let activityChart = null;

  function initCharts() {
    const threatCanvas = document.getElementById('threat-chart');
    const activityCanvas = document.getElementById('activity-chart');

    const isDark = state.theme === 'dark';
    const textColor = isDark ? '#94A3B8' : '#475569';
    const gridColor = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';

    if (threatCanvas && window.Chart) {
      threatChart = new Chart(threatCanvas, {
        type: 'doughnut',
        data: {
          labels: ['Safe / Normal', 'Policy Warnings', 'Critical Threats'],
          datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#10B981', '#F59E0B', '#EF4444'],
            borderColor: isDark ? '#0E172A' : '#FFFFFF',
            borderWidth: 2,
            hoverOffset: 4,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: textColor,
                boxWidth: 10,
                font: { family: 'JetBrains Mono', size: 10 }
              }
            }
          },
          cutout: '72%',
        }
      });
    }

    if (activityCanvas && window.Chart) {
      activityChart = new Chart(activityCanvas, {
        type: 'bar',
        data: {
          labels: ['Connected', 'Allowed', 'Storage Scans', 'Blocked', 'Heuristic Flags'],
          datasets: [{
            label: 'Event Volume',
            data: [0, 0, 0, 0, 0],
            backgroundColor: ['#2563EB', '#10B981', '#3B82F6', '#EF4444', '#F59E0B'],
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 9.5 } },
              grid: { display: false }
            },
            y: {
              ticks: { color: textColor, font: { family: 'JetBrains Mono', size: 10 }, precision: 0 },
              grid: { color: gridColor }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  function updateChartThemes(theme) {
    const isDark = theme === 'dark';
    const textColor = isDark ? '#94A3B8' : '#475569';
    const gridColor = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';

    if (threatChart) {
      threatChart.data.datasets[0].borderColor = isDark ? '#0E172A' : '#FFFFFF';
      if (threatChart.options.plugins?.legend?.labels) {
        threatChart.options.plugins.legend.labels.color = textColor;
      }
      threatChart.update();
    }
    if (activityChart) {
      if (activityChart.options.scales?.x?.ticks) activityChart.options.scales.x.ticks.color = textColor;
      if (activityChart.options.scales?.y?.ticks) activityChart.options.scales.y.ticks.color = textColor;
      if (activityChart.options.scales?.y?.grid) activityChart.options.scales.y.grid.color = gridColor;
      activityChart.update();
    }
  }

  function updateChartData(counts) {
    if (threatChart) {
      threatChart.data.datasets[0].data = [
        counts.info,
        counts.warning,
        counts.critical,
      ];
      threatChart.update('none');
    }
    if (activityChart) {
      activityChart.data.datasets[0].data = [
        counts.connected,
        counts.allowed,
        counts.scans,
        counts.blocked,
        counts.flagged,
      ];
      activityChart.update('none');
    }
  }

  // --- API Client Layer ---
  async function apiGet(endpoint) {
    const res = await fetch(`${CONFIG.API_PREFIX}${endpoint}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${endpoint}`);
    return res.json();
  }

  async function apiPost(endpoint, body) {
    const res = await fetch(`${CONFIG.API_PREFIX}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${endpoint}`);
    return res.json();
  }

  async function apiDelete(endpoint) {
    const res = await fetch(`${CONFIG.API_PREFIX}${endpoint}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${endpoint}`);
    return res.status === 204 ? null : res.json();
  }

  // --- Heartbeat & Notification Intercept ---
  async function sendHeartbeat() {
    try {
      const data = await apiPost(`/dashboard/heartbeat?client_id=${CONFIG.CLIENT_ID}`, {});
      if (data && data.actions && data.actions.length > 0) {
        for (const act of data.actions) {
          handleNotificationAction(act);
        }
      }
    } catch (e) {
      // Background heartbeat ignore
    }
  }

  function handleNotificationAction(act) {
    if (act.device_id) {
      openDeviceInspection(act.device_id);
    }
    if (act.action === 'block' && act.device_id) {
      blockDevice(act.device_id);
    } else if (act.action === 'allow' && act.device_id) {
      allowDevice(act.device_id);
    }
  }

  // --- Telemetry Polling & Aggregation ---
  async function fetchTelemetry() {
    try {
      const events = await apiGet('/events?limit=200');
      state.events = events || [];

      // Check for incoming alerts to play audio
      if (events.length > state.lastEventCount && state.lastEventCount > 0) {
        const newest = events[0];
        if (newest) {
          if (newest.severity === 'critical') soundEngine.playThreatAlert();
          else if (newest.severity === 'warning') soundEngine.playWarningAlert();
        }
      }
      state.lastEventCount = events.length;

      renderMetrics();
      renderEventsTable();
      updateSyncTime();
      checkSecurityAlertBanner();
    } catch (err) {
      const statusEl = document.getElementById('api-status');
      if (statusEl) statusEl.textContent = 'BUS OFFLINE (RETRYING)';
    }
  }

  async function fetchWhitelist() {
    try {
      const entries = await apiGet('/policy/whitelist');
      state.whitelist = entries || [];
      renderWhitelistTable();

      const policyStatus = await apiGet('/policy/status');
      const modeSelect = document.getElementById('policy-mode-select');
      const sideMode = document.getElementById('sidebar-policy-mode');
      if (modeSelect && policyStatus.mode) {
        modeSelect.value = policyStatus.mode;
      }
      if (sideMode && policyStatus.mode) {
        sideMode.textContent = policyStatus.mode === 'enforce' ? 'ENFORCE MODE' : 'AUDIT ONLY';
      }
    } catch (e) {
      // Ignored
    }
  }

  // --- Metric HUD Render ---
  function renderMetrics() {
    const totalEventsEl = document.getElementById('total-events');
    const devicesBlockedEl = document.getElementById('devices-blocked');
    const activeScansEl = document.getElementById('active-scans');
    const policyWarningsEl = document.getElementById('policy-warnings');
    const criticalThreatsEl = document.getElementById('critical-threats');
    const flaggedFilesEl = document.getElementById('flagged-files');
    const storageScansEl = document.getElementById('storage-scans');
    const navActiveBadge = document.getElementById('nav-active-badge');

    let total = state.events.length;
    let blocked = 0;
    let warnings = 0;
    let critical = 0;
    let scans = 0;
    let activeScans = 0;
    let flaggedFiles = 0;
    let connected = 0;
    let allowed = 0;

    for (const ev of state.events) {
      if (ev.severity === 'critical') critical++;
      if (ev.severity === 'warning') warnings++;

      if (ev.event_type === 'device.blocked') blocked++;
      if (ev.event_type === 'device.connected') connected++;
      if (ev.event_type === 'device.allowed') allowed++;

      // Handling active scan events (Requirement: "scan.started")
      if (ev.event_type === 'scan.started') {
        scans++;
        activeScans++;
      } else if (ev.event_type === 'scan.completed') {
        scans++;
      }

      // Requirement: "filename-based indicators"
      if (ev.event_type === 'scan.threat_detected') {
        critical++;
        if (ev.details && ev.details.flagged_files) {
          flaggedFiles += ev.details.flagged_files.length;
        } else {
          flaggedFiles++;
        }
      }
    }

    if (totalEventsEl) totalEventsEl.textContent = total;
    if (devicesBlockedEl) devicesBlockedEl.textContent = blocked;
    if (activeScansEl) activeScansEl.textContent = activeScans;
    if (policyWarningsEl) policyWarningsEl.textContent = warnings;
    if (criticalThreatsEl) criticalThreatsEl.textContent = critical;
    if (flaggedFilesEl) flaggedFilesEl.textContent = flaggedFiles;
    if (storageScansEl) storageScansEl.textContent = scans;
    if (navActiveBadge) navActiveBadge.textContent = total;

    updateChartData({
      info: total - warnings - critical,
      warning: warnings,
      critical: critical,
      connected: connected,
      allowed: allowed,
      scans: scans,
      blocked: blocked,
      flagged: flaggedFiles,
    });
  }

  // --- High Urgency Incident Banner ---
  function checkSecurityAlertBanner() {
    const banner = document.getElementById('security-alert-banner');
    const bannerTitle = document.getElementById('alert-banner-title');
    const bannerMsg = document.getElementById('alert-banner-msg');
    const inspectBtn = document.getElementById('alert-banner-inspect-btn');
    if (!banner) return;

    const criticalEvent = state.events.find(e => e.severity === 'critical');
    if (criticalEvent) {
      banner.classList.remove('hidden');
      const det = criticalEvent.details || {};
      const reason = det.reason || det.summary || 'Anomalous hardware violation intercepted';
      if (bannerTitle) bannerTitle.textContent = `CRITICAL THREAT: ${criticalEvent.event_type.toUpperCase()}`;
      if (bannerMsg) bannerMsg.textContent = `${criticalEvent.device_id} — ${reason}`;
      if (inspectBtn) {
        inspectBtn.onclick = () => openDeviceInspection(criticalEvent.device_id);
      }
    } else {
      banner.classList.add('hidden');
    }
  }

  // --- Events Table Render ---
  function renderEventsTable() {
    const tbody = document.getElementById('events-table-body');
    if (!tbody) return;

    let displayList = [];
    if (state.viewMode === 'connected') {
      // Group by device_id to show latest status per peripheral
      const deviceMap = new Map();
      for (const ev of state.events) {
        if (!deviceMap.has(ev.device_id)) {
          deviceMap.set(ev.device_id, ev);
        }
      }
      displayList = Array.from(deviceMap.values());
    } else {
      displayList = state.events;
    }

    // Filter by search
    if (state.searchTerm) {
      const q = state.searchTerm.toLowerCase();
      displayList = displayList.filter(ev => {
        const d = ev.details || {};
        return (
          ev.device_id.toLowerCase().includes(q) ||
          ev.event_type.toLowerCase().includes(q) ||
          ev.severity.toLowerCase().includes(q) ||
          (d.name && d.name.toLowerCase().includes(q)) ||
          (d.vendor_id && d.vendor_id.toLowerCase().includes(q)) ||
          (d.product_id && d.product_id.toLowerCase().includes(q)) ||
          (d.serial_number && d.serial_number.toLowerCase().includes(q)) ||
          (d.reason && d.reason.toLowerCase().includes(q))
        );
      });
    }

    if (displayList.length === 0) {
      tbody.innerHTML = `
        <tr class="table-empty-row">
          <td colspan="7" class="table-empty-cell">
            <div class="empty-state-wrap">
              <span class="empty-icon">🛡️</span>
              <strong class="empty-title">Database Clean — Bus Defense Active</strong>
              <span class="empty-desc">Connect any USB peripheral or inject diagnostic vectors below to inspect forensic verdicts in real-time.</span>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = displayList.map(ev => {
      const det = ev.details || {};
      const timeStr = formatTimestamp(ev.time);
      const name = det.name || ev.device_id;
      const vid = det.vendor_id ? `VID: ${det.vendor_id}` : '';
      const pid = det.product_id ? `PID: ${det.product_id}` : '';
      const serial = det.serial_number ? `SN: ${det.serial_number}` : '';
      const hardwareSub = [vid, pid, serial].filter(Boolean).join(' | ');

      const busClass = det.device_type || (ev.source === 'storage-scanner' ? 'Storage Volume' : 'USB Bus');
      const badge = getSeverityBadge(ev.severity, ev.event_type);
      const reason = det.reason || det.summary || det.threat_type || 'Verified normal operation';
      const action = det.action || (ev.event_type === 'device.blocked' ? 'Isolated & Disabled' : 'Allowed & Monitored');

      return `
        <tr>
          <td class="th-time mono-cell">${timeStr}</td>
          <td class="th-device">
            <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(name)}</div>
            ${hardwareSub ? `<div class="badge-mono" style="font-size: 10px; color: var(--text-dim);">${escapeHtml(hardwareSub)}</div>` : ''}
          </td>
          <td class="th-class" style="color: var(--text-muted); font-size: 11px;">${escapeHtml(busClass)}</td>
          <td class="th-status">${badge}</td>
          <td class="th-reason" style="font-size: 11.5px; color: var(--text-muted);">${escapeHtml(reason)}</td>
          <td class="th-action" style="font-size: 11px; font-weight: 600;">${escapeHtml(action)}</td>
          <td class="th-inspect" style="text-align: right;">
            <button type="button" class="btn-table-action" onclick="window.USBApp.inspectDevice('${escapeHtml(ev.device_id)}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function getSeverityBadge(sev, eventType) {
    if (eventType === 'device.blocked' || sev === 'critical') {
      return '<span class="badge-status badge-danger">BLOCKED</span>';
    }
    if (sev === 'warning') {
      return '<span class="badge-status badge-warning">SUSPICIOUS</span>';
    }
    if (eventType === 'device.allowed' || sev === 'info') {
      return '<span class="badge-status badge-safe">SAFE</span>';
    }
    return `<span class="badge-status badge-neutral">${escapeHtml(sev.toUpperCase())}</span>`;
  }

  // --- Whitelist Table Render ---
  function renderWhitelistTable() {
    const tbody = document.getElementById('whitelist-table-body');
    if (!tbody) return;

    if (state.whitelist.length === 0) {
      tbody.innerHTML = `
        <tr class="table-empty-row">
          <td colspan="6" class="table-empty-cell">No authorized hardware entries found. Add trusted peripherals above.</td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = state.whitelist.map(entry => {
      return `
        <tr>
          <td><strong>${escapeHtml(entry.name || 'Unnamed Peripheral')}</strong></td>
          <td class="mono-cell">${escapeHtml(entry.vendor_id || 'ANY')}</td>
          <td class="mono-cell">${escapeHtml(entry.product_id || 'ANY')}</td>
          <td class="mono-cell" style="color: var(--cobalt-bright); font-weight: 600;">${escapeHtml(entry.serial_number || 'ANY')}</td>
          <td style="color: var(--text-muted); font-size: 11px;">${escapeHtml(entry.notes || '—')}</td>
          <td style="text-align: right;">
            <button type="button" class="btn-table-action" style="color: var(--danger-text);" onclick="window.USBApp.deleteWhitelistEntry('${entry.id}')">Revoke</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  // --- Device Forensic Inspection Modal ---
  function openDeviceInspection(deviceId) {
    state.activeDeviceModal = deviceId;
    const modal = document.getElementById('detail-modal');
    const content = document.getElementById('detail-modal-content');
    const actionsEl = document.getElementById('detail-dynamic-actions');
    if (!modal || !content) return;

    const deviceEvents = state.events.filter(e => e.device_id === deviceId);
    const primary = deviceEvents[0] || { device_id: deviceId, severity: 'info', details: {} };
    const det = primary.details || {};

    content.innerHTML = `
      <div class="detail-meta-grid">
        <div class="detail-meta-cell">
          <div class="detail-label">DEVICE IDENTIFIER</div>
          <div class="detail-value detail-value-mono">${escapeHtml(primary.device_id)}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">SECURITY VERDICT</div>
          <div class="detail-value">${getSeverityBadge(primary.severity, primary.event_type)}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">HARDWARE IDENTITY</div>
          <div class="detail-value">${escapeHtml(det.name || 'Generic USB Bus Device')}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">BUS SIGNATURE</div>
          <div class="detail-value detail-value-mono">VID: ${escapeHtml(det.vendor_id || 'N/A')} | PID: ${escapeHtml(det.product_id || 'N/A')}</div>
        </div>
      </div>

      <div>
        <div class="detail-label">FORENSIC RISK / DIAGNOSTIC REASON</div>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          ${escapeHtml(det.reason || det.summary || 'Hardware signature inspected against corporate heuristics.')}
        </p>
      </div>

      <div>
        <div class="detail-label">RAW TELEMETRY TELETYPE (JSON DUMP)</div>
        <pre class="detail-json-box">${escapeHtml(JSON.stringify(deviceEvents, null, 2))}</pre>
      </div>
    `;

    if (actionsEl) {
      actionsEl.innerHTML = `
        <button type="button" class="btn-action-ghost" style="color: var(--danger-text);" onclick="window.USBApp.blockDevice('${escapeHtml(deviceId)}')">Isolate Port (Block)</button>
        <button type="button" class="btn-action-ghost" style="color: var(--safe-text);" onclick="window.USBApp.allowDevice('${escapeHtml(deviceId)}')">Allow Device</button>
        <button type="button" class="btn-primary-action" onclick="window.USBApp.whitelistDevice('${escapeHtml(deviceId)}')">Add to Whitelist</button>
      `;
    }

    modal.classList.remove('hidden');
  }

  function closeDetailModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.add('hidden');
    state.activeDeviceModal = null;
  }

  // --- Device Containment & Whitelisting Handlers ---
  async function blockDevice(deviceId) {
    try {
      await apiPost('/devices/block', { device_id: deviceId, reason: 'Manual containment by security officer' });
      soundEngine.playThreatAlert();
      showToast(`Device ${deviceId} blocked and hardware port isolated.`, 'danger');
      closeDetailModal();
      fetchTelemetry();
    } catch (e) {
      showToast(`Failed to block device: ${e.message}`, 'danger');
    }
  }

  async function allowDevice(deviceId) {
    try {
      await apiPost('/devices/allow', { device_id: deviceId, reason: 'Approved by security officer' });
      soundEngine.playSuccessChime();
      showToast(`Device ${deviceId} allowed to operate.`, 'safe');
      closeDetailModal();
      fetchTelemetry();
    } catch (e) {
      showToast(`Failed to allow device: ${e.message}`, 'danger');
    }
  }

  async function whitelistDevice(deviceId) {
    const ev = state.events.find(e => e.device_id === deviceId);
    const det = ev?.details || {};
    const name = det.name || 'Authorized Device';
    const vid = det.vendor_id || '';
    const pid = det.product_id || '';
    const serial = det.serial_number || deviceId.split('\\').pop() || 'DEVICE_SN';

    try {
      await apiPost('/policy/whitelist', {
        name,
        vendor_id: vid,
        product_id: pid,
        serial_number: serial,
        notes: 'Whitelisted via device forensic inspection',
      });
      soundEngine.playSuccessChime();
      showToast(`Device ${name} registered in corporate whitelist.`, 'safe');
      closeDetailModal();
      fetchWhitelist();
      fetchTelemetry();
    } catch (e) {
      showToast(`Failed to whitelist device: ${e.message}`, 'danger');
    }
  }

  async function deleteWhitelistEntry(entryId) {
    if (!confirm('Are you sure you want to revoke authorization for this hardware entry?')) return;
    try {
      await apiDelete(`/policy/whitelist/${entryId}`);
      showToast('Hardware authorization revoked.', 'warning');
      fetchWhitelist();
    } catch (e) {
      showToast(`Failed to revoke entry: ${e.message}`, 'danger');
    }
  }

  // --- Diagnostics Attack Simulation Triggers ---
  async function runSimulation(scenarioName, label) {
    const pill = document.getElementById('sim-status-pill');
    const text = document.getElementById('sim-status-text');
    if (pill) pill.style.borderColor = 'var(--cobalt-bright)';
    if (text) text.textContent = `Injecting ${label}...`;

    try {
      const res = await apiPost('/simulate/scenario', { scenario: scenarioName });
      soundEngine.playTone(400, 'sine', 0.1);
      showToast(`Diagnostic Vector: ${res.summary || 'Simulation completed'}`, res.outcome === 'blocked' ? 'danger' : 'safe');
      await fetchTelemetry();
    } catch (e) {
      showToast(`Simulation error: ${e.message}`, 'danger');
    } finally {
      if (pill) pill.style.borderColor = 'var(--border-app)';
      if (text) text.textContent = 'Engine Ready';
    }
  }

  // --- Utility Functions ---
  function formatTimestamp(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) +
        '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch (e) {
      return isoStr;
    }
  }

  function updateSyncTime() {
    const el = document.getElementById('last-refresh-time');
    if (el) {
      const now = new Date();
      el.textContent = `Sync: ${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
    }
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // --- Setup DOM Event Listeners ---
  function setupEventListeners() {
    // Navigation active states and smooth scroll
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        navItems.forEach(n => n.classList.remove('active'));
        item.classList.add('active');
      });
    });

    // View mode toggle
    const viewConnectedBtn = document.getElementById('view-connected-btn');
    const viewAllEventsBtn = document.getElementById('view-all-events-btn');

    if (viewConnectedBtn && viewAllEventsBtn) {
      viewConnectedBtn.addEventListener('click', () => {
        state.viewMode = 'connected';
        viewConnectedBtn.classList.add('active');
        viewAllEventsBtn.classList.remove('active');
        renderEventsTable();
      });

      viewAllEventsBtn.addEventListener('click', () => {
        state.viewMode = 'all';
        viewAllEventsBtn.classList.add('active');
        viewConnectedBtn.classList.remove('active');
        renderEventsTable();
      });
    }

    // Search filter & keyboard shortcut
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchTerm = e.target.value.trim();
        renderEventsTable();
      });

      window.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement !== searchInput) {
          e.preventDefault();
          searchInput.focus();
        }
      });
    }

    // Diagnostics simulation buttons
    const simSafeBtn = document.getElementById('sim-safe-btn');
    const simBadusbBtn = document.getElementById('sim-badusb-btn');
    const simMalwareBtn = document.getElementById('sim-malware-btn');
    const simUnauthorizedBtn = document.getElementById('sim-unauthorized-btn');
    const simSpoofedBtn = document.getElementById('sim-spoofed-btn');

    if (simSafeBtn) simSafeBtn.addEventListener('click', () => runSimulation('safe_usb', 'Safe Storage'));
    if (simBadusbBtn) simBadusbBtn.addEventListener('click', () => runSimulation('badusb', 'BadUSB'));
    if (simMalwareBtn) simMalwareBtn.addEventListener('click', () => runSimulation('malware_drive', 'Malware Media'));
    if (simUnauthorizedBtn) simUnauthorizedBtn.addEventListener('click', () => runSimulation('unauthorized_device', 'Unknown Device'));
    if (simSpoofedBtn) simSpoofedBtn.addEventListener('click', () => runSimulation('spoofed_identity', 'Cloned Hardware'));

    // Top action bar buttons
    const clearBtn = document.getElementById('clear-log-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        if (!confirm('Purge all forensic telemetry events from the database?')) return;
        try {
          await apiDelete('/events');
          showToast('Database event log cleared clean.', 'safe');
          fetchTelemetry();
        } catch (e) {
          showToast(`Error clearing log: ${e.message}`, 'danger');
        }
      });
    }

    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        fetchTelemetry();
        fetchWhitelist();
        showToast('Telemetry re-synced.', 'info');
      });
    }

    const exportCsvBtn = document.getElementById('export-csv-btn');
    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', () => {
        window.open(`${CONFIG.API_PREFIX}/reports/events.csv`, '_blank');
      });
    }

    const exportPdfBtn = document.getElementById('export-pdf-btn');
    if (exportPdfBtn) {
      exportPdfBtn.addEventListener('click', () => {
        window.open(`${CONFIG.API_PREFIX}/reports/incident/pdf`, '_blank');
      });
    }

    // Audio alerts toggle
    const soundToggle = document.getElementById('sound-toggle');
    if (soundToggle) {
      soundToggle.addEventListener('click', () => {
        state.soundEnabled = !state.soundEnabled;
        const label = soundToggle.querySelector('.tool-label');
        if (label) label.textContent = state.soundEnabled ? 'Alerts On' : 'Alerts Off';
        soundToggle.style.color = state.soundEnabled ? 'var(--text-main)' : 'var(--text-dim)';
        if (state.soundEnabled) soundEngine.playSuccessChime();
      });
    }

    // Policy mode change
    const policyModeSelect = document.getElementById('policy-mode-select');
    if (policyModeSelect) {
      policyModeSelect.addEventListener('change', async (e) => {
        const mode = e.target.value;
        try {
          await apiPost('/policy/mode', { mode });
          showToast(`Policy engine switched to ${mode.toUpperCase()}`, 'safe');
          fetchWhitelist();
        } catch (err) {
          showToast(`Failed to update policy mode: ${err.message}`, 'danger');
        }
      });
    }

    // Whitelist Modal
    const openWlModalBtn = document.getElementById('open-whitelist-modal-btn');
    const wlModal = document.getElementById('whitelist-modal');
    const closeWlModalBtn = document.getElementById('close-whitelist-modal-btn');
    const cancelWlBtn = document.getElementById('cancel-whitelist-btn');
    const wlForm = document.getElementById('whitelist-form');

    if (openWlModalBtn && wlModal) {
      openWlModalBtn.addEventListener('click', () => wlModal.classList.remove('hidden'));
    }
    if (closeWlModalBtn && wlModal) {
      closeWlModalBtn.addEventListener('click', () => wlModal.classList.add('hidden'));
    }
    if (cancelWlBtn && wlModal) {
      cancelWlBtn.addEventListener('click', () => wlModal.classList.add('hidden'));
    }

    if (wlForm) {
      wlForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('wl-name')?.value.trim();
        const vid = document.getElementById('wl-vid')?.value.trim();
        const pid = document.getElementById('wl-pid')?.value.trim();
        const serial = document.getElementById('wl-serial')?.value.trim();
        const notes = document.getElementById('wl-notes')?.value.trim();

        try {
          await apiPost('/policy/whitelist', {
            name,
            vendor_id: vid || null,
            product_id: pid || null,
            serial_number: serial,
            notes: notes || null,
          });
          showToast(`Authorized ${name} successfully`, 'safe');
          wlForm.reset();
          wlModal.classList.add('hidden');
          fetchWhitelist();
        } catch (err) {
          showToast(`Error adding entry: ${err.message}`, 'danger');
        }
      });
    }

    // Detail Modal Close
    const closeDetailModalBtn = document.getElementById('close-detail-modal-btn');
    const detailCloseBtn = document.getElementById('detail-close-btn');
    if (closeDetailModalBtn) closeDetailModalBtn.addEventListener('click', closeDetailModal);
    if (detailCloseBtn) detailCloseBtn.addEventListener('click', closeDetailModal);

    // MITRE ATT&CK Modal
    const mitreBtn = document.getElementById('mitre-modal-btn');
    const mitreModal = document.getElementById('mitre-modal');
    const closeMitreBtn = document.getElementById('close-mitre-modal-btn');
    const closeMitreFooterBtn = document.getElementById('close-mitre-footer-btn');

    if (mitreBtn && mitreModal) {
      mitreBtn.addEventListener('click', () => mitreModal.classList.remove('hidden'));
    }
    if (closeMitreBtn && mitreModal) {
      closeMitreBtn.addEventListener('click', () => mitreModal.classList.add('hidden'));
    }
    if (closeMitreFooterBtn && mitreModal) {
      closeMitreFooterBtn.addEventListener('click', () => mitreModal.classList.add('hidden'));
    }

    // Dismiss Alert Banner
    const dismissAlertBtn = document.getElementById('alert-banner-dismiss-btn');
    if (dismissAlertBtn) {
      dismissAlertBtn.addEventListener('click', () => {
        const banner = document.getElementById('security-alert-banner');
        if (banner) banner.classList.add('hidden');
      });
    }
  }

  // --- Initialize Application ---
  function init() {
    initTheme();
    initCharts();
    setupEventListeners();

    // Initial fetch
    fetchTelemetry();
    fetchWhitelist();

    // Polling intervals
    setInterval(fetchTelemetry, CONFIG.POLL_INTERVAL_MS);
    setInterval(sendHeartbeat, CONFIG.HEARTBEAT_INTERVAL_MS);

    // Check query params for notification click routing
    const params = new URLSearchParams(window.location.search);
    const targetDev = params.get('inspect_device') || params.get('device_id');
    const toastAct = params.get('toast_action');

    if (targetDev) {
      setTimeout(() => openDeviceInspection(targetDev), 600);
      if (toastAct === 'block') {
        setTimeout(() => blockDevice(targetDev), 800);
      }
    }
  }

  // Expose global methods for inline HTML table action buttons
  window.USBApp = {
    inspectDevice: openDeviceInspection,
    blockDevice,
    allowDevice,
    whitelistDevice,
    deleteWhitelistEntry,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
