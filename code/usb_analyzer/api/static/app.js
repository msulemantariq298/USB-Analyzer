/**
 * USB Analyzer — Endpoint Hardware Defense Console
 * Real-Time Telemetry Client & Policy Management UI
 */

(() => {
  'use strict';

  const API_BASE = '/api/v1';
  const CLIENT_ID = `dash_${Math.random().toString(36).substring(2, 10)}`;
  const SIDEBAR_STORAGE_KEY = 'usb_analyzer_sidebar_collapsed';
  const THEME_STORAGE_KEY = 'usb_analyzer_theme';

  const state = {
    events: [],
    whitelist: [],
    connectedDevicesCache: [],
    selectedPickerDeviceId: null,
    whitelistInputMode: 'connected', // 'connected' | 'manual'
    policyMode: 'enforce',
    viewMode: 'connected', // 'connected' | 'all' | 'files'
    severityFilter: 'all', // 'all' | 'safe' | 'warning' | 'danger'
    analyzedFiles: [],
    searchTerm: '',
    soundEnabled: true,
    wsConnected: false,
    activeTimeRange: '1h',
    theme: 'light',
    dismissedAlertEventId: null,
  };

  // --- Web Audio Synthesizer ---
  class SoundEngine {
    constructor() {
      this.ctx = null;
    }

    _init() {
      if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        this.ctx = new AudioCtx();
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume();
      }
    }

    playTone(freq, type, duration, gainLevel = 0.07) {
      if (!state.soundEnabled) return;
      try {
        this._init();
        if (!this.ctx) return;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
        gain.gain.setValueAtTime(gainLevel, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + duration);
      } catch {
        // Audio policy ignored
      }
    }

    playSuccessChime() {
      this.playTone(523.25, 'sine', 0.12, 0.05);
      setTimeout(() => this.playTone(659.25, 'sine', 0.18, 0.05), 80);
    }

    playThreatAlert() {
      this.playTone(330, 'sawtooth', 0.16, 0.08);
      setTimeout(() => this.playTone(220, 'sawtooth', 0.24, 0.08), 110);
    }
  }

  const soundEngine = new SoundEngine();

  function refreshIcons() {
    if (typeof window.lucide !== 'undefined' && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  }

  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(message, type = 'info', duration = 3600) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconName = 'info';
    let iconColor = 'var(--primary-blue)';
    if (type === 'safe') {
      iconName = 'check-circle-2';
      iconColor = 'var(--safe)';
    } else if (type === 'danger') {
      iconName = 'shield-alert';
      iconColor = 'var(--danger)';
    } else if (type === 'warning') {
      iconName = 'alert-triangle';
      iconColor = 'var(--warning)';
    }

    toast.innerHTML = `
      <i data-lucide="${iconName}" style="width: 16px; height: 16px; color: ${iconColor}; flex-shrink: 0;"></i>
      <span style="flex: 1; line-height: 1.4;">${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);
    refreshIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(6px)';
      toast.style.transition = 'all 0.18s ease-out';
      setTimeout(() => toast.remove(), 200);
    }, duration);
  }

  // --- Segmented Tab Gliders & View Cross-Fades ---
  function syncSegmentedGlider(container) {
    if (!container) return;
    const activeBtn = container.querySelector('.active');
    let glider = container.querySelector('.seg-glider');
    if (!glider) {
      glider = document.createElement('span');
      glider.className = 'seg-glider';
      glider.setAttribute('aria-hidden', 'true');
      container.insertBefore(glider, container.firstChild);
      container.classList.add('has-glider');
    }
    if (!activeBtn || activeBtn.offsetWidth === 0) {
      glider.style.opacity = '0';
      return;
    }
    glider.style.opacity = '1';
    glider.style.width = `${activeBtn.offsetWidth}px`;
    glider.style.transform = `translateX(${activeBtn.offsetLeft}px)`;
  }

  function syncAllSegmentedGliders() {
    document.querySelectorAll('.audit-tab-switcher, .time-range-switcher').forEach(syncSegmentedGlider);
  }

  function triggerFadeAnimation(el) {
    if (!el) return;
    el.classList.remove('is-tab-switching');
    void el.offsetWidth;
    el.classList.add('is-tab-switching');
  }

  // --- Custom Dropdown Menus ---
  function closeAllCustomMenus() {
    document.querySelectorAll('.custom-menu-panel').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.custom-menu-trigger').forEach(t => t.setAttribute('aria-expanded', 'false'));
    document.querySelectorAll('.console-band.has-menu-open').forEach(b => b.classList.remove('has-menu-open'));
  }

  function setupCustomMenu(wrapId, triggerId, panelId) {
    const wrap = document.getElementById(wrapId);
    const trigger = document.getElementById(triggerId);
    const panel = document.getElementById(panelId);
    if (!wrap || !trigger || !panel) return;

    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      const willOpen = panel.classList.contains('hidden');
      closeAllCustomMenus();
      if (willOpen) {
        const rect = trigger.getBoundingClientRect();
        const isBlock = panel.classList.contains('custom-menu-block');
        if (!isBlock) {
          const spaceBelow = window.innerHeight - rect.bottom;
          panel.classList.toggle('menu-up', spaceBelow < 210 && rect.top > spaceBelow);
          panel.classList.toggle('menu-left', rect.right < 260);
        }
        panel.closest('.console-band')?.classList.add('has-menu-open');
        panel.classList.remove('hidden');
        trigger.setAttribute('aria-expanded', 'true');
      }
    });
  }

  // --- Collapsible Drawer Navigation ---
  function isMobileViewport() {
    return window.innerWidth <= 1024;
  }

  function setSidebarCollapsed(collapsed, persist = true) {
    const shell = document.getElementById('app-shell');
    const toggleBtn = document.getElementById('sidebar-toggle-btn');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (!shell) return;

    shell.classList.toggle('sidebar-collapsed', collapsed);
    if (toggleBtn) {
      toggleBtn.setAttribute('aria-expanded', String(!collapsed));
    }
    if (backdrop) {
      if (!collapsed && isMobileViewport()) {
        backdrop.classList.remove('hidden');
      } else {
        backdrop.classList.add('hidden');
      }
    }
    if (persist && !isMobileViewport()) {
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? '1' : '0');
      } catch {
        // Storage unavailable
      }
    }
  }

  function initSidebarDrawer() {
    let savedCollapsed = false;
    try {
      savedCollapsed = localStorage.getItem(SIDEBAR_STORAGE_KEY) === '1';
    } catch {
      savedCollapsed = false;
    }

    if (isMobileViewport()) {
      setSidebarCollapsed(true, false);
    } else {
      setSidebarCollapsed(savedCollapsed, false);
    }

    const toggleBtn = document.getElementById('sidebar-toggle-btn');
    const closeBtn = document.getElementById('sidebar-close-btn');
    const backdrop = document.getElementById('sidebar-backdrop');
    const shell = document.getElementById('app-shell');

    if (toggleBtn && shell) {
      toggleBtn.addEventListener('click', () => {
        const nextCollapsed = !shell.classList.contains('sidebar-collapsed');
        setSidebarCollapsed(nextCollapsed, true);
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', () => setSidebarCollapsed(true, true));
    }

    if (backdrop) {
      backdrop.addEventListener('click', () => setSidebarCollapsed(true, false));
    }

    window.addEventListener('resize', () => {
      if (!isMobileViewport() && backdrop) {
        backdrop.classList.add('hidden');
      }
    });
  }

  // --- Theme Controller ---
  function applyTheme(theme) {
    state.theme = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', state.theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, state.theme);
    } catch {
      // Ignored
    }

    const themeIcon = document.getElementById('theme-toggle-icon');
    if (themeIcon) {
      themeIcon.setAttribute('data-lucide', state.theme === 'dark' ? 'sun' : 'moon');
      refreshIcons();
    }

    updateChartTheme();
  }

  // --- Chart.js Controllers (Zero Gradients, Montserrat Typography) ---
  let activityChart = null;
  let threatChart = null;

  function chartColorsForTheme() {
    const isDark = state.theme === 'dark';
    return {
      tickColor: isDark ? '#94A3B8' : '#64748B',
      gridColor: isDark ? 'rgba(148, 163, 184, 0.14)' : 'rgba(15, 23, 42, 0.07)',
      lineColor: isDark ? '#3B82F6' : '#1D4ED8',
      fillColor: isDark ? 'rgba(59, 130, 246, 0.14)' : 'rgba(29, 78, 216, 0.09)',
      tooltipBg: isDark ? '#070C17' : '#0F172A',
      emptySlice: isDark ? '#1E293B' : '#E2E8F0',
    };
  }

  function initCharts() {
    const activityCanvas = document.getElementById('activity-chart');
    const threatCanvas = document.getElementById('threat-chart');
    const palette = chartColorsForTheme();

    if (activityCanvas && window.Chart) {
      activityChart = new Chart(activityCanvas, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Events',
            data: [],
            borderColor: palette.lineColor,
            borderWidth: 2,
            backgroundColor: palette.fillColor,
            fill: true,
            tension: 0.25,
            pointBackgroundColor: '#FFFFFF',
            pointBorderColor: palette.lineColor,
            pointBorderWidth: 2,
            pointRadius: 3,
            pointHoverRadius: 5,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              ticks: { color: palette.tickColor, font: { family: 'Montserrat', size: 10.5, weight: '500' } },
              grid: { display: false }
            },
            y: {
              beginAtZero: true,
              ticks: { color: palette.tickColor, precision: 0, font: { family: 'Montserrat', size: 10.5, weight: '500' } },
              grid: { color: palette.gridColor }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: palette.tooltipBg,
              titleFont: { family: 'Montserrat', size: 11, weight: '700' },
              bodyFont: { family: 'Montserrat', size: 11, weight: '500' },
              padding: 8,
              displayColors: false,
            }
          }
        }
      });
    }

    function handleDonutTooltip(context) {
      const tooltipEl = document.getElementById('donut-tooltip');
      if (!tooltipEl) return;

      const { tooltip } = context;
      if (!tooltip || tooltip.opacity === 0 || !tooltip.dataPoints || tooltip.dataPoints.length === 0) {
        tooltipEl.classList.add('hidden');
        tooltipEl.setAttribute('aria-hidden', 'true');
        return;
      }

      const dp = tooltip.dataPoints[0];
      const rawLabel = dp.label || (tooltip.title && tooltip.title[0]) || 'Devices';
      const isEmptySlice = rawLabel === 'No Active Devices';
      const valueText = dp.formattedValue ?? String(dp.raw ?? 0);
      const swatch = (tooltip.labelColors && tooltip.labelColors[0]?.backgroundColor) || '#1D4ED8';

      tooltipEl.replaceChildren();
      const dot = document.createElement('span');
      dot.className = 'donut-tooltip-dot';
      dot.style.backgroundColor = String(swatch);

      const labelSpan = document.createElement('span');
      labelSpan.className = 'donut-tooltip-label';
      labelSpan.textContent = isEmptySlice ? 'No active devices' : `${rawLabel}:`;

      tooltipEl.appendChild(dot);
      tooltipEl.appendChild(labelSpan);

      if (!isEmptySlice) {
        const valSpan = document.createElement('span');
        valSpan.className = 'donut-tooltip-val';
        valSpan.textContent = valueText;
        tooltipEl.appendChild(valSpan);
      }

      const x = typeof tooltip.caretX === 'number' ? tooltip.caretX : 50;
      const y = typeof tooltip.caretY === 'number' ? tooltip.caretY : 50;
      const placeBelow = y >= 50;
      const anchorY = placeBelow ? Math.max(y + 10, 76) : Math.min(y - 10, 24);
      const shiftX = x < 42 ? '-12%' : '-50%';
      const shiftY = placeBelow ? '0%' : '-100%';

      tooltipEl.style.left = `${Math.max(8, x)}px`;
      tooltipEl.style.top = `${anchorY}px`;
      tooltipEl.style.transform = `translate(${shiftX}, ${shiftY})`;
      tooltipEl.classList.remove('hidden');
      tooltipEl.setAttribute('aria-hidden', 'false');
    }

    if (threatCanvas && window.Chart) {
      threatChart = new Chart(threatCanvas, {
        type: 'doughnut',
        data: {
          labels: ['No Active Devices'],
          datasets: [{
            data: [1],
            backgroundColor: [palette.emptySlice],
            borderWidth: 0,
            hoverOffset: 2,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              enabled: false,
              external: handleDonutTooltip,
            }
          },
          cutout: '76%',
        }
      });
    }
  }

  function updateChartTheme() {
    const palette = chartColorsForTheme();
    if (activityChart) {
      activityChart.data.datasets[0].borderColor = palette.lineColor;
      activityChart.data.datasets[0].backgroundColor = palette.fillColor;
      activityChart.data.datasets[0].pointBorderColor = palette.lineColor;
      activityChart.options.scales.x.ticks.color = palette.tickColor;
      activityChart.options.scales.y.ticks.color = palette.tickColor;
      activityChart.options.scales.y.grid.color = palette.gridColor;
      activityChart.options.plugins.tooltip.backgroundColor = palette.tooltipBg;
      activityChart.update('none');
    }
    if (threatChart) {
      renderMetrics();
    }
  }

  function updateHealthDonut(safeDevices, warningDevices, blockedDevices) {
    const palette = chartColorsForTheme();
    const total = safeDevices + warningDevices + blockedDevices;

    if (threatChart) {
      if (total === 0) {
        threatChart.data.labels = ['No Active Devices'];
        threatChart.data.datasets[0].data = [1];
        threatChart.data.datasets[0].backgroundColor = [palette.emptySlice];
      } else {
        threatChart.data.labels = ['Safe', 'Warnings', 'Blocked'];
        threatChart.data.datasets[0].data = [safeDevices, warningDevices, blockedDevices];
        threatChart.data.datasets[0].backgroundColor = ['#059669', '#D97706', '#DC2626'];
      }
      threatChart.update('none');
    }

    const pct = total > 0 ? Math.round((safeDevices / total) * 100) : 100;
    const scoreEl = document.getElementById('overview-health-score');
    if (scoreEl) scoreEl.textContent = `${pct}%`;

    const safeEl = document.getElementById('legend-safe-count');
    const monEl = document.getElementById('legend-monitored-count');
    const blkEl = document.getElementById('legend-blocked-count');
    if (safeEl) safeEl.textContent = safeDevices;
    if (monEl) monEl.textContent = warningDevices;
    if (blkEl) blkEl.textContent = blockedDevices;

    const healthBadge = document.getElementById('health-status-badge');
    const healthText = document.getElementById('health-status-text');
    if (healthBadge && healthText) {
      healthBadge.classList.remove('is-warning', 'is-danger');
      if (blockedDevices > 0) {
        healthBadge.classList.add('is-danger');
        healthText.textContent = 'Threats Blocked';
      } else if (warningDevices > 0) {
        healthBadge.classList.add('is-warning');
        healthText.textContent = 'Needs Review';
      } else {
        healthText.textContent = 'Healthy';
      }
    }
  }

  // --- API Client Layer ---
  async function apiGet(endpoint) {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return res.json();
  }

  async function apiPost(endpoint, body) {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function apiDelete(endpoint) {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      method: 'DELETE',
      headers: { 'Accept': 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (res.status === 204) return null;
    return res.json();
  }

  // --- Heartbeat & Windows Notification Action Intercept ---
  async function sendHeartbeat() {
    try {
      const data = await apiPost(`/dashboard/heartbeat?client_id=${CLIENT_ID}`, {});
      updateMonitorStatus(true);
      if (data.actions && data.actions.length > 0) {
        for (const act of data.actions) {
          await handleNotificationAction(act);
        }
      }
    } catch {
      updateMonitorStatus(false);
    }
  }

  async function handleNotificationAction(act) {
    if (!act || !act.device_id) return;
    if (act.action === 'allow') {
      await allowDevice(act.device_id);
    } else if (act.action === 'block') {
      await blockDevice(act.device_id);
    } else {
      await fetchTelemetry();
      openDeviceInspection(act.device_id);
    }
  }

  function updateMonitorStatus(online) {
    const apiStatusEl = document.getElementById('api-status');
    const statusIcon = document.getElementById('bus-status-icon');

    if (apiStatusEl) {
      apiStatusEl.textContent = online
        ? (state.wsConnected ? 'Live WebSocket' : 'Polling Active')
        : 'Reconnecting...';
      apiStatusEl.style.color = online ? 'var(--safe)' : 'var(--warning)';
    }
    if (statusIcon) {
      statusIcon.style.color = online ? 'var(--safe)' : 'var(--warning)';
    }
  }

  // --- Telemetry Polling & Analytics ---
  async function syncConnectedDevices() {
    try {
      return await apiPost('/devices/scan', {});
    } catch {
      return null;
    }
  }

  async function scanUsbStorage({ silent = false, volumePath = null, deviceId = null } = {}) {
    try {
      const payload = {};
      if (volumePath) payload.volume_path = volumePath;
      if (deviceId) payload.device_id = deviceId;
      const res = await apiPost('/storage/scan', payload);
      await fetchTelemetry();
      if (!silent) {
        if (!res || res.volumes_scanned === 0) {
          showToast('No mounted removable USB storage volumes detected to scan.', 'info');
        } else {
          const msg = `Scanned ${res.files_scanned} file(s) across ${res.volumes_scanned} USB volume(s)`
            + (res.new_files_count > 0 ? ` (${res.new_files_count} new/modified)` : '')
            + ` — Max Risk Score: ${res.max_risk_score}/100.`;
          const kind = res.max_risk_score >= 50 ? 'danger' : (res.max_risk_score >= 20 ? 'warning' : 'safe');
          showToast(msg, kind);
        }
      }
      return res;
    } catch (err) {
      if (!silent) {
        showToast(`USB storage scan failed: ${err.message}`, 'danger');
      }
      return null;
    }
  }

  async function loadTimeRangeAnalytics(range = state.activeTimeRange, animate = false) {
    try {
      const data = await apiGet(`/analytics/activity?range=${range}`);
      if (activityChart) {
        activityChart.data.labels = data.labels;
        activityChart.data.datasets[0].data = data.data;
        activityChart.update(animate ? undefined : 'none');
      }
      const totalEl = document.getElementById('analytics-total-events');
      const suspEl = document.getElementById('analytics-suspicious-events');
      if (totalEl) totalEl.textContent = data.total_events;
      if (suspEl) suspEl.textContent = data.suspicious_events;
    } catch (err) {
      console.warn('Analytics fetch error:', err);
    }
  }

  async function fetchTelemetry() {
    try {
      const data = await apiGet('/events?limit=200');
      const events = Array.isArray(data) ? data : (data.events || []);

      const prevCount = state.events.length;
      state.events = events;

      if (events.length > prevCount && prevCount > 0) {
        const newest = events[0];
        if (newest && newest.severity === 'critical') {
          soundEngine.playThreatAlert();
        }
      }

      updateMonitorStatus(true);
      collectLatestAnalyzedFiles();
      renderMetrics();
      renderEventsTable();
      renderFileAnalysisTable();
      checkSecurityAlertBanner();
      await loadTimeRangeAnalytics(state.activeTimeRange);
    } catch (err) {
      updateMonitorStatus(false);
      console.warn('Telemetry sync error:', err.message);
    }
  }

  async function fetchWhitelist() {
    try {
      const data = await apiGet('/policy/whitelist');
      state.whitelist = Array.isArray(data) ? data : [];
      renderWhitelistTable();
    } catch {
      // Whitelist offline
    }
  }

  async function fetchPolicyStatus() {
    try {
      const data = await apiGet('/policy/status');
      if (data && data.mode) {
        applyPolicyModeUI(data.mode);
      }
    } catch {
      // Fallback to default
    }
  }

  function syncSettingsPolicyMenu(mode) {
    const normalized = mode === 'audit_only' ? 'audit_only' : 'enforce';
    const isAudit = normalized === 'audit_only';
    const hiddenInput = document.getElementById('settings-policy-mode');
    const selectedLabel = document.getElementById('settings-policy-selected-label');
    const selectedIcon = document.getElementById('settings-policy-selected-icon');
    const settingsPanel = document.getElementById('settings-policy-menu-panel');

    if (hiddenInput) hiddenInput.value = normalized;
    if (selectedLabel) {
      selectedLabel.textContent = isAudit
        ? 'Audit Only (Telemetry & Alert Logging Only)'
        : 'Enforce (Active Blocking & Containment)';
    }
    if (selectedIcon) {
      selectedIcon.setAttribute('data-lucide', isAudit ? 'eye' : 'shield-check');
      selectedIcon.style.color = isAudit ? 'var(--warning)' : 'var(--primary-blue)';
      refreshIcons();
    }
    if (settingsPanel) {
      settingsPanel.querySelectorAll('[data-settings-policy-value]').forEach(item => {
        const active = item.getAttribute('data-settings-policy-value') === normalized;
        item.classList.toggle('active', active);
        item.setAttribute('aria-checked', String(active));
      });
    }
  }

  function applyPolicyModeUI(mode) {
    state.policyMode = mode;
    const isAudit = mode === 'audit_only';
    const labelText = isAudit ? 'Audit Only' : 'Enforce';

    const policyLabel = document.getElementById('policy-menu-label');
    const policyPanel = document.getElementById('policy-menu-panel');

    if (policyLabel) policyLabel.textContent = labelText;

    if (policyPanel) {
      policyPanel.querySelectorAll('[data-policy-value]').forEach(item => {
        const active = item.getAttribute('data-policy-value') === mode;
        item.classList.toggle('active', active);
        item.setAttribute('aria-checked', String(active));
      });
    }

    syncSettingsPolicyMenu(mode);
  }

  // --- Per-Device State Evaluation (Chronological: events[0] is newest) ---
  function summarizeDeviceStatus(evList) {
    const latestEv = evList[0];
    const connectEv = evList.find(e => e.event_type === 'device.connected' && e.details && (e.details.vendor_id || e.details.name))
      || evList.find(e => e.details && (e.details.vendor_id || e.details.name))
      || latestEv;
    const reasonEv = evList.find(e => e.details && (e.details.reason || e.details.threat_type || e.details.summary)) || latestEv;

    const latestScanEv = evList.find(e => e.event_type === 'scan.completed');

    const latestDecisionEv = evList.find(e =>
      e.event_type === 'device.allowed' ||
      e.event_type === 'policy.allowed' ||
      e.event_type === 'device.blocked' ||
      e.event_type === 'device.spoofed_identity' ||
      e.event_type === 'device.attack_hardware' ||
      e.event_type === 'hid.injection_detected' ||
      e.event_type === 'policy.violation' ||
      e.event_type === 'device.suspicious' ||
      e.event_type === 'scan.completed'
    );

    const isAllowed = Boolean(
      latestDecisionEv &&
      (latestDecisionEv.event_type === 'device.allowed' || latestDecisionEv.event_type === 'policy.allowed')
    );

    const isLatestScanClean = Boolean(
      latestScanEv &&
      latestScanEv.severity === 'info' &&
      !latestScanEv.details?.has_threats
    );

    const lastBlockEv = evList.find(e => e.event_type === 'device.blocked');
    const isPortDisabled = Boolean(lastBlockEv && lastBlockEv.details?.blocked !== false);
    const hasHardwareAttack = evList.some(e =>
      e.event_type === 'device.spoofed_identity' ||
      e.event_type === 'device.attack_hardware' ||
      e.event_type === 'hid.injection_detected'
    );
    const storageClearedAfterThreat = Boolean(
      isLatestScanClean &&
      !isPortDisabled &&
      !hasHardwareAttack &&
      latestScanEv &&
      (!lastBlockEv || new Date(latestScanEv.time).getTime() >= new Date(lastBlockEv.time).getTime())
    );

    const hasCritical = !isAllowed && !storageClearedAfterThreat && (
      hasHardwareAttack ||
      evList.some(e =>
        (e.severity === 'critical' && e.event_type !== 'scan.completed' && e.event_type !== 'device.blocked') ||
        (e.event_type === 'device.blocked' && e.details?.threat_type !== 'storage_malware')
      ) ||
      Boolean(latestScanEv && (latestScanEv.severity === 'critical' || latestScanEv.details?.has_threats))
    );

    const isBlocked = !isAllowed && !storageClearedAfterThreat && (
      hasCritical ||
      (latestDecisionEv && latestDecisionEv.event_type === 'device.blocked' && latestDecisionEv.details?.blocked !== false)
    );

    const isWarning = !isAllowed && !isBlocked && !storageClearedAfterThreat && (
      evList.some(e =>
        (e.severity === 'warning' && e.event_type !== 'scan.completed') ||
        e.event_type === 'policy.violation' ||
        e.event_type === 'device.suspicious'
      ) ||
      Boolean(latestScanEv && latestScanEv.severity === 'warning')
    );

    const isDisconnected = latestEv && latestEv.event_type === 'device.disconnected';

    const severity = isBlocked ? 'critical' : (isAllowed ? 'info' : (isWarning ? 'warning' : 'info'));
    const eventType = isBlocked ? 'device.blocked' : (isAllowed ? 'device.allowed' : (isWarning ? 'policy.violation' : latestEv.event_type));
    const verdict = isAllowed ? 'SAFE' : (isBlocked ? 'BLOCKED' : (isWarning ? 'CONTAINED' : 'SAFE'));

    let reason = 'Standard peripheral verified';
    if (isAllowed) {
      reason = latestDecisionEv?.details?.reason || 'Approved by operator';
    } else if (isBlocked || isWarning) {
      reason = reasonEv.details?.reason || reasonEv.details?.threat_type || reasonEv.details?.summary || 'Policy review required';
    } else if (isDisconnected) {
      reason = 'Device detached from USB bus';
    } else if (latestEv.event_type === 'scan.completed' && latestEv.details?.summary) {
      reason = latestEv.details.summary;
    }

    let action = latestEv.details?.action_taken || latestEv.details?.action || 'Connected';
    if (isAllowed) {
      action = latestDecisionEv?.details?.action_taken || 'Allowed & Active';
    } else if (isBlocked) {
      const blockEv = evList.find(e => e.event_type === 'device.blocked');
      if (blockEv && blockEv.details?.blocked === false) {
        action = blockEv.details?.action_taken || 'Block Failed (Run as Admin)';
      } else {
        action = blockEv?.details?.action_taken || 'Isolated & Disabled';
      }
    } else if (isWarning) {
      const warnEv = evList.find(e => e.event_type === 'policy.violation' || e.event_type === 'scan.completed');
      action = warnEv?.details?.action_taken || 'Review Required';
    } else if (isDisconnected) {
      action = 'Disconnected';
    }

    return {
      latestEv,
      connectEv,
      reasonEv,
      isAllowed,
      isBlocked,
      isWarning,
      isDisconnected,
      severity,
      eventType,
      verdict,
      reason,
      action,
    };
  }

  // --- Metric HUD Render (100% Real Data) ---
  function renderMetrics() {
    const totalEventsEl = document.getElementById('total-events');
    const connectedDevicesEl = document.getElementById('connected-devices-val');
    const threatsDetectedEl = document.getElementById('threats-detected-val');
    const devicesBlockedEl = document.getElementById('devices-blocked');
    const activeScansEl = document.getElementById('active-scans');
    const policyWarningsEl = document.getElementById('policy-warnings');
    const flaggedFilesEl = document.getElementById('flagged-files');
    const storageScansEl = document.getElementById('storage-scans');
    const navActiveBadge = document.getElementById('nav-active-badge');

    const deviceMap = new Map();
    for (const ev of state.events) {
      if (!deviceMap.has(ev.device_id)) deviceMap.set(ev.device_id, []);
      deviceMap.get(ev.device_id).push(ev);
    }

    let connectedDevices = 0;
    let safeDevices = 0;
    let warningDevices = 0;
    let blockedDevices = 0;

    for (const [, evList] of deviceMap.entries()) {
      const status = summarizeDeviceStatus(evList);
      if (!status.isDisconnected) {
        connectedDevices++;
      }
      if (status.isBlocked) {
        blockedDevices++;
      } else if (status.isWarning) {
        warningDevices++;
      } else {
        safeDevices++;
      }
    }

    let total = state.events.length;
    let warnings = 0;
    let critical = 0;
    let scans = 0;
    let startedScans = 0;
    let finishedScans = 0;
    let flaggedFiles = 0;

    for (const ev of state.events) {
      if (ev.severity === 'critical') critical++;
      if (ev.severity === 'warning') warnings++;

      if (ev.event_type === 'scan.started') {
        startedScans++;
      } else if (ev.event_type === 'scan.completed' || ev.event_type === 'scan.failed') {
        scans++;
        finishedScans++;
      }

      if (ev.event_type === 'scan.completed' && ev.details) {
        if (Array.isArray(ev.details.flagged)) {
          flaggedFiles += ev.details.flagged.length;
        } else if (typeof ev.details.flagged_count === 'number') {
          flaggedFiles += ev.details.flagged_count;
        }
      } else if (ev.event_type === 'scan.threat_detected') {
        if (ev.details && Array.isArray(ev.details.flagged_files)) {
          flaggedFiles += ev.details.flagged_files.length;
        } else {
          flaggedFiles++;
        }
      }
    }

    const activeScans = Math.max(0, startedScans - finishedScans);

    if (totalEventsEl) totalEventsEl.textContent = total;
    if (connectedDevicesEl) connectedDevicesEl.textContent = connectedDevices;
    if (threatsDetectedEl) threatsDetectedEl.textContent = critical;
    if (devicesBlockedEl) devicesBlockedEl.textContent = blockedDevices;
    if (activeScansEl) activeScansEl.textContent = activeScans;
    if (policyWarningsEl) policyWarningsEl.textContent = warnings;
    if (flaggedFilesEl) flaggedFilesEl.textContent = flaggedFiles;
    if (storageScansEl) storageScansEl.textContent = scans;
    if (navActiveBadge) navActiveBadge.textContent = connectedDevices;

    updateHealthDonut(safeDevices, warningDevices, blockedDevices);
  }

  // --- Urgent Threat Callout Banner ---
  function checkSecurityAlertBanner() {
    const banner = document.getElementById('security-alert-banner');
    const bannerTitle = document.getElementById('alert-banner-title');
    const bannerMsg = document.getElementById('alert-banner-msg');
    const inspectBtn = document.getElementById('alert-banner-inspect-btn');
    if (!banner) return;

    const criticalEvent = state.events.find(e => {
      if (e.severity !== 'critical') return false;
      const devEvents = findDeviceEvents(e.device_id);
      const summary = summarizeDeviceStatus(devEvents);
      return !summary.isAllowed && summary.isBlocked;
    });

    if (criticalEvent && String(criticalEvent.id) !== String(state.dismissedAlertEventId)) {
      banner.classList.remove('hidden');
      const devEvents = findDeviceEvents(criticalEvent.device_id);
      const summary = summarizeDeviceStatus(devEvents);
      const friendlyName = summary.connectEv?.details?.friendly_name || summary.connectEv?.details?.name || criticalEvent.device_id;
      const det = criticalEvent.details || {};
      const reason = det.summary || det.reason || 'Anomalous hardware violation intercepted';
      if (bannerTitle) bannerTitle.textContent = `CRITICAL THREAT: ${criticalEvent.event_type.toUpperCase()}`;
      if (bannerMsg) bannerMsg.textContent = `${friendlyName} — ${reason}`;
      if (inspectBtn) {
        inspectBtn.onclick = () => openDeviceInspection(criticalEvent.device_id);
      }
    } else {
      banner.classList.add('hidden');
    }
  }

  // --- Utility Helpers ---
  function extractParam(str, prefix) {
    if (!str) return '';
    const match = str.match(new RegExp(prefix + '([0-9a-fA-F]+)'));
    return match ? match[1] : '';
  }

  function extractSerial(str) {
    if (!str) return '';
    const parts = str.split('\\');
    return parts.length > 2 ? parts[parts.length - 1] : '';
  }

  function formatHex(val) {
    if (!val) return 'N/A';
    val = String(val).trim();
    if (!val) return 'N/A';
    if (val.toLowerCase().startsWith('0x')) return val;
    return `0x${val.toUpperCase()}`;
  }

  function findDeviceEvents(deviceId) {
    if (!deviceId) return [];
    const target = deviceId.toLowerCase();
    return state.events.filter(e => {
      const id = (e.device_id || '').toLowerCase();
      return id === target || id.includes(target) || target.includes(id);
    });
  }

  function resolveDeviceCategory(devName = '', devClass = '', devType = '') {
    const text = `${devName} ${devClass} ${devType}`.toLowerCase();
    if (text.includes('card reader') || text.includes('cardreader') || text.includes('sd reader') || text.includes('rtsuer')) {
      return { category: 'Card Reader', icon: 'hard-drive', colorClass: 'cat-blue' };
    }
    if (text.includes('usb hub') || text.includes('usbhub') || text.includes('generic hub')) {
      return { category: 'USB Hub', icon: 'usb', colorClass: 'cat-cyan' };
    }
    if (text.includes('camera') || text.includes('video') || text.includes('webcam')) {
      return { category: 'Webcam', icon: 'camera', colorClass: 'cat-purple' };
    }
    if (text.includes('bluetooth') || text.includes('bth') || text.includes('bt ')) {
      return { category: 'Bluetooth Adapter', icon: 'bluetooth', colorClass: 'cat-blue' };
    }
    if (text.includes('keyboard') || text.includes('mouse') || text.includes('hid')) {
      return { category: 'Keyboard & Mouse', icon: 'keyboard', colorClass: 'cat-cyan' };
    }
    if (text.includes('storage') || text.includes('drive') || text.includes('disk') || text.includes('mass storage') || text.includes('usbstor')) {
      return { category: 'USB Storage Drive', icon: 'hard-drive', colorClass: 'cat-blue' };
    }
    if (text.includes('network') || text.includes('ethernet') || text.includes('wlan') || text.includes('wi-fi')) {
      return { category: 'Network Adapter', icon: 'network', colorClass: 'cat-green' };
    }
    return { category: devType || 'USB Peripheral', icon: 'usb', colorClass: 'cat-blue' };
  }

  function getActionStatusIcon(verdict) {
    if (verdict === 'BLOCKED' || verdict === 'DANGER') {
      return '<i data-lucide="shield-alert" class="action-icon-danger" style="width: 14px; height: 14px;"></i>';
    }
    if (verdict === 'CONTAINED' || verdict === 'WARNING') {
      return '<i data-lucide="alert-triangle" class="action-icon-warning" style="width: 14px; height: 14px;"></i>';
    }
    return '<i data-lucide="check-circle-2" class="action-icon-safe" style="width: 14px; height: 14px;"></i>';
  }

  function classifyEventVerdict(ev) {
    const det = ev?.details || {};
    return getVerdictCategory(
      ev?.severity,
      ev?.event_type,
      det.verdict || '',
      det.action_taken || det.action || ''
    );
  }

  function getVerdictCategory(sev, eventType, verdict = '', actionTaken = '') {
    if (eventType === 'device.allowed' || eventType === 'policy.allowed' || verdict === 'SAFE' || actionTaken === 'Allowed & Active') {
      return 'safe';
    }
    if (eventType === 'device.blocked' || sev === 'critical' || verdict === 'BLOCKED' || verdict === 'DANGER') {
      return 'danger';
    }
    if (sev === 'warning' || eventType === 'policy.violation' || eventType === 'device.suspicious' || verdict === 'CONTAINED' || verdict === 'WARNING') {
      return 'warning';
    }
    return 'safe';
  }

  function applyAuditFilterUI(filterValue) {
    const allowed = ['all', 'safe', 'warning', 'danger'];
    const normalized = allowed.includes(filterValue) ? filterValue : 'all';
    state.severityFilter = normalized;

    const labelMap = {
      all: 'All',
      safe: 'Safe',
      warning: 'Contained',
      danger: 'Blocked',
    };
    const labelEl = document.getElementById('audit-filter-label');
    if (labelEl) labelEl.textContent = labelMap[normalized];

    const panel = document.getElementById('audit-filter-menu-panel');
    if (panel) {
      panel.querySelectorAll('[data-filter-value]').forEach(item => {
        const active = item.getAttribute('data-filter-value') === normalized;
        item.classList.toggle('active', active);
        item.setAttribute('aria-checked', String(active));
      });
    }
  }

  function formatBytes(bytes) {
    const val = Number(bytes || 0);
    if (val < 1024) return `${val} B`;
    if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB`;
    if (val < 1024 * 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(2)} MB`;
    return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function collectLatestAnalyzedFiles() {
    const latestVolumeScans = new Map();
    for (const ev of state.events) {
      if (ev.event_type !== 'scan.completed' || !ev.details) continue;
      const vol = (ev.details.volume_path || ev.details.root || ev.device_id || 'USB').toString();
      const key = `${ev.device_id}::${vol.toLowerCase()}`;
      if (!latestVolumeScans.has(key)) {
        latestVolumeScans.set(key, ev);
      }
    }

    const combined = [];
    for (const scanEv of latestVolumeScans.values()) {
      const vol = scanEv.details.volume_path || scanEv.details.root || 'USB Volume';
      const files = Array.isArray(scanEv.details.file_analyses) && scanEv.details.file_analyses.length > 0
        ? scanEv.details.file_analyses
        : (Array.isArray(scanEv.details.flagged) ? scanEv.details.flagged : []);
      for (const item of files) {
        combined.push({
          ...item,
          volume_path: vol,
          device_id: scanEv.device_id,
          scan_time: scanEv.time,
        });
      }
    }
    combined.sort((a, b) => (Number(b.risk_score || 0) - Number(a.risk_score || 0)) || String(a.path || '').localeCompare(String(b.path || '')));
    state.analyzedFiles = combined;
  }

  function renderFileAnalysisTable() {
    const tbody = document.getElementById('file-analysis-table-body');
    if (!tbody) return;

    let files = state.analyzedFiles || [];
    if (state.severityFilter !== 'all') {
      files = files.filter(f => {
        const score = Number(f.risk_score || 0);
        if (state.severityFilter === 'danger') return score >= 50 || (f.flags || []).some(fl => fl.startsWith('yara:') || fl.startsWith('malware_hash:') || fl === 'eicar_test_file');
        if (state.severityFilter === 'warning') return score >= 20 && score < 50;
        return score < 20 && !(f.flags || []).length;
      });
    }

    if (state.searchTerm) {
      const q = state.searchTerm.toLowerCase();
      files = files.filter(f =>
        String(f.path || '').toLowerCase().includes(q) ||
        String(f.sha256 || '').toLowerCase().includes(q) ||
        String(f.md5 || '').toLowerCase().includes(q) ||
        String(f.file_type || '').toLowerCase().includes(q) ||
        String(f.volume_path || '').toLowerCase().includes(q) ||
        (f.flags || []).some(fl => fl.toLowerCase().includes(q))
      );
    }

    if (files.length === 0) {
      const filtered = Boolean(state.searchTerm) || state.severityFilter !== 'all';
      tbody.innerHTML = `
        <tr class="table-empty-row">
          <td colspan="6">
            <div class="empty-state-wrap">
              <i data-lucide="scan-search" class="empty-icon-shield" style="width: 26px; height: 26px;"></i>
              <strong class="empty-title">${filtered ? 'No Analyzed Files Match Current Filter' : 'No USB Storage Files Scanned Yet'}</strong>
              <span class="empty-desc">${filtered
                ? 'Clear your search query or verdict filter to inspect all scanned files.'
                : 'Click Scan USB Files in the top toolbar to scan mounted USB volumes for hashes, file types, entropy, metadata, and YARA signatures.'}</span>
            </div>
          </td>
        </tr>
      `;
      refreshIcons();
      return;
    }

    tbody.innerHTML = files.map((f, idx) => {
      const score = Number(f.risk_score || 0);
      const entropy = Number(f.entropy || 0);
      const entropyPct = Math.min(100, Math.round((entropy / 8.0) * 100));
      const meta = f.metadata || {};
      const mismatch = Boolean(meta.extension_mismatch);
      const isHiddenOrSys = Boolean(meta.hidden || meta.system);
      const changeStatus = String(f.change_status || 'initial').toLowerCase();

      const riskFillClass = score >= 50 ? 'fill-danger' : (score >= 20 ? 'fill-warning' : 'fill-safe');
      const entropyFillClass = entropy >= 7.2 && !meta.expected_compressed ? 'fill-danger' : (entropy >= 6.8 && !meta.expected_compressed ? 'fill-warning' : 'fill-blue');
      const entropyLabel = meta.expected_compressed && entropy >= 6.8 ? 'Compressed' : (entropy >= 7.2 ? 'High Packed' : (entropy >= 6.8 ? 'Elevated' : 'Normal'));
      const riskLabel = score >= 80 ? 'CRITICAL' : (score >= 50 ? 'HIGH' : (score >= 20 ? 'SUSPICIOUS' : 'CLEAN'));

      const changeBadgeHtml = changeStatus === 'new'
        ? '<span class="change-pill is-new">NEW</span>'
        : (changeStatus === 'modified' ? '<span class="change-pill is-modified">MODIFIED</span>' : '');

      const attrBadgeHtml = isHiddenOrSys
        ? `<span class="change-pill">${meta.system ? 'SYSTEM' : 'HIDDEN'}</span>`
        : '';

      const flags = Array.isArray(f.flags) ? f.flags : [];
      const chipsHtml = flags.slice(0, 4).map(fl => {
        const cls = (fl.startsWith('yara:') || fl.startsWith('malware_hash:') || fl === 'eicar_test_file' || fl === 'extension_signature_mismatch' || fl === 'rtlo_filename_spoof' || fl === 'double_extension_masquerade')
          ? 'is-danger'
          : 'is-warning';
        return `<span class="indicator-chip ${cls}">${escapeHtml(fl)}</span>`;
      }).join('');

      return `
        <tr>
          <td>
            <div class="file-cell-wrap">
              <div class="file-name-row">
                <span class="file-path-title">${escapeHtml(f.path)}</span>
                ${changeBadgeHtml}
                ${attrBadgeHtml}
              </div>
              <span class="file-sub-meta tabular-num">${escapeHtml(f.volume_path || 'USB')} &middot; ${formatBytes(f.size)}</span>
            </div>
          </td>
          <td>
            <div class="file-cell-wrap">
              <span style="font-size: 12px; font-weight: 600; color: var(--text-main);">${escapeHtml(f.file_type || 'Unknown')}</span>
              <span class="file-sub-meta">Ext: ${escapeHtml(meta.extension || '(none)')}${mismatch ? ' &middot; <strong style="color: var(--danger);">MISMATCH</strong>' : ''}</span>
            </div>
          </td>
          <td>
            <div class="metric-bar-stack">
              <div class="metric-bar-head tabular-num">
                <span>${entropy.toFixed(2)} b/B</span>
                <span class="metric-bar-sub">${entropyLabel}</span>
              </div>
              <div class="metric-bar-track"><div class="metric-bar-fill ${entropyFillClass}" style="width: ${entropyPct}%;"></div></div>
            </div>
          </td>
          <td>
            <div class="metric-bar-stack">
              <div class="metric-bar-head tabular-num">
                <span>${score} / 100</span>
                <span class="metric-bar-sub">${riskLabel}</span>
              </div>
              <div class="metric-bar-track"><div class="metric-bar-fill ${riskFillClass}" style="width: ${score}%;"></div></div>
            </div>
          </td>
          <td>
            <div class="file-cell-wrap">
              <span class="file-sub-meta tabular-num" title="${escapeHtml(f.sha256 || '')}">SHA256: ${escapeHtml(String(f.sha256 || '').slice(0, 16))}...</span>
              ${f.md5 ? `<span class="file-sub-meta tabular-num">MD5: ${escapeHtml(String(f.md5).slice(0, 16))}...</span>` : ''}
              ${chipsHtml ? `<div class="indicator-chip-row">${chipsHtml}</div>` : ''}
            </div>
          </td>
          <td>
            <div class="table-actions-cell">
              <button type="button" class="btn-table-inspect btn-inspect-file-row" data-file-index="${idx}">Inspect</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    tbody.onclick = (e) => {
      const btn = e.target.closest('.btn-inspect-file-row');
      if (!btn) return;
      const idx = Number(btn.getAttribute('data-file-index'));
      if (!Number.isNaN(idx) && files[idx]) {
        openFileInspection(files[idx]);
      }
    };
  }

  // --- Events Table Render (Non-Repetitive Columns) ---
  function renderEventsTable() {
    const tbody = document.getElementById('events-table-body');
    if (!tbody) return;

    let displayList = [];
    if (state.viewMode === 'connected') {
      const deviceMap = new Map();
      for (const ev of state.events) {
        if (!deviceMap.has(ev.device_id)) deviceMap.set(ev.device_id, []);
        deviceMap.get(ev.device_id).push(ev);
      }

      displayList = Array.from(deviceMap.entries()).map(([deviceId, evList]) => {
        const s = summarizeDeviceStatus(evList);
        return {
          id: s.latestEv.id,
          time: s.latestEv.time,
          device_id: deviceId,
          source: s.latestEv.source,
          severity: s.severity,
          event_type: s.eventType,
          details: {
            ...s.latestEv.details,
            name: s.connectEv.details?.name || s.latestEv.details?.name || deviceId,
            vendor_id: s.connectEv.details?.vendor_id || s.latestEv.details?.vendor_id || extractParam(deviceId, 'VID_'),
            product_id: s.connectEv.details?.product_id || s.latestEv.details?.product_id || extractParam(deviceId, 'PID_'),
            serial_number: s.connectEv.details?.serial_number || s.latestEv.details?.serial_number || extractSerial(deviceId),
            device_type: s.connectEv.details?.device_type || s.latestEv.details?.device_type || (s.latestEv.source === 'storage-scanner' ? 'Storage Volume' : 'USB Bus'),
            reason: s.reason,
            action: s.action,
            verdict: s.verdict,
          }
        };
      });
    } else {
      displayList = state.events;
    }

    if (state.severityFilter !== 'all') {
      displayList = displayList.filter(ev => classifyEventVerdict(ev) === state.severityFilter);
    }

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
          (d.reason && d.reason.toLowerCase().includes(q)) ||
          (d.summary && d.summary.toLowerCase().includes(q))
        );
      });
    }

    const hasActiveFilter = Boolean(state.searchTerm) || state.severityFilter !== 'all';
    if (displayList.length === 0) {
      tbody.innerHTML = `
        <tr class="table-empty-row">
          <td colspan="7">
            <div class="empty-state-wrap">
              <i data-lucide="usb" class="empty-icon-shield" style="width: 26px; height: 26px;"></i>
              <strong class="empty-title">${hasActiveFilter ? 'No Matching Devices Found' : 'No Hardware Events Recorded Yet'}</strong>
              <span class="empty-desc">${hasActiveFilter
                ? 'No recorded entries match your active search text or verdict filter.'
                : 'Plug in a physical USB drive or peripheral, or click Refresh to synchronize currently attached devices.'}</span>
            </div>
          </td>
        </tr>
      `;
      refreshIcons();
      return;
    }

    tbody.innerHTML = displayList.map(ev => {
      const det = ev.details || {};
      const timeStr = formatTimestamp(ev.time);
      const name = det.name || ev.device_id;
      const vidHex = formatHex(det.vendor_id || extractParam(ev.device_id, 'VID_'));
      const pidHex = formatHex(det.product_id || extractParam(ev.device_id, 'PID_'));
      const serial = det.serial_number || extractSerial(ev.device_id) || 'N/A';
      const hardwareSub = `VID: ${vidHex} | PID: ${pidHex} | SN: ${serial}`;

      const catInfo = resolveDeviceCategory(name, det.device_class, det.device_type);
      const badge = getSeverityBadge(ev.severity, ev.event_type, det.verdict, det.action_taken || det.action);

      let reasonText = det.reason || det.summary || 'Standard peripheral verified';
      if (ev.event_type === 'scan.started') {
        reasonText = `Storage scan started for ${det.volume_path || 'mounted volume'}`;
      } else if (ev.event_type === 'scan.completed' && Array.isArray(det.flagged) && det.flagged.length > 0 && ev.severity === 'warning') {
        reasonText = `${det.flagged.length} file(s) flagged via filename-based indicators (${det.volume_path || 'volume'})`;
      } else if (ev.event_type === 'device.connected' && ev.severity === 'info' && !det.reason) {
        reasonText = 'Standard peripheral verified';
      }

      const actionText = det.action_taken || det.action || (ev.event_type === 'device.blocked' ? 'Isolated & Disabled' : ev.event_type);
      const verdictForIcon = det.verdict || (ev.severity === 'critical' ? 'BLOCKED' : (ev.severity === 'warning' ? 'CONTAINED' : 'SAFE'));
      const actionIconHtml = getActionStatusIcon(verdictForIcon);

      return `
        <tr>
          <td class="th-timestamp">${timeStr}</td>
          <td>
            <div class="peripheral-cell">
              <div class="device-category-icon ${catInfo.colorClass}">
                <i data-lucide="${catInfo.icon}" style="width: 15px; height: 15px;"></i>
              </div>
              <div class="peripheral-meta">
                <span class="peripheral-name">${escapeHtml(name)}</span>
                <span class="peripheral-ids">${escapeHtml(hardwareSub)}</span>
              </div>
            </div>
          </td>
          <td class="bus-class-cell">${escapeHtml(catInfo.category)}</td>
          <td>${badge}</td>
          <td style="font-size: 11.5px; color: var(--text-body); max-width: 230px; overflow-wrap: break-word;">${escapeHtml(reasonText)}</td>
          <td>
            <div class="action-taken-cell">
              ${actionIconHtml}
              <span>${escapeHtml(actionText)}</span>
            </div>
          </td>
          <td>
            <div class="table-actions-cell">
              <button type="button" class="btn-table-inspect btn-inspect-row" data-device-id="${escapeHtml(ev.device_id)}" data-event-id="${escapeHtml(ev.id || '')}">Inspect</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    refreshIcons();

    tbody.onclick = (e) => {
      const inspectBtn = e.target.closest('.btn-inspect-row');
      if (inspectBtn) {
        const deviceId = inspectBtn.getAttribute('data-device-id');
        const eventId = inspectBtn.getAttribute('data-event-id');
        if (deviceId) openDeviceInspection(deviceId, eventId);
      }
    };
  }

  function getSeverityBadge(sev, eventType, verdict = '', actionTaken = '') {
    const category = getVerdictCategory(sev, eventType, verdict, actionTaken);
    if (category === 'danger') {
      return `
        <span class="badge-status badge-danger">
          <i data-lucide="shield-alert" style="width: 11px; height: 11px;"></i>
          <span>BLOCKED</span>
        </span>
      `;
    }
    if (category === 'warning') {
      return `
        <span class="badge-status badge-warning">
          <i data-lucide="alert-triangle" style="width: 11px; height: 11px;"></i>
          <span>CONTAINED</span>
        </span>
      `;
    }
    return `
      <span class="badge-status badge-safe">
        <i data-lucide="check" style="width: 11px; height: 11px;"></i>
        <span>SAFE</span>
      </span>
    `;
  }

  // --- Whitelist Table Render ---
  function renderWhitelistTable() {
    const tbody = document.getElementById('whitelist-table-body');
    if (!tbody) return;

    if (state.whitelist.length === 0) {
      tbody.innerHTML = `
        <tr class="table-empty-row">
          <td colspan="6" style="padding: 24px; text-align: center; color: var(--text-muted);">
            No whitelisted devices registered yet. Click "Add Device" to authorize one.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = state.whitelist.map(entry => `
      <tr>
        <td style="font-weight: 600; color: var(--text-main);">${escapeHtml(entry.name)}</td>
        <td class="mono-cell" style="font-size: 12px;">${escapeHtml(formatHex(entry.vendor_id))}</td>
        <td class="mono-cell" style="font-size: 12px;">${escapeHtml(formatHex(entry.product_id))}</td>
        <td class="mono-cell" style="font-size: 12px;">${escapeHtml(entry.serial_number || 'ANY')}</td>
        <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(entry.notes || 'Authorized device')}</td>
        <td style="text-align: right;">
          <button type="button" class="btn-secondary btn-danger-ghost btn-sm btn-delete-whitelist" data-entry-id="${escapeHtml(String(entry.id))}" data-entry-name="${escapeHtml(entry.name)}">Revoke</button>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.btn-delete-whitelist').forEach(btn => {
      btn.onclick = () => {
        const entryId = btn.getAttribute('data-entry-id');
        const entryName = btn.getAttribute('data-entry-name');
        deleteWhitelistEntry(entryId, entryName);
      };
    });
  }

  // --- Add Trusted Device Modal: Connected Device Picker + Manual Switch ---
  function isDeviceWhitelisted(vid, pid, serial, deviceId) {
    return state.whitelist.some(entry => {
      const serialMatch = entry.serial_number && serial && entry.serial_number.toLowerCase() === serial.toLowerCase();
      const vidMatch = entry.vendor_id && vid && entry.vendor_id.toUpperCase() === vid.toUpperCase();
      const pidMatch = entry.product_id && pid && entry.product_id.toUpperCase() === pid.toUpperCase();
      const idMatch = entry.device_id && deviceId && entry.device_id.toLowerCase() === deviceId.toLowerCase();
      return Boolean(idMatch || (serialMatch && (!entry.vendor_id || vidMatch) && (!entry.product_id || pidMatch)));
    });
  }

  function setWhitelistInputMode(mode) {
    state.whitelistInputMode = mode === 'manual' ? 'manual' : 'connected';
    const connectedBtn = document.getElementById('wl-mode-connected-btn');
    const manualBtn = document.getElementById('wl-mode-manual-btn');
    const connectedSection = document.getElementById('wl-connected-section');
    const refreshConnectedBtn = document.getElementById('wl-refresh-connected-btn');

    const vidEl = document.getElementById('wl-vid');
    const pidEl = document.getElementById('wl-pid');
    const serialEl = document.getElementById('wl-serial');

    const isConnected = state.whitelistInputMode === 'connected';
    if (connectedBtn) {
      connectedBtn.classList.toggle('active', isConnected);
      connectedBtn.setAttribute('aria-selected', String(isConnected));
    }
    if (manualBtn) {
      manualBtn.classList.toggle('active', !isConnected);
      manualBtn.setAttribute('aria-selected', String(!isConnected));
    }
    if (connectedSection) connectedSection.classList.toggle('hidden', !isConnected);
    if (refreshConnectedBtn) refreshConnectedBtn.classList.toggle('hidden', !isConnected);

    if (vidEl) vidEl.readOnly = isConnected;
    if (pidEl) pidEl.readOnly = isConnected;
    if (serialEl) serialEl.readOnly = isConnected;

    if (connectedBtn) {
      requestAnimationFrame(() => syncSegmentedGlider(connectedBtn.closest('.audit-tab-switcher')));
    }
    triggerFadeAnimation(document.getElementById('wl-fields-section'));
    if (isConnected) triggerFadeAnimation(connectedSection);
  }

  function applyDeviceToWhitelistForm(dev) {
    if (!dev) return;
    state.selectedPickerDeviceId = dev.device_id;

    const nameEl = document.getElementById('wl-name');
    const vidEl = document.getElementById('wl-vid');
    const pidEl = document.getElementById('wl-pid');
    const serialEl = document.getElementById('wl-serial');

    if (nameEl) nameEl.value = dev.name || dev.device_id;
    if (vidEl) vidEl.value = (dev.vendor_id || '').slice(0, 4);
    if (pidEl) pidEl.value = (dev.product_id || '').slice(0, 4);
    if (serialEl) serialEl.value = dev.serial_number || dev.device_id;

    renderConnectedDevicePicker();
  }

  function renderConnectedDevicePicker() {
    const picker = document.getElementById('wl-device-picker');
    if (!picker) return;

    const list = state.connectedDevicesCache;
    if (!list || list.length === 0) {
      picker.innerHTML = `
        <div class="wl-picker-empty">
          <span>No live USB devices returned by host scan.</span>
          <button type="button" class="btn-secondary btn-sm" id="wl-switch-manual-inline">Switch to Manual Entry</button>
        </div>
      `;
      const switchBtn = document.getElementById('wl-switch-manual-inline');
      if (switchBtn) {
        switchBtn.onclick = () => setWhitelistInputMode('manual');
      }
      return;
    }

    picker.innerHTML = list.map(dev => {
      const selected = state.selectedPickerDeviceId === dev.device_id;
      const alreadyTrusted = isDeviceWhitelisted(dev.vendor_id, dev.product_id, dev.serial_number, dev.device_id);
      const catInfo = resolveDeviceCategory(dev.name, dev.device_class, dev.device_type);
      const sub = `VID: ${formatHex(dev.vendor_id)} | PID: ${formatHex(dev.product_id)} | SN: ${dev.serial_number || 'N/A'}`;
      return `
        <button type="button" class="wl-device-option ${selected ? 'selected' : ''}" data-picker-id="${escapeHtml(dev.device_id)}" role="option" aria-selected="${selected}">
          <div class="wl-device-option-left">
            <div class="device-category-icon ${catInfo.colorClass}">
              <i data-lucide="${catInfo.icon}" style="width: 15px; height: 15px;"></i>
            </div>
            <div class="wl-device-option-meta">
              <span class="wl-device-option-name">${escapeHtml(dev.name)}</span>
              <span class="wl-device-option-ids">${escapeHtml(sub)}</span>
            </div>
          </div>
          <div class="wl-device-option-right">
            ${alreadyTrusted ? '<span class="badge-status badge-safe">Trusted</span>' : ''}
            ${selected ? '<span class="wl-device-check"><i data-lucide="check-circle-2" style="width: 16px; height: 16px;"></i></span>' : ''}
          </div>
        </button>
      `;
    }).join('');

    refreshIcons();

    picker.querySelectorAll('.wl-device-option').forEach(btn => {
      btn.onclick = () => {
        const id = btn.getAttribute('data-picker-id');
        const dev = state.connectedDevicesCache.find(d => d.device_id === id);
        if (dev) applyDeviceToWhitelistForm(dev);
      };
    });
  }

  async function loadConnectedDevicesForPicker(preferredDeviceId = null) {
    const picker = document.getElementById('wl-device-picker');
    if (picker) {
      picker.innerHTML = '<div class="wl-picker-empty">Scanning attached USB devices...</div>';
    }

    const normalized = [];
    const seen = new Set();

    try {
      const liveList = await apiGet('/devices/connected');
      if (Array.isArray(liveList)) {
        for (const item of liveList) {
          const det = item.details || {};
          const devId = item.device_id || det.pnp_device_id;
          if (!devId || seen.has(devId)) continue;
          seen.add(devId);
          normalized.push({
            device_id: devId,
            name: det.name || det.friendly_name || devId,
            vendor_id: det.vendor_id || extractParam(devId, 'VID_'),
            product_id: det.product_id || extractParam(devId, 'PID_'),
            serial_number: det.serial_number || extractSerial(devId) || devId,
            device_type: det.device_type || '',
            device_class: det.device_class || '',
          });
        }
      }
    } catch {
      // Fallback below
    }

    // Fallback: include active devices from recent telemetry if live endpoint returned none
    if (normalized.length === 0) {
      const deviceMap = new Map();
      for (const ev of state.events) {
        if (!deviceMap.has(ev.device_id)) deviceMap.set(ev.device_id, []);
        deviceMap.get(ev.device_id).push(ev);
      }
      for (const [devId, evList] of deviceMap.entries()) {
        const summary = summarizeDeviceStatus(evList);
        if (summary.isDisconnected || seen.has(devId)) continue;
        seen.add(devId);
        const det = summary.connectEv.details || {};
        normalized.push({
          device_id: devId,
          name: det.name || det.friendly_name || devId,
          vendor_id: det.vendor_id || extractParam(devId, 'VID_'),
          product_id: det.product_id || extractParam(devId, 'PID_'),
          serial_number: det.serial_number || extractSerial(devId) || devId,
          device_type: det.device_type || '',
          device_class: det.device_class || '',
        });
      }
    }

    state.connectedDevicesCache = normalized;

    if (preferredDeviceId) {
      const match = normalized.find(d => d.device_id.toLowerCase() === preferredDeviceId.toLowerCase());
      if (match) {
        applyDeviceToWhitelistForm(match);
        return;
      }
    }

    if (normalized.length > 0 && state.whitelistInputMode === 'connected') {
      const firstUntrusted = normalized.find(d => !isDeviceWhitelisted(d.vendor_id, d.product_id, d.serial_number, d.device_id));
      applyDeviceToWhitelistForm(firstUntrusted || normalized[0]);
    } else {
      renderConnectedDevicePicker();
    }
  }

  async function openWhitelistModal(prefill = null) {
    const wlModal = document.getElementById('whitelist-modal');
    const wlForm = document.getElementById('whitelist-form');
    if (!wlModal) return;

    if (wlForm) wlForm.reset();
    state.selectedPickerDeviceId = null;

    if (prefill && (prefill.serialNumber || prefill.vendorId || prefill.name)) {
      setWhitelistInputMode('manual');
      const nameEl = document.getElementById('wl-name');
      const vidEl = document.getElementById('wl-vid');
      const pidEl = document.getElementById('wl-pid');
      const serialEl = document.getElementById('wl-serial');
      if (nameEl) nameEl.value = prefill.name || '';
      if (vidEl) vidEl.value = (prefill.vendorId || '').slice(0, 4);
      if (pidEl) pidEl.value = (prefill.productId || '').slice(0, 4);
      if (serialEl) serialEl.value = prefill.serialNumber || '';
      wlModal.classList.remove('hidden');
      loadConnectedDevicesForPicker(prefill.deviceId || null);
      return;
    }

    setWhitelistInputMode('connected');
    wlModal.classList.remove('hidden');
    await loadConnectedDevicesForPicker();
  }

  // --- Device Forensic Inspection Modal ---
  function openDeviceInspection(deviceId, eventId = null) {
    const modal = document.getElementById('detail-modal');
    const content = document.getElementById('detail-modal-content');
    const actionsEl = document.getElementById('detail-dynamic-actions');
    if (!modal || !content) return;

    const deviceEvents = findDeviceEvents(deviceId);
    const status = deviceEvents.length > 0 ? summarizeDeviceStatus(deviceEvents) : null;
    const specificEv = (eventId && deviceEvents.find(e => String(e.id) === String(eventId))) || deviceEvents[0] || {};
    const connectEv = status ? status.connectEv : {};

    const resolvedId = connectEv.device_id || specificEv.device_id || deviceId;
    const name = connectEv.details?.name || specificEv.details?.name || resolvedId;
    const rawVid = connectEv.details?.vendor_id || specificEv.details?.vendor_id || extractParam(resolvedId, 'VID_');
    const rawPid = connectEv.details?.product_id || specificEv.details?.product_id || extractParam(resolvedId, 'PID_');
    const vidHex = formatHex(rawVid);
    const pidHex = formatHex(rawPid);
    const serial = connectEv.details?.serial_number || specificEv.details?.serial_number || extractSerial(resolvedId) || 'N/A';

    const effectiveSeverity = status ? status.severity : 'info';
    const effectiveEventType = status ? status.eventType : 'device.connected';
    const effectiveVerdict = status ? status.verdict : 'SAFE';
    const effectiveAction = status ? status.action : 'Connected';
    const reason = status ? status.reason : 'No recorded telemetry events found for this device yet.';

    const scanEv = deviceEvents.find(e => e.event_type === 'scan.completed' && e.details);
    const realFlagged = Array.isArray(scanEv?.details?.flagged) ? scanEv.details.flagged : [];
    const deletedThreats = Array.isArray(scanEv?.details?.deleted_threats) ? scanEv.details.deleted_threats : [];
    const scanErrors = Array.isArray(scanEv?.details?.errors) ? scanEv.details.errors : [];

    const hasFilenameIndicators = realFlagged.some(f =>
      Array.isArray(f.flags) && f.flags.some(fl => fl === 'autorun_inf' || fl === 'risky_extension')
    );

    const volumePaths = Array.isArray(connectEv.details?.volume_paths)
      ? connectEv.details.volume_paths
      : (scanEv?.details?.volume_path ? [scanEv.details.volume_path] : []);
    const primaryVolume = scanEv?.details?.volume_path || scanEv?.details?.root || volumePaths[0] || '';
    const analyzedList = Array.isArray(scanEv?.details?.file_analyses) && scanEv.details.file_analyses.length > 0
      ? scanEv.details.file_analyses
      : realFlagged;

    const storageSectionHtml = (scanEv || primaryVolume) ? `
      <div class="detail-section-block">
        <div class="detail-section-head">
          <div class="detail-label">STORAGE MALWARE TELEMETRY (${escapeHtml(primaryVolume || 'USB Volume')})</div>
          ${primaryVolume ? `
            <button type="button" class="btn-secondary btn-sm" id="detail-rescan-volume-btn">
              <i data-lucide="scan-search" style="width: 13px; height: 13px;"></i>
              <span>Rescan Volume</span>
            </button>
          ` : ''}
        </div>
        <div class="detail-section-body">
          ${scanEv ? `
            <div style="font-size: 12px; color: var(--text-body); margin-bottom: ${analyzedList.length || deletedThreats.length ? '10px' : '0'};">
              Files Scanned: <strong class="tabular-num">${Number(scanEv.details.files_scanned || 0)}</strong> &nbsp;|&nbsp;
              Max Risk Score: <strong class="tabular-num">${Number(scanEv.details.max_risk_score || 0)} / 100</strong> &nbsp;|&nbsp;
              Flagged: <strong class="tabular-num">${realFlagged.length}</strong> &nbsp;|&nbsp;
              New/Modified: <strong class="tabular-num">${Number(scanEv.details.new_files_count || 0) + Number(scanEv.details.modified_files_count || 0)}</strong>
            </div>
            ${hasFilenameIndicators ? `
              <div style="font-size: 11.5px; color: var(--warning-text); margin-bottom: 8px;">
                Note: Extension and autorun.inf findings are heuristic indicators combined with hash, magic-signature, entropy, and YARA checks.
              </div>
            ` : ''}
            ${deletedThreats.length > 0 ? `
              <div style="font-size: 12px; color: var(--danger-text); margin-bottom: 8px;">
                <strong>Quarantined &amp; Removed Payloads:</strong> ${deletedThreats.map(p => escapeHtml(p)).join(', ')}
              </div>
            ` : ''}
          ` : `
            <div style="font-size: 12px; color: var(--text-muted);">Storage volume ${escapeHtml(primaryVolume)} has not been scanned yet. Click Rescan Volume to inspect files.</div>
          `}
        </div>
        ${analyzedList.length > 0 ? `
          <table class="detail-factor-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Magic Type</th>
                <th>Entropy</th>
                <th>Risk Score</th>
                <th style="text-align: right;">Details</th>
              </tr>
            </thead>
            <tbody>
              ${analyzedList.slice(0, 12).map((f, idx) => `
                <tr>
                  <td><strong>${escapeHtml(f.path || '')}</strong> <span class="file-sub-meta">(${formatBytes(f.size)})</span></td>
                  <td>${escapeHtml(f.file_type || f.metadata?.magic_type || 'Unknown')}</td>
                  <td class="tabular-num">${Number(f.entropy || 0).toFixed(2)} b/B</td>
                  <td class="tabular-num"><strong>${Number(f.risk_score || 0)}/100</strong></td>
                  <td style="text-align: right;">
                    <button type="button" class="btn-table-inspect btn-inspect-device-file" data-dev-file-idx="${idx}">Inspect</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        ` : ''}
      </div>
    ` : '';

    content.innerHTML = `
      <div class="detail-meta-grid">
        <div class="detail-meta-cell">
          <div class="detail-label">DEVICE IDENTIFIER</div>
          <div class="detail-value detail-value-mono" style="word-break: break-all;">${escapeHtml(resolvedId)}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">SECURITY VERDICT</div>
          <div class="detail-value">${getSeverityBadge(effectiveSeverity, effectiveEventType, effectiveVerdict, effectiveAction)}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">HARDWARE IDENTITY</div>
          <div class="detail-value">${escapeHtml(name)}</div>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">BUS SIGNATURE</div>
          <div class="detail-value detail-value-mono">VID: ${escapeHtml(vidHex)} | PID: ${escapeHtml(pidHex)} | SN: ${escapeHtml(serial)}</div>
        </div>
      </div>

      <div>
        <div class="detail-label" style="margin-bottom: 6px;">FORENSIC RISK / POLICY DIAGNOSTIC</div>
        <p style="font-size: 12.5px; color: var(--text-body); background: var(--bg-surface-subtle); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-light);">
          ${escapeHtml(reason)}
        </p>
      </div>

      ${storageSectionHtml}

      <div>
        <div class="detail-label" style="margin-bottom: 6px;">RAW TELEMETRY RECORD (${deviceEvents.length} EVENT${deviceEvents.length === 1 ? '' : 'S'})</div>
        <pre class="detail-json-box">${escapeHtml(JSON.stringify(deviceEvents.length > 0 ? deviceEvents : [{ device_id: resolvedId, details: connectEv.details || {} }], null, 2))}</pre>
      </div>
    `;

    if (actionsEl) {
      const buttonsHtml = [];
      if (status && status.isBlocked) {
        buttonsHtml.push(`
          <button type="button" class="btn-secondary btn-safe-outline btn-sm btn-modal-allow-device">
            Let It Run
          </button>
        `);
      } else if (status && status.isWarning) {
        buttonsHtml.push(`
          <button type="button" class="btn-danger btn-sm btn-modal-block-device">
            Block Device
          </button>
          <button type="button" class="btn-secondary btn-safe-outline btn-sm btn-modal-allow-device">
            Let It Run
          </button>
        `);
      } else {
        buttonsHtml.push(`
          <button type="button" class="btn-danger btn-sm btn-modal-block-device">
            Block Device
          </button>
        `);
      }

      buttonsHtml.push(`
        <button type="button" class="btn-primary btn-sm btn-modal-whitelist-device">
          Authorize &amp; Whitelist
        </button>
      `);

      actionsEl.innerHTML = buttonsHtml.join('');

      const btnAllow = actionsEl.querySelector('.btn-modal-allow-device');
      const btnBlock = actionsEl.querySelector('.btn-modal-block-device');
      const btnWhitelist = actionsEl.querySelector('.btn-modal-whitelist-device');

      if (btnAllow) btnAllow.onclick = () => allowDevice(resolvedId);
      if (btnBlock) btnBlock.onclick = () => blockDevice(resolvedId);
      if (btnWhitelist) {
        btnWhitelist.onclick = () => {
          closeDetailModal();
          openWhitelistModal({
            deviceId: resolvedId,
            name,
            vendorId: rawVid,
            productId: rawPid,
            serialNumber: serial !== 'N/A' ? serial : resolvedId,
          });
        };
      }
    }

    modal.classList.remove('hidden');
    refreshIcons();

    const rescanBtn = document.getElementById('detail-rescan-volume-btn');
    if (rescanBtn && primaryVolume) {
      rescanBtn.onclick = async () => {
        rescanBtn.disabled = true;
        await scanUsbStorage({ volumePath: primaryVolume, deviceId: resolvedId });
        openDeviceInspection(resolvedId);
      };
    }

    content.querySelectorAll('.btn-inspect-device-file').forEach(btn => {
      btn.onclick = () => {
        const idx = Number(btn.getAttribute('data-dev-file-idx'));
        if (!Number.isNaN(idx) && analyzedList[idx]) {
          openFileInspection({
            ...analyzedList[idx],
            volume_path: primaryVolume,
            device_id: resolvedId,
          });
        }
      };
    });
  }

  function openFileInspection(fileItem) {
    const modal = document.getElementById('detail-modal');
    const content = document.getElementById('detail-modal-content');
    const actionsEl = document.getElementById('detail-dynamic-actions');
    if (!modal || !content || !fileItem) return;

    const score = Number(fileItem.risk_score || 0);
    const entropy = Number(fileItem.entropy || 0);
    const meta = fileItem.metadata || {};
    const factors = Array.isArray(fileItem.risk_factors) ? fileItem.risk_factors : [];
    const pe = meta.pe_info || null;

    const verdictBadge = score >= 50
      ? '<span class="badge-status badge-danger">CRITICAL / HIGH RISK</span>'
      : (score >= 20
        ? '<span class="badge-status badge-warning">SUSPICIOUS</span>'
        : '<span class="badge-status badge-safe">CLEAN</span>');

    content.innerHTML = `
      <div class="detail-meta-grid">
        <div class="detail-meta-cell">
          <div class="detail-label">FILE PATH &amp; ORIGIN</div>
          <div class="detail-value" style="word-break: break-all;">${escapeHtml(fileItem.path || 'Unknown')}</div>
          <span class="file-sub-meta">Volume: ${escapeHtml(fileItem.volume_path || 'USB Storage')} &middot; Status: ${escapeHtml(String(fileItem.change_status || 'initial').toUpperCase())}</span>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">RISK ASSESSMENT (${score} / 100)</div>
          <div class="detail-value">${verdictBadge}</div>
          <span class="file-sub-meta">Shannon Entropy: ${entropy.toFixed(2)} / 8.00 bits/byte</span>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">FILE TYPE SIGNATURE (MAGIC VS EXT)</div>
          <div class="detail-value">${escapeHtml(fileItem.file_type || meta.magic_type || 'Unknown')}</div>
          <span class="file-sub-meta">Extension: ${escapeHtml(meta.extension || '(none)')}${meta.extension_mismatch ? ' — MISMATCH DETECTED' : ''}</span>
        </div>
        <div class="detail-meta-cell">
          <div class="detail-label">METADATA &amp; ATTRIBUTES</div>
          <div class="detail-value">${formatBytes(fileItem.size)}</div>
          <span class="file-sub-meta">Hidden: ${meta.hidden ? 'Yes' : 'No'} | System: ${meta.system ? 'Yes' : 'No'} | ReadOnly: ${meta.readonly ? 'Yes' : 'No'}</span>
        </div>
      </div>

      <div class="detail-section-block">
        <div class="detail-section-head">
          <span class="detail-label">CRYPTOGRAPHIC DIGESTS &amp; TIMESTAMPS</span>
        </div>
        <div class="detail-section-body" style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
          <div class="tabular-num" style="word-break: break-all;"><strong>SHA-256:</strong> ${escapeHtml(fileItem.sha256 || 'N/A')}</div>
          <div class="tabular-num" style="word-break: break-all;"><strong>MD5:</strong> ${escapeHtml(fileItem.md5 || 'N/A')}</div>
          <div class="tabular-num"><strong>Created (UTC):</strong> ${escapeHtml(meta.created_at || 'N/A')} &nbsp;|&nbsp; <strong>Modified (UTC):</strong> ${escapeHtml(meta.modified_at || 'N/A')}</div>
          ${pe ? `<div class="tabular-num"><strong>PE Header Metadata:</strong> ${escapeHtml(pe.architecture)} | Sections: ${pe.sections} | Compiled: ${escapeHtml(pe.compiled_at || 'N/A')}</div>` : ''}
        </div>
      </div>

      <div class="detail-section-block">
        <div class="detail-section-head">
          <span class="detail-label">WEIGHTED RISK SCORE BREAKDOWN (${score} / 100)</span>
        </div>
        ${factors.length > 0 ? `
          <table class="detail-factor-table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Category</th>
                <th>Forensic Explanation</th>
                <th style="text-align: right;">Weight</th>
              </tr>
            </thead>
            <tbody>
              ${factors.map(fac => `
                <tr>
                  <td><strong>${escapeHtml(fac.indicator || '')}</strong></td>
                  <td style="text-transform: uppercase; font-size: 11px;">${escapeHtml(fac.category || '')}</td>
                  <td>${escapeHtml(fac.detail || '')}</td>
                  <td style="text-align: right; font-weight: 700;" class="tabular-num">+${Number(fac.points || 0)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        ` : `
          <div class="detail-section-body" style="font-size: 12px; color: var(--text-muted);">
            No malicious YARA rules, malware hashes, extension mismatches, or anomalous behavioral indicators were triggered.
          </div>
        `}
      </div>
    `;

    if (actionsEl) {
      actionsEl.innerHTML = fileItem.device_id
        ? `<button type="button" class="btn-secondary btn-sm" id="file-inspect-parent-btn">View Host USB Device</button>`
        : '';
      const parentBtn = document.getElementById('file-inspect-parent-btn');
      if (parentBtn) {
        parentBtn.onclick = () => openDeviceInspection(fileItem.device_id);
      }
    }

    modal.classList.remove('hidden');
    refreshIcons();
  }

  function closeDetailModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.add('hidden');
  }

  // --- Device Containment & Whitelisting Handlers ---
  async function blockDevice(deviceId) {
    try {
      const res = await apiPost('/devices/block', {
        device_id: deviceId,
        reason: 'Manual containment by security officer',
      });
      soundEngine.playThreatAlert();
      showToast(res.summary || `Device ${deviceId} blocked.`, res.blocked ? 'danger' : 'warning');
      closeDetailModal();
      await fetchTelemetry();
    } catch (e) {
      showToast(`Failed to block device: ${e.message}`, 'danger');
    }
  }

  async function allowDevice(deviceId) {
    try {
      const res = await apiPost('/devices/allow', {
        device_id: deviceId,
        reason: 'Approved by security officer',
      });
      soundEngine.playSuccessChime();
      const msg = res.port_enabled === false
        ? 'Device marked SAFE in dashboard (run monitor as Admin to re-enable hardware port).'
        : 'Device permitted to run and marked SAFE.';
      showToast(msg, 'safe');
      closeDetailModal();
      await fetchTelemetry();
      await fetchWhitelist();
    } catch (e) {
      showToast(`Failed to allow device: ${e.message}`, 'danger');
    }
  }

  async function deleteWhitelistEntry(entryId, entryName = '') {
    if (!entryId) return;
    try {
      await apiDelete(`/policy/whitelist/${encodeURIComponent(entryId)}`);
      showToast(`Revoked whitelist rule${entryName ? ` for '${entryName}'` : ''}.`, 'warning');
      await fetchWhitelist();
    } catch (e) {
      showToast(`Revocation failed: ${e.message}`, 'danger');
    }
  }

  async function updatePolicyMode(mode) {
    try {
      const res = await apiPost('/policy/mode', { mode });
      applyPolicyModeUI(res.mode || mode);
      soundEngine.playSuccessChime();
      showToast(`Security policy updated to '${(res.mode || mode).toUpperCase()}'.`, 'safe');
    } catch (err) {
      showToast(`Failed to update policy: ${err.message}`, 'danger');
    }
  }

  // --- Utility Formatting ---
  function formatTimestamp(isoStr) {
    if (!isoStr) return '--:--:--';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      const hh = String(d.getHours()).padStart(2, '0');
      const mm = String(d.getMinutes()).padStart(2, '0');
      const ss = String(d.getSeconds()).padStart(2, '0');
      return `${hh}:${mm}:${ss}`;
    } catch {
      return isoStr;
    }
  }

  // --- Real-Time WebSocket Telemetry Stream ---
  function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}${API_BASE}/ws/telemetry`;

    let ws = null;
    let reconnectDelay = 2000;

    function connect() {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          state.wsConnected = true;
          reconnectDelay = 2000;
          updateMonitorStatus(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'threat_alert' || data.type === 'device_blocked') {
              soundEngine.playThreatAlert();
            } else if (data.type === 'device_allowed') {
              soundEngine.playSuccessChime();
            } else if (data.type === 'policy_updated' && data.payload?.mode) {
              applyPolicyModeUI(data.payload.mode);
            }
            fetchTelemetry();
          } catch {
            fetchTelemetry();
          }
        };

        ws.onclose = () => {
          state.wsConnected = false;
          updateMonitorStatus(true);
          setTimeout(connect, reconnectDelay);
          reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
        };

        ws.onerror = () => {
          if (ws) ws.close();
        };
      } catch {
        setTimeout(connect, reconnectDelay);
      }
    }

    connect();
  }

  // --- Event Listeners ---
  function setupEventListeners() {
    // 1. Custom popover menus everywhere
    setupCustomMenu('export-menu-wrap', 'export-menu-btn', 'export-menu-panel');
    setupCustomMenu('audit-filter-menu-wrap', 'audit-filter-menu-btn', 'audit-filter-menu-panel');
    setupCustomMenu('policy-menu-wrap', 'policy-menu-btn', 'policy-menu-panel');
    setupCustomMenu('settings-policy-menu-wrap', 'settings-policy-menu-btn', 'settings-policy-menu-panel');

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.custom-menu-wrap')) {
        closeAllCustomMenus();
      }
    });

    const auditFilterPanel = document.getElementById('audit-filter-menu-panel');
    if (auditFilterPanel) {
      auditFilterPanel.querySelectorAll('[data-filter-value]').forEach(item => {
        item.addEventListener('click', () => {
          const val = item.getAttribute('data-filter-value') || 'all';
          applyAuditFilterUI(val);
          closeAllCustomMenus();
          renderEventsTable();
          renderFileAnalysisTable();
          triggerFadeAnimation(document.getElementById(state.viewMode === 'files' ? 'file-analysis-table-body' : 'events-table-body'));
        });
      });
    }

    const policyMenuPanel = document.getElementById('policy-menu-panel');
    if (policyMenuPanel) {
      policyMenuPanel.querySelectorAll('[data-policy-value]').forEach(item => {
        item.addEventListener('click', () => {
          const val = item.getAttribute('data-policy-value');
          closeAllCustomMenus();
          if (val) updatePolicyMode(val);
        });
      });
    }

    const settingsPolicyMenuPanel = document.getElementById('settings-policy-menu-panel');
    if (settingsPolicyMenuPanel) {
      settingsPolicyMenuPanel.querySelectorAll('[data-settings-policy-value]').forEach(item => {
        item.addEventListener('click', () => {
          const val = item.getAttribute('data-settings-policy-value') || 'enforce';
          syncSettingsPolicyMenu(val);
          closeAllCustomMenus();
        });
      });
    }

    // 2. View mode tabs
    const viewConnectedBtn = document.getElementById('view-connected-btn');
    const viewAllEventsBtn = document.getElementById('view-all-events-btn');
    const viewFileAnalysisBtn = document.getElementById('view-file-analysis-btn');
    const eventsTableWrap = document.getElementById('events-table-wrap');
    const fileAnalysisWrap = document.getElementById('file-analysis-wrap');

    function setAuditViewMode(nextMode) {
      if (state.viewMode === nextMode) return;
      state.viewMode = nextMode;
      const tabButtons = [
        { btn: viewConnectedBtn, mode: 'connected' },
        { btn: viewAllEventsBtn, mode: 'all' },
        { btn: viewFileAnalysisBtn, mode: 'files' },
      ];
      for (const item of tabButtons) {
        if (!item.btn) continue;
        const active = item.mode === nextMode;
        item.btn.classList.toggle('active', active);
        item.btn.setAttribute('aria-selected', String(active));
      }
      const switcher = viewConnectedBtn?.closest('.audit-tab-switcher');
      syncSegmentedGlider(switcher);

      if (nextMode === 'files') {
        eventsTableWrap?.classList.add('hidden');
        fileAnalysisWrap?.classList.remove('hidden');
        renderFileAnalysisTable();
        triggerFadeAnimation(document.getElementById('file-analysis-table-body'));
      } else {
        fileAnalysisWrap?.classList.add('hidden');
        eventsTableWrap?.classList.remove('hidden');
        renderEventsTable();
        triggerFadeAnimation(document.getElementById('events-table-body'));
      }
    }

    if (viewConnectedBtn) viewConnectedBtn.addEventListener('click', () => setAuditViewMode('connected'));
    if (viewAllEventsBtn) viewAllEventsBtn.addEventListener('click', () => setAuditViewMode('all'));
    if (viewFileAnalysisBtn) viewFileAnalysisBtn.addEventListener('click', () => setAuditViewMode('files'));

    // 3. Global search & shortcut
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        state.searchTerm = e.target.value.trim();
        renderEventsTable();
        renderFileAnalysisTable();
      });

      window.addEventListener('keydown', (e) => {
        if ((e.key === 'k' && (e.ctrlKey || e.metaKey)) || (e.key === '/' && document.activeElement !== searchInput && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName))) {
          e.preventDefault();
          searchInput.focus();
        }
      });
    }

    // 4. Topbar & header actions
    const clearLogBtn = document.getElementById('clear-log-btn');
    const scanStorageBtn = document.getElementById('scan-storage-btn');
    const refreshBtn = document.getElementById('refresh-btn');
    const exportCsvBtn = document.getElementById('export-csv-btn');
    const exportPdfBtn = document.getElementById('export-pdf-btn');

    if (scanStorageBtn) {
      scanStorageBtn.addEventListener('click', async () => {
        scanStorageBtn.disabled = true;
        scanStorageBtn.classList.add('is-spinning');
        try {
          await syncConnectedDevices();
          await scanUsbStorage({ silent: false });
          setAuditViewMode('files');
        } finally {
          scanStorageBtn.disabled = false;
          scanStorageBtn.classList.remove('is-spinning');
        }
      });
    }

    if (clearLogBtn) {
      clearLogBtn.addEventListener('click', async () => {
        try {
          await apiDelete('/events');
          state.events = [];
          state.analyzedFiles = [];
          state.dismissedAlertEventId = null;
          renderMetrics();
          renderEventsTable();
          renderFileAnalysisTable();
          checkSecurityAlertBanner();
          await loadTimeRangeAnalytics(state.activeTimeRange);
          showToast('Hardware bus audit log cleared.', 'safe');
        } catch (e) {
          showToast(`Clear log failed: ${e.message}`, 'danger');
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        refreshBtn.classList.add('is-spinning');
        refreshBtn.disabled = true;
        try {
          await syncConnectedDevices();
          await scanUsbStorage({ silent: true });
          await fetchTelemetry();
          await fetchWhitelist();
          await fetchPolicyStatus();
          showToast('Hardware inventory and USB storage telemetry synchronized.', 'info');
        } finally {
          refreshBtn.classList.remove('is-spinning');
          refreshBtn.disabled = false;
        }
      });
    }

    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', () => {
        closeAllCustomMenus();
        window.open(`${API_BASE}/reports/events.csv`, '_blank');
      });
    }

    const downloadPdf = () => {
      closeAllCustomMenus();
      window.open(`${API_BASE}/reports/incident/pdf`, '_blank');
      showToast('Generating forensic incident PDF report...', 'info');
    };
    if (exportPdfBtn) exportPdfBtn.addEventListener('click', downloadPdf);

    // 5. Alert banner dismiss
    const dismissBannerBtn = document.getElementById('alert-banner-dismiss-btn');
    if (dismissBannerBtn) {
      dismissBannerBtn.addEventListener('click', () => {
        const criticalEvent = state.events.find(e => e.severity === 'critical');
        if (criticalEvent) state.dismissedAlertEventId = criticalEvent.id;
        const banner = document.getElementById('security-alert-banner');
        if (banner) banner.classList.add('hidden');
      });
    }

    // 6. Analytics time range buttons
    document.querySelectorAll('.btn-time-range').forEach(btn => {
      btn.addEventListener('click', async () => {
        document.querySelectorAll('.btn-time-range').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        syncSegmentedGlider(btn.closest('.time-range-switcher'));
        state.activeTimeRange = btn.getAttribute('data-range') || '1h';
        await loadTimeRangeAnalytics(state.activeTimeRange, true);
      });
    });

    // 7. Detail modal close
    const closeDetailBtn = document.getElementById('close-detail-modal-btn');
    const detailCloseBtn = document.getElementById('detail-close-btn');
    if (closeDetailBtn) closeDetailBtn.addEventListener('click', closeDetailModal);
    if (detailCloseBtn) detailCloseBtn.addEventListener('click', closeDetailModal);

    // 8. Whitelist modal, connected device picker & mode toggle
    const openWlBtn = document.getElementById('open-whitelist-modal-btn');
    const wlModal = document.getElementById('whitelist-modal');
    const closeWlBtn = document.getElementById('close-whitelist-modal-btn');
    const cancelWlBtn = document.getElementById('cancel-whitelist-btn');
    const wlForm = document.getElementById('whitelist-form');
    const wlModeConnectedBtn = document.getElementById('wl-mode-connected-btn');
    const wlModeManualBtn = document.getElementById('wl-mode-manual-btn');
    const wlRefreshBtn = document.getElementById('wl-refresh-connected-btn');

    if (openWlBtn) openWlBtn.addEventListener('click', () => openWhitelistModal());
    if (closeWlBtn && wlModal) closeWlBtn.addEventListener('click', () => wlModal.classList.add('hidden'));
    if (cancelWlBtn && wlModal) cancelWlBtn.addEventListener('click', () => wlModal.classList.add('hidden'));

    if (wlModeConnectedBtn) {
      wlModeConnectedBtn.addEventListener('click', () => {
        setWhitelistInputMode('connected');
        if (state.connectedDevicesCache.length === 0) {
          loadConnectedDevicesForPicker();
        } else if (state.selectedPickerDeviceId) {
          const selected = state.connectedDevicesCache.find(d => d.device_id === state.selectedPickerDeviceId);
          if (selected) applyDeviceToWhitelistForm(selected);
        } else {
          applyDeviceToWhitelistForm(state.connectedDevicesCache[0]);
        }
      });
    }

    if (wlModeManualBtn) {
      wlModeManualBtn.addEventListener('click', () => {
        setWhitelistInputMode('manual');
      });
    }

    if (wlRefreshBtn) {
      wlRefreshBtn.addEventListener('click', () => loadConnectedDevicesForPicker(state.selectedPickerDeviceId));
    }

    if (wlForm) {
      wlForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('wl-name')?.value.trim();
        const vid = document.getElementById('wl-vid')?.value.trim();
        const pid = document.getElementById('wl-pid')?.value.trim();
        const serial = document.getElementById('wl-serial')?.value.trim();
        const notes = document.getElementById('wl-notes')?.value.trim();

        if (!name || !serial) {
          showToast(
            state.whitelistInputMode === 'connected'
              ? 'Select a connected device first or switch to Enter Manually.'
              : 'Device Name and Serial Number are required.',
            'warning'
          );
          return;
        }

        try {
          await apiPost('/policy/whitelist', {
            name,
            vendor_id: vid || null,
            product_id: pid || null,
            serial_number: serial,
            notes: notes || ''
          });
          soundEngine.playSuccessChime();
          showToast(`Whitelisted device '${name}'.`, 'safe');
          if (wlModal) wlModal.classList.add('hidden');
          wlForm.reset();
          await fetchWhitelist();
        } catch (err) {
          showToast(`Authorization failed: ${err.message}`, 'danger');
        }
      });
    }

    // 9. Security Settings modal
    const navSecuritySettings = document.getElementById('nav-security-settings');
    const settingsModal = document.getElementById('settings-modal');
    const closeSettingsBtn = document.getElementById('close-settings-modal-btn');
    const cancelSettingsBtn = document.getElementById('cancel-settings-btn');
    const saveSettingsBtn = document.getElementById('save-settings-btn');
    const policyModeSelect = document.getElementById('settings-policy-mode');
    const soundAlertsCheckbox = document.getElementById('setting-sound-alerts');
    const exportPdfReportBtn = document.getElementById('btn-export-pdf-report');

    async function openSettingsModal() {
      if (!settingsModal) return;
      closeAllCustomMenus();
      await fetchPolicyStatus();
      syncSettingsPolicyMenu(state.policyMode);
      if (soundAlertsCheckbox) soundAlertsCheckbox.checked = state.soundEnabled;
      settingsModal.classList.remove('hidden');
      if (isMobileViewport()) setSidebarCollapsed(true, false);
    }

    function closeSettingsModal() {
      closeAllCustomMenus();
      if (settingsModal) settingsModal.classList.add('hidden');
    }

    if (navSecuritySettings) navSecuritySettings.addEventListener('click', openSettingsModal);
    if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', closeSettingsModal);
    if (cancelSettingsBtn) cancelSettingsBtn.addEventListener('click', closeSettingsModal);

    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener('click', async () => {
        const mode = policyModeSelect ? policyModeSelect.value : 'enforce';
        if (soundAlertsCheckbox) {
          state.soundEnabled = soundAlertsCheckbox.checked;
          const soundIcon = document.getElementById('sound-toggle-icon');
          if (soundIcon) {
            soundIcon.setAttribute('data-lucide', state.soundEnabled ? 'volume-2' : 'volume-x');
            refreshIcons();
          }
        }
        await updatePolicyMode(mode);
        closeSettingsModal();
      });
    }

    if (exportPdfReportBtn) exportPdfReportBtn.addEventListener('click', downloadPdf);

    // 10. MITRE ATT&CK Modal & Sidebar Navigation
    const mitreModal = document.getElementById('mitre-modal');
    const closeMitreBtn = document.getElementById('close-mitre-modal-btn');
    const closeMitreFooterBtn = document.getElementById('close-mitre-footer-btn');
    const navMitre = document.getElementById('nav-mitre');

    const openMitre = () => {
      if (mitreModal) mitreModal.classList.remove('hidden');
      if (isMobileViewport()) setSidebarCollapsed(true, false);
    };
    if (navMitre) navMitre.addEventListener('click', openMitre);
    if (closeMitreBtn && mitreModal) closeMitreBtn.addEventListener('click', () => mitreModal.classList.add('hidden'));
    if (closeMitreFooterBtn && mitreModal) closeMitreFooterBtn.addEventListener('click', () => mitreModal.classList.add('hidden'));

    const navLinks = [
      { id: 'nav-dashboard', target: '#section-overview' },
      { id: 'nav-telemetry', target: '#section-monitor' },
      { id: 'nav-analytics', target: '#section-analytics' },
      { id: 'nav-whitelist', target: '#section-whitelist' },
    ];
    for (const item of navLinks) {
      const el = document.getElementById(item.id);
      if (!el) continue;
      el.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.sidebar-nav .nav-item').forEach(n => n.classList.remove('active'));
        el.classList.add('active');
        document.querySelector(item.target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        if (isMobileViewport()) setSidebarCollapsed(true, false);
      });
    }

    // 11. Theme & Sound Toggles
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener('click', () => {
        const nextTheme = state.theme === 'light' ? 'dark' : 'light';
        applyTheme(nextTheme);
        showToast(`Switched to ${nextTheme} theme.`, 'info');
      });
    }

    const soundToggleBtn = document.getElementById('sound-toggle');
    if (soundToggleBtn) {
      soundToggleBtn.addEventListener('click', () => {
        state.soundEnabled = !state.soundEnabled;
        const soundAlertsCheckbox = document.getElementById('setting-sound-alerts');
        if (soundAlertsCheckbox) soundAlertsCheckbox.checked = state.soundEnabled;
        const soundIcon = document.getElementById('sound-toggle-icon');
        if (soundIcon) {
          soundIcon.setAttribute('data-lucide', state.soundEnabled ? 'volume-2' : 'volume-x');
          refreshIcons();
        }
        showToast(`Audio alerts ${state.soundEnabled ? 'enabled' : 'muted'}.`, 'info');
      });
    }

    // Close modals when clicking on the backdrop overlay
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) {
          backdrop.classList.add('hidden');
        }
      });
    });

    // Close modals, menus & mobile drawer on Escape
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeAllCustomMenus();
        closeDetailModal();
        if (wlModal) wlModal.classList.add('hidden');
        if (mitreModal) mitreModal.classList.add('hidden');
        if (settingsModal) settingsModal.classList.add('hidden');
        if (isMobileViewport()) setSidebarCollapsed(true, false);
      }
    });

    window.addEventListener('resize', () => {
      syncAllSegmentedGliders();
    });
  }

  // Handle Windows toast redirect parameters ONLY AFTER initial telemetry is loaded
  async function handleInitialUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const toastAction = urlParams.get('toast_action');
    const inspectDev = urlParams.get('inspect_device') || urlParams.get('device_id');

    if (!toastAction && !inspectDev) return;

    try {
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch {
      // Ignore history restriction
    }

    if (toastAction === 'allow' && inspectDev) {
      await allowDevice(inspectDev);
    } else if (toastAction === 'block' && inspectDev) {
      await blockDevice(inspectDev);
    } else if (inspectDev) {
      openDeviceInspection(inspectDev);
    }
  }

  // --- Initialize Application ---
  async function init() {
    let savedTheme = 'light';
    try {
      savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || 'light';
    } catch {
      savedTheme = 'light';
    }
    applyTheme(savedTheme);
    initSidebarDrawer();
    initCharts();
    setupEventListeners();
    refreshIcons();
    requestAnimationFrame(syncAllSegmentedGliders);
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(syncAllSegmentedGliders);
    }

    const syncRes = await syncConnectedDevices();
    await Promise.all([
      fetchTelemetry(),
      fetchWhitelist(),
      fetchPolicyStatus(),
    ]);

    const hasMountedVolume = Boolean(
      syncRes && Array.isArray(syncRes.devices) &&
      syncRes.devices.some(d => Array.isArray(d.volume_paths) && d.volume_paths.length > 0)
    );
    const hasCompletedScan = state.events.some(e => e.event_type === 'scan.completed');
    if (hasMountedVolume && !hasCompletedScan) {
      await scanUsbStorage({ silent: true });
    }

    await handleInitialUrlParams();
    initWebSocket();

    setInterval(sendHeartbeat, 5000);
    setInterval(fetchTelemetry, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
