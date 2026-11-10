const eventsBody = document.querySelector("#events-body");
const eventsTableHead = document.querySelector("#events-table-head");
const viewModeConsolidated = document.querySelector("#view-mode-consolidated");
const viewModeRaw = document.querySelector("#view-mode-raw");
const whitelistBody = document.querySelector("#whitelist-body");
const message = document.querySelector("#message");
const apiStatus = document.querySelector("#api-status");
const connection = document.querySelector(".connection");
const themeToggle = document.querySelector("#theme-toggle");
const alertBanner = document.querySelector("#security-alert-banner");
const alertSummary = document.querySelector("#alert-summary");
const alertDetail = document.querySelector("#alert-detail");
const dismissAlertBtn = document.querySelector("#dismiss-alert-btn");
const showAddWlBtn = document.querySelector("#show-add-whitelist-btn");
const addWlForm = document.querySelector("#add-whitelist-form");
const cancelWlBtn = document.querySelector("#cancel-whitelist-btn");
const simulateDropdownBtn = document.querySelector("#simulate-dropdown-btn");
const simulationMenu = document.querySelector("#simulation-menu");
const simulateBadusbBtn = document.querySelector("#simulate-badusb-btn");
const eventSearchInput = document.querySelector("#event-search");
const soundToggleBtn = document.querySelector("#sound-toggle-btn");
const soundIcon = document.querySelector("#sound-icon");
const soundLabel = document.querySelector("#sound-label");
const threatMatrixBtn = document.querySelector("#threat-matrix-btn");
const threatMatrixModal = document.querySelector("#threat-matrix-modal");
const closeMatrixModalBtn = document.querySelector("#close-matrix-modal-btn");

let soundAlertsEnabled = localStorage.getItem("usb-sound-alerts") !== "false";

function updateSoundUI() {
  if (soundLabel) {
    soundLabel.textContent = soundAlertsEnabled ? "Alerts On" : "Muted";
  }
  const soundSvg = document.querySelector("#sound-icon-svg");
  if (soundSvg) {
    soundSvg.style.opacity = soundAlertsEnabled ? "1" : "0.35";
  }
}

if (soundToggleBtn) {
  updateSoundUI();
  soundToggleBtn.addEventListener("click", () => {
    soundAlertsEnabled = !soundAlertsEnabled;
    localStorage.setItem("usb-sound-alerts", String(soundAlertsEnabled));
    updateSoundUI();
    showMessage(soundAlertsEnabled ? "Audio threat alerts enabled" : "Audio threat alerts muted");
  });
}

function playCyberThreatAlert() {
  if (!soundAlertsEnabled) return;
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    const now = audioCtx.currentTime;
    osc.frequency.setValueAtTime(587.33, now); // D5
    osc.frequency.exponentialRampToValueAtTime(880.0, now + 0.12); // A5
    osc.frequency.exponentialRampToValueAtTime(440.0, now + 0.28); // A4
    gain.gain.setValueAtTime(0.18, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(now);
    osc.stop(now + 0.36);
  } catch (e) {}
}

if (threatMatrixBtn && threatMatrixModal) {
  threatMatrixBtn.addEventListener("click", () => {
    threatMatrixModal.hidden = false;
  });
  closeMatrixModalBtn?.addEventListener("click", () => {
    threatMatrixModal.hidden = true;
  });
  threatMatrixModal.addEventListener("click", (e) => {
    if (e.target === threatMatrixModal) {
      threatMatrixModal.hidden = true;
    }
  });
}

// Suspicious Hardware Triage Prompt (Windows Defender Style)
const suspiciousTriageModal = document.querySelector("#suspicious-triage-modal");
const closeTriageModalBtn = document.querySelector("#close-triage-modal-btn");
const triageDeviceName = document.querySelector("#triage-device-name");
const triageDeviceId = document.querySelector("#triage-device-id");
const triageReasonText = document.querySelector("#triage-reason-text");
const triageBlockBtn = document.querySelector("#triage-block-btn");
const triageTrustBtn = document.querySelector("#triage-trust-btn");
const triageLeaveBtn = document.querySelector("#triage-leave-btn");

let currentTriageDevice = null;
let notifiedEventIds = new Set();

// Request Web Notification permission
if ("Notification" in window && Notification.permission === "default") {
  Notification.requestPermission().catch(() => {});
}

function sendWindowsWebNotification(title, body, onClick = null) {
  if ("Notification" in window && Notification.permission === "granted") {
    try {
      const notif = new Notification(title, {
        body: body,
        requireInteraction: true,
      });
      if (onClick) {
        notif.onclick = () => {
          window.focus();
          onClick();
        };
      }
    } catch (e) {}
  }
}

function openSuspiciousTriageModal(deviceData) {
  currentTriageDevice = deviceData;
  if (!suspiciousTriageModal) return;
  const details = deviceData.details || {};
  triageDeviceName.textContent = deviceData.name || details.name || "Unregistered USB Peripheral";
  triageDeviceId.textContent = deviceData.device_id || deviceData.id || "USB\\UNREGISTERED";
  triageReasonText.textContent = details.reason || details.summary || "This device is not on your authorized whitelist. Unverified USB hardware can introduce firmware risks or unauthorized data access.";
  suspiciousTriageModal.hidden = false;
}

if (closeTriageModalBtn && suspiciousTriageModal) {
  closeTriageModalBtn.addEventListener("click", () => {
    suspiciousTriageModal.hidden = true;
  });
  triageLeaveBtn?.addEventListener("click", () => {
    suspiciousTriageModal.hidden = true;
    showMessage("Device left active under audit warning.", "warning");
  });
  triageBlockBtn?.addEventListener("click", async () => {
    if (!currentTriageDevice) return;
    triageBlockBtn.disabled = true;
    try {
      const devId = currentTriageDevice.device_id || currentTriageDevice.id;
      const res = await fetch("/api/v1/devices/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: devId,
          reason: "Blocked by user following suspicious device notification prompt",
        }),
      });
      if (!res.ok) throw new Error("Block command failed");
      suspiciousTriageModal.hidden = true;
      playCyberThreatAlert();
      showMessage(`Device ${devId} disabled and blocked at OS port!`, "error");
      await loadEvents(false);
    } catch (err) {
      showMessage(`Failed to block device: ${err.message}`, true);
    } finally {
      triageBlockBtn.disabled = false;
    }
  });

  triageTrustBtn?.addEventListener("click", async () => {
    if (!currentTriageDevice) return;
    triageTrustBtn.disabled = true;
    try {
      const details = currentTriageDevice.details || {};
      const devId = currentTriageDevice.device_id || currentTriageDevice.id;
      const name = currentTriageDevice.name || details.name || "Approved Corporate Peripheral";
      const res = await fetch("/api/v1/policy/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name,
          device_id: devId,
          vendor_id: currentTriageDevice.vendorId || details.vendor_id || null,
          product_id: currentTriageDevice.productId || details.product_id || null,
          serial_number: currentTriageDevice.serialNumber || details.serial_number || null,
          notes: "Approved via Defender-style user triage dialog",
        }),
      });
      if (!res.ok) throw new Error("Whitelist command failed");
      suspiciousTriageModal.hidden = true;
      showMessage(`Device '${name}' added to Whitelist and marked SAFE!`, false);
      await loadWhitelist();
      await loadEvents(false);
    } catch (err) {
      showMessage(`Failed to trust device: ${err.message}`, true);
    } finally {
      triageTrustBtn.disabled = false;
    }
  });

  suspiciousTriageModal.addEventListener("click", (e) => {
    if (e.target === suspiciousTriageModal) {
      suspiciousTriageModal.hidden = true;
    }
  });
}

const themeStorageKey = "usb-analyzer-theme";
let allEventsCache = [];
let eventsLoadInProgress = false;
let currentPolicyMode = "enforce";
let currentViewMode = "consolidated"; // "consolidated" (recommended) or "raw"
let severityChart = null;
let activityChart = null;
let dismissedAlertIds = new Set();
let searchQuery = "";

// Permanent Vision UI Light Theme
document.documentElement.dataset.theme = "light";
document.documentElement.setAttribute("data-theme", "light");
try {
  localStorage.setItem(themeStorageKey, "light");
} catch (e) {}

// Expansion tracking for inspection and details rows (prevents auto-closing on refresh)
const expandedInspectionKeys = new Set();

function isEventsDataEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].id !== b[i].id || a[i].time !== b[i].time || a[i].severity !== b[i].severity) {
      return false;
    }
  }
  return true;
}

function showMessage(text, variant = false) {
  if (!message) return;
  message.textContent = text;
  let statusClass = "success";
  if (variant === true || variant === "error" || variant === "danger" || variant === "blocked") {
    statusClass = "error";
  } else if (variant === "warning" || variant === "suspicious") {
    statusClass = "warning";
  }
  message.className = `toast-message ${statusClass}`;
  message.hidden = false;
  setTimeout(() => {
    message.hidden = true;
  }, 5000);
}

function formatTime(value) {
  return new Date(value).toLocaleString([], {
    dateStyle: "short",
    timeStyle: "medium",
  });
}

// Dismiss alert banner
if (dismissAlertBtn) {
  dismissAlertBtn.addEventListener("click", () => {
    if (alertBanner) {
      alertBanner.hidden = true;
      alertBanner.style.display = "none";
    }
    for (const event of allEventsCache) {
      if (event.severity === "critical") {
        dismissedAlertIds.add(event.id);
      }
    }
  });
}

// View Mode Switcher
if (viewModeConsolidated && viewModeRaw) {
  viewModeConsolidated.addEventListener("click", () => {
    currentViewMode = "consolidated";
    viewModeConsolidated.classList.add("active");
    viewModeConsolidated.setAttribute("aria-selected", "true");
    viewModeRaw.classList.remove("active");
    viewModeRaw.setAttribute("aria-selected", "false");
    updateTableHeaders();
    filterAndRenderEvents();
  });

  viewModeRaw.addEventListener("click", () => {
    currentViewMode = "raw";
    viewModeRaw.classList.add("active");
    viewModeRaw.setAttribute("aria-selected", "true");
    viewModeConsolidated.classList.remove("active");
    viewModeConsolidated.setAttribute("aria-selected", "false");
    updateTableHeaders();
    filterAndRenderEvents();
  });
}

function updateTableHeaders() {
  if (!eventsTableHead) return;
  if (currentViewMode === "consolidated") {
    eventsTableHead.innerHTML = `
      <tr>
        <th scope="col">Time</th>
        <th scope="col">Connected Device</th>
        <th scope="col">Security Status</th>
        <th scope="col">Risk / Reason</th>
        <th scope="col">Action Taken</th>
        <th scope="col" class="text-right">Actions</th>
      </tr>
    `;
  } else {
    eventsTableHead.innerHTML = `
      <tr>
        <th scope="col">Timestamp</th>
        <th scope="col">Event Activity</th>
        <th scope="col">Device Identifier & Metadata</th>
        <th scope="col">Source Engine</th>
        <th scope="col">Severity</th>
        <th scope="col" class="text-right">Action</th>
      </tr>
    `;
  }
}

function extractVid(deviceId) {
  const m = String(deviceId).match(/VID_([0-9A-Fa-f]{4})/i);
  return m ? m[1].toUpperCase() : "";
}

function extractPid(deviceId) {
  const m = String(deviceId).match(/PID_([0-9A-Fa-f]{4})/i);
  return m ? m[1].toUpperCase() : "";
}

function isGenericName(name) {
  if (!name) return true;
  const s = String(name).trim().toLowerCase();
  return (
    s === "usb composite device" ||
    s === "usb input device" ||
    s === "generic usb hub" ||
    s === "usb root hub" ||
    s === "usb device" ||
    s === "unnamed device"
  );
}

function inferDeviceTypeFromEvent(event) {
  if (event.details?.device_type) return event.details.device_type;
  const str = `${event.device_id} ${event.details?.name || ""} ${event.details?.pnp_class || ""} ${event.details?.service || ""}`.toLowerCase();
  if (str.includes("keyboard") && str.includes("mouse")) return "Keyboard & Mouse";
  if (str.includes("keyboard") || str.includes("kbd")) return "Keyboard";
  if (str.includes("mouse") || str.includes("mou")) return "Mouse";
  if (str.includes("disk") || str.includes("storage") || str.includes("usbstor") || event.event_type.startsWith("scan.")) return "USB Storage Drive";
  if (str.includes("audio") || str.includes("headset") || str.includes("sound") || str.includes("media")) return "Audio Device";
  if (str.includes("camera") || str.includes("webcam") || str.includes("video")) return "Webcam";
  if (str.includes("bluetooth") || str.includes("bth")) return "Bluetooth Adapter";
  if (str.includes("yubikey") || str.includes("token") || str.includes("smartcard")) return "Security Token";
  return "Unrecognized USB Peripheral";
}

function groupEventsByDevice(events) {
  const groups = new Map();

  for (const event of events) {
    let key = event.device_id;
    if (key.includes("&MI_")) {
      key = key.replace(/&MI_[0-9A-Fa-f]{2}/i, "");
    }
    if (key.toUpperCase().startsWith("USBSTOR\\") && key.endsWith("&0")) {
      key = key.slice(0, -2);
    }

    if (!groups.has(key)) {
      const vid = event.details?.vendor_id || extractVid(event.device_id);
      const pid = event.details?.product_id || extractPid(event.device_id);
      const serial = event.details?.serial_number || "";
      const devType = event.details?.device_type || inferDeviceTypeFromEvent(event);
      let friendlyName = event.details?.friendly_name || event.details?.name || "";
      if (isGenericName(friendlyName)) {
        friendlyName = (devType !== "Unrecognized USB Peripheral") ? `USB ${devType}` : "USB Peripheral";
      }

      groups.set(key, {
        groupKey: key,
        primaryDeviceId: event.device_id,
        name: friendlyName,
        deviceType: devType,
        vendorId: vid,
        productId: pid,
        serialNumber: serial,
        lastTime: event.time,
        events: [],
        highestSeverity: "info",
        verdict: "SAFE",
        risk: "None (Approved Peripheral)",
        actionTaken: "Allowed & Active",
        summary: event.details?.summary || "",
      });
    }

    const group = groups.get(key);
    group.events.push(event);

    if (new Date(event.time) > new Date(group.lastTime)) {
      group.lastTime = event.time;
    }

    const evName = event.details?.friendly_name || event.details?.name;
    if (evName && !isGenericName(evName)) {
      group.name = evName;
    }
    if (event.details?.device_type && event.details.device_type !== "Unrecognized USB Peripheral") {
      group.deviceType = event.details.device_type;
    }
    if (event.details?.serial_number) {
      group.serialNumber = event.details.serial_number;
    }

    const sev = (event.severity || "").toLowerCase();
    const type = event.event_type || "";

    if (sev === "critical" || type === "device.blocked" || type === "device.spoofed_identity" || type === "hid.injection_detected") {
      group.highestSeverity = "critical";
      group.verdict = "BLOCKED";
      if (type === "device.spoofed_identity") {
        group.risk = "Identity Spoofing Detected — Serial mismatch";
        group.actionTaken = "Hardware Blocked (Port Disabled)";
      } else if (type === "hid.injection_detected") {
        group.risk = "BadUSB Keystroke Injection (Robotic typing cadence)";
        group.actionTaken = "Hardware Blocked (Port Disabled)";
      } else if (type === "scan.completed" || event.details?.flagged?.length) {
        group.risk = "Malware / YARA Threat Found on storage drive";
        group.actionTaken = "Volume Quarantined";
      } else {
        group.risk = event.details?.reason || "Security Threat — Hardware Attack Intercepted";
        group.actionTaken = "Hardware Blocked (Port Disabled)";
      }
      group.summary = event.details?.summary || `${group.name} (${group.deviceType}) — THREAT BLOCKED: ${group.risk}. Action taken: ${group.actionTaken}`;
    } else if (sev === "warning" && group.highestSeverity !== "critical") {
      group.highestSeverity = "warning";
      group.verdict = "SUSPICIOUS";
      group.risk = event.details?.reason || "Unregistered Device — Not recognized on whitelist";
      group.actionTaken = "User Warned";
      group.summary = event.details?.summary || `${group.name} (${group.deviceType}) — SUSPICIOUS WARNING: ${group.risk}. Action taken: ${group.actionTaken}`;
    } else if (group.highestSeverity === "info") {
      if (type === "device.allowed") {
        group.verdict = "SAFE";
        group.risk = "None — Approved by Whitelist";
        group.actionTaken = "Allowed & Active";
        group.summary = event.details?.summary || `${group.name} (${group.deviceType}) — SAFE: Authorized clean device.`;
      } else if (type === "device.disconnected") {
        group.verdict = "INFO";
        group.risk = "None";
        group.actionTaken = "Disconnected";
        group.summary = `${group.name} (${group.deviceType}) disconnected.`;
      }
    }
  }

  return Array.from(groups.values()).sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));
}

// Multi-Scenario Simulation Handler
async function triggerScenarioSimulation(scenarioName, buttonEl = null) {
  let originalContent = "";
  if (buttonEl) {
    buttonEl.disabled = true;
    originalContent = buttonEl.innerHTML;
    buttonEl.innerHTML = "<span>Simulating...</span>";
  }
  try {
    const res = await fetch("/api/v1/simulate/scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioName }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned status ${res.status}`);
    }
    const data = await res.json();
    let variant = "success";
    if (data.outcome === "blocked") {
      variant = "error";
    } else if (data.outcome === "warning") {
      variant = "warning";
    }
    showMessage(data.summary, variant);
    await loadEvents(false);
  } catch (err) {
    showMessage(`Simulation failed: ${err.message}`, true);
  } finally {
    if (buttonEl) {
      buttonEl.disabled = false;
      buttonEl.innerHTML = originalContent;
    }
    if (simulationMenu) {
      simulationMenu.hidden = true;
      if (simulateDropdownBtn) {
        simulateDropdownBtn.setAttribute("aria-expanded", "false");
      }
    }
  }
}

// Dropdown Toggle
if (simulateDropdownBtn && simulationMenu) {
  simulateDropdownBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isHidden = simulationMenu.hidden;
    simulationMenu.hidden = !isHidden;
    simulateDropdownBtn.setAttribute("aria-expanded", String(!isHidden));
  });

  document.addEventListener("click", (e) => {
    if (
      !simulationMenu.hidden &&
      !simulationMenu.contains(e.target) &&
      e.target !== simulateDropdownBtn &&
      !simulateDropdownBtn.contains(e.target)
    ) {
      simulationMenu.hidden = true;
      simulateDropdownBtn.setAttribute("aria-expanded", "false");
    }
  });
}

// Attach simulation handler to all scenario trigger buttons
document.querySelectorAll("[data-scenario]").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const scenario = btn.getAttribute("data-scenario");
    if (scenario) {
      triggerScenarioSimulation(scenario, btn);
    }
  });
});

// Toggle Whitelist Form
if (showAddWlBtn && addWlForm) {
  showAddWlBtn.addEventListener("click", () => {
    addWlForm.hidden = !addWlForm.hidden;
    if (!addWlForm.hidden) {
      document.querySelector("#wl-name")?.focus();
    }
  });
}

if (cancelWlBtn && addWlForm) {
  cancelWlBtn.addEventListener("click", () => {
    addWlForm.hidden = true;
  });
}

// Add to Whitelist Submit
if (addWlForm) {
  addWlForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const entry = {
      name: document.querySelector("#wl-name").value.trim(),
      serial_number: document.querySelector("#wl-serial").value.trim() || null,
      vendor_id: document.querySelector("#wl-vid").value.trim() || null,
      product_id: document.querySelector("#wl-pid").value.trim() || null,
      notes: "Added via dashboard",
    };

    try {
      const res = await fetch("/api/v1/policy/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      addWlForm.reset();
      addWlForm.hidden = true;
      showMessage(`Authorized device '${entry.name}' successfully saved!`, false);
      await loadWhitelist();
    } catch (err) {
      showMessage(`Failed to save whitelist entry: ${err.message}`, true);
    }
  });
}

async function loadWhitelist() {
  if (!whitelistBody) return;
  try {
    const res = await fetch("/api/v1/policy/whitelist");
    if (!res.ok) return;
    const items = await res.json();
    renderWhitelist(items);
  } catch (err) {
    console.debug("Whitelist fetch error:", err);
  }
}

function renderWhitelist(items) {
  if (!items.length) {
    whitelistBody.innerHTML = '<tr><td colspan="5" class="empty-state">No authorized devices configured. All unknown peripherals are evaluated per security policy.</td></tr>';
    return;
  }

  whitelistBody.innerHTML = "";
  for (const item of items) {
    const tr = document.createElement("tr");

    const vidPid = item.vendor_id || item.product_id
      ? `${item.vendor_id || "????"} : ${item.product_id || "????"}`
      : "Any";

    tr.innerHTML = `
      <td><strong>${escapeHtml(item.name)}</strong></td>
      <td><code>${escapeHtml(item.serial_number || "Any Serial")}</code></td>
      <td><code>${escapeHtml(vidPid)}</code></td>
      <td class="text-muted small">${formatTime(item.created_at)}</td>
      <td class="text-right">
        <button class="btn btn-sm btn-danger" data-remove-wl="${item.id}" type="button">Revoke</button>
      </td>
    `;
    whitelistBody.appendChild(tr);
  }
}

if (whitelistBody) {
  whitelistBody.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-remove-wl]");
    if (!btn) return;
    const id = btn.dataset.removeWl;
    if (!confirm("Revoke authorization for this device?")) return;

    try {
      const res = await fetch(`/api/v1/policy/whitelist/${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showMessage("Authorization revoked.");
      await loadWhitelist();
    } catch (err) {
      showMessage(`Revocation failed: ${err.message}`, true);
    }
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Live Search Filter
if (eventSearchInput) {
  eventSearchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    filterAndRenderEvents();
  });
}

function filterAndRenderEvents() {
  let filtered = allEventsCache;
  if (searchQuery) {
    filtered = allEventsCache.filter((e) => {
      const str = `${e.device_id} ${e.event_type} ${e.source} ${JSON.stringify(e.details)}`.toLowerCase();
      return str.includes(searchQuery);
    });
  }
  displayEventRows(filtered);
}

// Chart.js Configuration with Montserrat Font
function renderCharts(events) {
  if (typeof Chart === "undefined") return;
  Chart.defaults.font.family = "'Montserrat', sans-serif";

  const textColor = "#707eae";
  const gridColor = "rgba(0, 0, 0, 0.05)";

  const infoCount = events.filter((e) => e.severity === "info").length;
  const warnCount = events.filter((e) => e.severity === "warning").length;
  const critCount = events.filter((e) => e.severity === "critical").length;

  // 1. Severity Chart
  const sevCtx = document.getElementById("severity-chart")?.getContext("2d");
  if (sevCtx) {
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sevCtx, {
      type: "doughnut",
      data: {
        labels: ["Info (Safe)", "Warning", "Critical"],
        datasets: [{
          data: [infoCount, warnCount, critCount],
          backgroundColor: ["#2563eb", "#b45309", "#be123c"],
          borderColor: "#ffffff",
          borderWidth: 3,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: textColor, boxWidth: 12, padding: 14, font: { family: "var(--font-sans)", size: 11, weight: "600" } },
          },
        },
      },
    });
  }

  // 2. Activity Type Chart
  const typeCounts = {};
  for (const e of events) {
    const key = e.event_type.replace("device.", "").replace("scan.", "").replace("hid.", "");
    typeCounts[key] = (typeCounts[key] || 0) + 1;
  }
  const topTypes = Object.entries(typeCounts).slice(0, 6);

  const actCtx = document.getElementById("activity-chart")?.getContext("2d");
  if (actCtx) {
    if (activityChart) activityChart.destroy();
    activityChart = new Chart(actCtx, {
      type: "bar",
      data: {
        labels: topTypes.map(([k]) => k.toUpperCase()),
        datasets: [{
          data: topTypes.map(([, v]) => v),
          backgroundColor: "#1e3a8a",
          borderRadius: 6,
          hoverBackgroundColor: "#2563eb",
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: textColor, font: { family: "var(--font-sans)", size: 10, weight: "600" } },
          },
          y: {
            beginAtZero: true,
            grid: { color: gridColor },
            ticks: { precision: 0, color: textColor, font: { family: "var(--font-mono)", size: 10 } },
          },
        },
      },
    });
  }
}

function checkLiveAlerts(events) {
  if (!alertBanner) return;
  const criticalEvent = events.find(
    (e) => e.severity === "critical" && !dismissedAlertIds.has(e.id)
  );
  const warningEvent = !criticalEvent
    ? events.find((e) => e.severity === "warning" && !dismissedAlertIds.has(e.id))
    : null;

  if (criticalEvent) {
    if (!notifiedEventIds.has(criticalEvent.id)) {
      notifiedEventIds.add(criticalEvent.id);
      playCyberThreatAlert();
      sendWindowsWebNotification(
        "🛡️ USB Analyzer: Threat Blocked",
        `Action taken: Port disabled.\n${criticalEvent.details?.summary || criticalEvent.details?.reason || "High-risk threat intercepted."}`
      );
    }
    alertBanner.hidden = false;
    alertBanner.style.display = "flex";
    alertBanner.classList.remove("alert-warning");
    alertBanner.classList.add("alert-critical");
    const summary = criticalEvent.details?.reason || criticalEvent.details?.summary || criticalEvent.details?.threat || "High-risk hardware attack intercepted";
    alertSummary.textContent = `THREAT BLOCKED: ${summary}`;
    alertDetail.textContent = `Target: ${criticalEvent.device_id} • Hardware port isolated to protect endpoint.`;
  } else if (warningEvent) {
    if (!notifiedEventIds.has(warningEvent.id)) {
      notifiedEventIds.add(warningEvent.id);
      sendWindowsWebNotification(
        "⚠️ USB Analyzer: Suspicious Device Alert",
        `Problem: Unregistered USB hardware connected.\nClick to choose action: Trust or Block device.`,
        () => openSuspiciousTriageModal(warningEvent)
      );
      openSuspiciousTriageModal(warningEvent);
    }
    alertBanner.hidden = false;
    alertBanner.style.display = "flex";
    alertBanner.classList.remove("alert-critical");
    alertBanner.classList.add("alert-warning");
    const summary = warningEvent.details?.reason || warningEvent.details?.summary || "Suspicious unverified hardware attached";
    alertSummary.textContent = `SUSPICIOUS DEVICE WARNING: ${summary}`;
    alertDetail.textContent = `Target: ${warningEvent.device_id} • Device is not on your trusted whitelist. Click banner to decide action.`;
  } else {
    alertBanner.hidden = true;
    alertBanner.style.display = "none";
  }
}

// Click banner to open triage modal if warning
if (alertBanner) {
  alertBanner.addEventListener("click", (e) => {
    if (e.target.closest("#dismiss-alert-btn")) return;
    if (alertBanner.classList.contains("alert-warning")) {
      const warningEvent = allEventsCache.find((ev) => ev.severity === "warning");
      if (warningEvent) openSuspiciousTriageModal(warningEvent);
    }
  });
}

function renderEvents(events) {
  const hasChanged = !isEventsDataEqual(events, allEventsCache);
  allEventsCache = events;

  document.querySelector("#total-events").textContent = events.length;
  document.querySelector("#warning-events").textContent =
    events.filter((event) => event.severity === "warning").length;
  document.querySelector("#critical-events").textContent =
    events.filter((event) => event.severity === "critical").length;
  document.querySelector("#blocked-count").textContent =
    events.filter((event) => event.event_type === "device.blocked").length;

  const scanEvents = events.filter((e) => ["scan.started", "scan.completed"].includes(e.event_type));
  document.querySelector("#active-scans").textContent =
    scanEvents.filter((e) => e.event_type === "scan.started").length;
  document.querySelector("#flagged-files").textContent =
    events.filter((e) => e.event_type === "scan.completed")
      .reduce((sum, e) => sum + Number(e.details?.flagged_count ?? 0), 0);

  if (events.length && document.querySelector("#last-update")) {
    document.querySelector("#last-update").textContent = formatTime(events[0].time);
  }

  checkLiveAlerts(events);
  if (hasChanged) {
    renderCharts(events);
    filterAndRenderEvents();
  }
}

function displayEventRows(events) {
  if (!eventsBody) return;

  if (currentViewMode === "consolidated") {
    const groups = groupEventsByDevice(events);
    displayConsolidatedDevices(groups);
  } else {
    displayRawEvents(events);
  }
}

function generateInfosecSummary(item) {
  const isGroup = Array.isArray(item.events);
  const events = isGroup ? item.events : [item];
  const verdict = item.verdict || (item.severity === "critical" ? "DANGER" : item.severity === "warning" ? "WARNING" : "SAFE");
  const deviceType = item.deviceType || item.details?.device_type || "USB Peripheral";

  // Check event types
  const hasSpoof = events.some((e) => e.event_type === "device.spoofed_identity");
  const hasBadUsb = events.some((e) => e.event_type === "hid.injection_detected");
  const scanEvent = events.find((e) => e.event_type === "scan.completed" || e.event_type === "scan.started");
  const hasMalware = Boolean(scanEvent?.details?.flagged && scanEvent.details.flagged.length > 0);
  const isBlocked = events.some((e) => e.event_type === "device.blocked");
  const isAllowed = events.some((e) => e.event_type === "device.allowed");
  const isViolation = verdict === "WARNING" || events.some((e) => e.event_type === "policy.violation");

  let statusText = "INFOSEC ASSESSMENT";
  let badgeClass = "badge-safe";
  let category = "Device Connected";
  let reason = "The device was inspected on the USB controller bus.";
  let actionJustification = "Allowed under continuous telemetry monitoring.";
  let recommendation = "Standard monitoring active. No administrative intervention required.";
  let mitreFramework = "Physical Bus Access Control Baseline Verified";

  if (hasBadUsb) {
    statusText = "HIGH-SEVERITY HARDWARE ATTACK";
    badgeClass = "badge-danger";
    category = "Keystroke Injection Threat (BadUSB / Rubber Ducky)";
    mitreFramework = "T1200 (Hardware Additions) • T1059 (Command & Scripting Interpreter)";
    reason = `This device identifies as a '${deviceType}', but hardware timing analysis detected rapid automated keystrokes typed with an artificial cadence (< 4ms inter-key delay, 0ms variance). Attackers program rogue microcontrollers to inject pre-compiled terminal commands, scripts, or reverse shells at machine speed.`;
    actionJustification = "Hardware Blocked: The system immediately detached and disabled the USB port to cut off automated keystroke execution before payloads could execute.";
    recommendation = "Do not connect this peripheral to other systems. Physically confiscate and inspect the hardware for covert programmable microcontrollers.";
  } else if (hasMalware) {
    statusText = "MALICIOUS REMOVABLE MEDIA";
    badgeClass = "badge-danger";
    category = "Storage Volume Containing Malware / YARA Signatures";
    mitreFramework = "T1091 (Replication via Removable Media) • T1547.001 (Autorun Execution)";
    reason = `Storage scanning on this drive intercepted dangerous files matching malicious signatures, autorun scripts, or YARA heuristic threat indicators. Removable drives are a primary vector for ransomware infection, air-gap crossing, and data harvesting.`;
    actionJustification = "Volume Quarantined: The drive was unmounted and access was restricted to prevent local execution or propagation over the organization's network.";
    recommendation = "Quarantine the removable drive. Do not open or execute files from it. Submit flagged files to an isolated sandbox or the SOC team for reverse engineering.";
  } else if (hasSpoof) {
    statusText = "HARDWARE IDENTITY SPOOFING";
    badgeClass = "badge-danger";
    category = "Peripheral Impersonation / Serial Number Mismatch";
    mitreFramework = "T1036 (Masquerading / Hardware Descriptor Spoofing)";
    reason = `The connected device claimed a trusted Vendor ID (VID) and Product ID (PID) matching an authorized organization asset, but broadcasted an unregistered or counterfeit physical serial number. Attackers frequently clone public VID/PID pairs to fool simple device filters.`;
    actionJustification = "Hardware Blocked: The analyzer enforced strict Zero-Trust serial validation and disabled the port to prevent unauthorized hardware from operating under a false identity.";
    recommendation = "Investigate the physical origin of this hardware. Check if the device is a cloned counterfeit or an unauthorized substitute.";
  } else if (isBlocked) {
    statusText = "HARDWARE THREAT BLOCKED";
    badgeClass = "badge-danger";
    category = "Threat Containment & Device Isolation";
    mitreFramework = "T1200 (Unauthorized Peripheral Insertion Blocked)";
    reason = `This '${deviceType}' was identified as a hardware threat or dangerous peripheral. The analyzer automatically isolated the device to protect endpoint data and bus integrity.`;
    actionJustification = "Hardware Blocked: The system disabled the USB port, cutting off bus communication immediately.";
    recommendation = "Do not connect this peripheral to other computers. Submit for security evaluation.";
  } else if (isViolation || verdict === "SUSPICIOUS" || verdict === "WARNING") {
    statusText = "SUSPICIOUS DEVICE WARNING";
    badgeClass = "badge-warning";
    category = "Unrecognized Hardware — User Warned";
    mitreFramework = "T1200 (Unapproved Physical Peripheral Insertion)";
    reason = `The connected peripheral is not registered on the trusted device whitelist. Unrecognized devices can carry firmware risks or unapproved hardware functions.`;
    actionJustification = "User Warned: A high-visibility security alert was generated to notify the user of unverified hardware.";
    recommendation = "Verify the physical origin of this device. If this is a trusted device, click '+ Trust & Add to Whitelist' below to authorize it as Safe.";
  } else if (isAllowed) {
    statusText = "AUTHORIZED SAFE PERIPHERAL";
    badgeClass = "badge-safe";
    category = "Approved Trusted Peripheral";
    mitreFramework = "T1052 Physical Medium Access Control Compliant";
    reason = `The peripheral's Vendor ID, Product ID, and Hardware Serial matched an authorized organizational whitelist rule. The device passed zero-trust authentication checks.`;
    actionJustification = "Allowed & Active: Normal peripheral access granted under continuous behavioral and typing monitoring.";
    recommendation = "Peripheral is behaving normally. No security action is necessary.";
  }

  return { statusText, badgeClass, category, reason, actionJustification, recommendation, mitreFramework };
}

function createInfosecCard(item) {
  const info = generateInfosecSummary(item);
  const isSuspicious = info.badgeClass === "badge-warning" || item.verdict === "SUSPICIOUS" || item.verdict === "WARNING";
  const card = document.createElement("div");
  card.className = `infosec-card ${info.badgeClass}`;
  card.innerHTML = `
    <div class="infosec-header">
      <div class="infosec-title-group">
        <span class="infosec-badge">${escapeHtml(info.statusText)}</span>
        <h3 class="infosec-category">${escapeHtml(info.category)}</h3>
        <div class="mitre-banner-pill">🛡 MITRE ATT&amp;CK: ${escapeHtml(info.mitreFramework)}</div>
      </div>
    </div>
    <div class="infosec-body">
      <div class="infosec-section">
        <span class="infosec-label">Why was this device flagged / evaluated?</span>
        <p class="infosec-text">${escapeHtml(info.reason)}</p>
      </div>
      <div class="infosec-section">
        <span class="infosec-label">Information Security Action Taken:</span>
        <p class="infosec-text">${escapeHtml(info.actionJustification)}</p>
      </div>
      <div class="infosec-section">
        <span class="infosec-label">Cybersecurity Recommendation:</span>
        <p class="infosec-text">${escapeHtml(info.recommendation)}</p>
      </div>
      ${isSuspicious ? `
      <div class="infosec-section" style="margin-top: 14px; padding-top: 12px; border-top: 1px dashed #e2e8f0;">
        <button class="btn btn-primary btn-sm quick-whitelist-btn" type="button" data-name="${escapeHtml(item.name || 'Approved Peripheral')}" data-vid="${escapeHtml(item.vendorId || '')}" data-pid="${escapeHtml(item.productId || '')}" data-serial="${escapeHtml(item.serialNumber || '')}" data-device-id="${escapeHtml(item.deviceId || item.id || '')}">
          + Trust &amp; Add to Whitelist
        </button>
      </div>` : ''}
    </div>
  `;
  return card;
}

function displayConsolidatedDevices(groups) {
  if (!eventsBody) return;

  if (!groups.length) {
    eventsBody.innerHTML = '<tr><td colspan="6" class="empty-state">Database reset clean. Connect any USB device to inspect security status in real-time.</td></tr>';
    return;
  }

  const rows = [];
  groups.forEach((group, index) => {
    const row = document.createElement("tr");

    // 1. Time
    const timeTd = document.createElement("td");
    timeTd.className = "font-mono small text-muted";
    timeTd.textContent = formatTime(group.lastTime);

    // 2. Connected Device & Type
    const devTd = document.createElement("td");
    const nameWrap = document.createElement("div");
    nameWrap.innerHTML = `<strong>${escapeHtml(group.name)}</strong><span class="device-type-badge">${escapeHtml(group.deviceType)}</span>`;
    devTd.appendChild(nameWrap);

    const vidPid = (group.vendorId || group.productId)
      ? `VID: ${group.vendorId || "????"} | PID: ${group.productId || "????"}`
      : "";
    const snText = group.serialNumber ? ` | SN: ${group.serialNumber}` : "";
    const metaDiv = document.createElement("div");
    metaDiv.className = "device-sub-meta font-mono";
    metaDiv.textContent = `${vidPid}${snText}` || group.primaryDeviceId;
    devTd.appendChild(metaDiv);

    // 3. Security Status (Verdict)
    const statusTd = document.createElement("td");
    const verdictSpan = document.createElement("span");
    const vClass = (group.verdict || "info").toLowerCase();
    verdictSpan.className = `verdict-badge verdict-${vClass}`;
    verdictSpan.textContent = group.verdict;
    statusTd.appendChild(verdictSpan);

    // 4. Risk / Reason
    const riskTd = document.createElement("td");
    riskTd.className = "small";
    riskTd.textContent = group.risk;

    // 5. Action Taken
    const actionTd = document.createElement("td");
    const actionSpan = document.createElement("span");
    actionSpan.className = "action-badge";
    actionSpan.textContent = group.actionTaken;
    actionTd.appendChild(actionSpan);

    // 6. Actions (Inspect + Whitelist)
    const actActionTd = document.createElement("td");
    actActionTd.className = "text-right";
    const btnGroup = document.createElement("div");
    btnGroup.style.display = "inline-flex";
    btnGroup.style.gap = "6px";

    const isExpanded = expandedInspectionKeys.has(group.primaryDeviceId);

    const inspectBtn = document.createElement("button");
    inspectBtn.className = "btn btn-sm btn-secondary";
    inspectBtn.type = "button";
    inspectBtn.dataset.detailToggle = "";
    inspectBtn.dataset.detailKey = group.primaryDeviceId;
    inspectBtn.setAttribute("aria-expanded", String(isExpanded));
    inspectBtn.setAttribute("aria-controls", `device-details-${index}`);
    inspectBtn.textContent = isExpanded ? "Close" : "Inspect";
    btnGroup.appendChild(inspectBtn);

    if (group.verdict === "DANGER" || group.verdict === "WARNING") {
      const wlBtn = document.createElement("button");
      wlBtn.className = "btn btn-sm btn-ghost";
      wlBtn.type = "button";
      wlBtn.textContent = "+ Whitelist";
      wlBtn.title = "Authorize this peripheral in the whitelist";
      wlBtn.addEventListener("click", () => {
        document.querySelector("#wl-name").value = group.name;
        document.querySelector("#wl-serial").value = group.serialNumber || "";
        document.querySelector("#wl-vid").value = group.vendorId || "";
        document.querySelector("#wl-pid").value = group.productId || "";
        addWlForm.hidden = false;
        addWlForm.scrollIntoView({ behavior: "smooth" });
      });
      btnGroup.appendChild(wlBtn);
    }
    actActionTd.appendChild(btnGroup);

    row.append(timeTd, devTd, statusTd, riskTd, actionTd, actActionTd);

    // Detailed Forensic Expandable Row
    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.id = `device-details-${index}`;
    detailsRow.hidden = !isExpanded;

    const detailsTd = document.createElement("td");
    detailsTd.colSpan = 6;
    const panel = document.createElement("div");
    panel.className = "details-panel";

    // InfoSec Assessment Card
    panel.appendChild(createInfosecCard(group));

    // Summary callout
    if (group.summary) {
      const summaryDiv = document.createElement("div");
      summaryDiv.className = "summary-callout";
      summaryDiv.textContent = group.summary;
      panel.appendChild(summaryDiv);
    }

    // Check if any event has flagged findings or scan caveats
    const scanEvent = group.events.find((e) => e.event_type === "scan.completed" || e.event_type === "scan.started");
    if (scanEvent) {
      const caveat = document.createElement("div");
      caveat.className = "scan-caveat";
      caveat.textContent = "These are filename-based indicators and signature matches.";
      panel.appendChild(caveat);

      if (scanEvent.details?.flagged && Array.isArray(scanEvent.details.flagged) && scanEvent.details.flagged.length > 0) {
        const grid = document.createElement("div");
        grid.className = "findings-grid";
        for (const finding of scanEvent.details.flagged) {
          const card = document.createElement("div");
          card.className = "finding-card";
          card.innerHTML = `
            <div class="finding-path">${escapeHtml(finding.path)}</div>
            <div class="finding-meta">SHA-256: <code>${escapeHtml(finding.sha256)}</code> • ${(finding.size || 0).toLocaleString()} bytes</div>
            <div class="finding-flags">
              ${(finding.flags || []).map((f) => `<span class="flag-badge">${escapeHtml(f)}</span>`).join("")}
            </div>
          `;
          grid.appendChild(card);
        }
        panel.appendChild(grid);
      }
    }

    // Consolidated Sub-Events Audit Trail
    const eventsSummary = document.createElement("div");
    eventsSummary.className = "small text-muted font-mono";
    eventsSummary.style.marginTop = "4px";
    eventsSummary.textContent = `Consolidated Events (${group.events.length} event${group.events.length === 1 ? "" : "s"}): ` +
      group.events.map((e) => `${e.event_type} [${e.severity.toUpperCase()}]`).join(" → ");
    panel.appendChild(eventsSummary);

    // Full JSON Block
    const pre = document.createElement("pre");
    pre.className = "details-json";
    pre.textContent = JSON.stringify(
      group.events.length === 1 ? group.events[0].details : { summary: group.summary, events: group.events },
      null,
      2
    );
    panel.appendChild(pre);

    detailsTd.appendChild(panel);
    detailsRow.appendChild(detailsTd);

    rows.push(row, detailsRow);
  });

  eventsBody.replaceChildren(...rows);
}

function displayRawEvents(events) {
  if (!eventsBody) return;

  if (!events.length) {
    eventsBody.innerHTML = '<tr><td colspan="6" class="empty-state">No matching device activity found.</td></tr>';
    return;
  }

  const rows = [];
  events.forEach((event, index) => {
    const row = document.createElement("tr");

    // 1. Time
    const timeTd = document.createElement("td");
    timeTd.className = "font-mono small text-muted";
    timeTd.textContent = formatTime(event.time);

    // 2. Activity Toggle
    const isExpanded = expandedInspectionKeys.has(event.id);
    const actTd = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.className = "activity-toggle";
    toggle.type = "button";
    toggle.dataset.detailToggle = "";
    toggle.dataset.detailKey = event.id;
    toggle.setAttribute("aria-expanded", String(isExpanded));
    toggle.setAttribute("aria-controls", `raw-event-details-${index}`);
    toggle.innerHTML = `<strong>${escapeHtml(event.event_type)}</strong><span class="activity-chevron" aria-hidden="true"></span>`;
    actTd.appendChild(toggle);

    // 3. Device Info
    const devTd = document.createElement("td");
    const devCode = document.createElement("code");
    devCode.textContent = event.device_id;
    devTd.appendChild(devCode);
    if (event.details?.name) {
      const nameDiv = document.createElement("div");
      nameDiv.className = "text-muted small";
      nameDiv.textContent = event.details.name;
      devTd.appendChild(nameDiv);
    }

    // 4. Source Engine
    const srcTd = document.createElement("td");
    srcTd.className = "small font-mono text-muted";
    srcTd.textContent = event.source;

    // 5. Severity Badge
    const sevTd = document.createElement("td");
    const sevSpan = document.createElement("span");
    sevSpan.className = `severity ${event.severity}`;
    sevSpan.textContent = event.severity;
    sevTd.appendChild(sevSpan);

    // 6. Action
    const actActionTd = document.createElement("td");
    actActionTd.className = "text-right";
    if (event.details?.serial_number || event.details?.vendor_id) {
      const wlBtn = document.createElement("button");
      wlBtn.className = "btn btn-sm btn-secondary";
      wlBtn.textContent = "+ Whitelist";
      wlBtn.title = "Authorize this peripheral in the whitelist policy";
      wlBtn.addEventListener("click", () => {
        document.querySelector("#wl-name").value = event.details.name || "USB Device";
        document.querySelector("#wl-serial").value = event.details.serial_number || "";
        document.querySelector("#wl-vid").value = event.details.vendor_id || "";
        document.querySelector("#wl-pid").value = event.details.product_id || "";
        addWlForm.hidden = false;
        addWlForm.scrollIntoView({ behavior: "smooth" });
      });
      actActionTd.appendChild(wlBtn);
    }

    row.append(timeTd, actTd, devTd, srcTd, sevTd, actActionTd);

    // Forensic Details Panel Row
    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.id = `raw-event-details-${index}`;
    detailsRow.hidden = !isExpanded;

    const detailsTd = document.createElement("td");
    detailsTd.colSpan = 6;
    const panel = document.createElement("div");
    panel.className = "details-panel";

    // InfoSec Assessment Card
    panel.appendChild(createInfosecCard(event));

    // Regression requirement: preserve filename-based indicators caveat
    if (event.event_type === "scan.completed") {
      const caveat = document.createElement("div");
      caveat.className = "scan-caveat";
      caveat.textContent = "These are filename-based indicators and signature matches.";
      panel.appendChild(caveat);

      if (event.details?.flagged && Array.isArray(event.details.flagged) && event.details.flagged.length > 0) {
        const grid = document.createElement("div");
        grid.className = "findings-grid";
        for (const finding of event.details.flagged) {
          const card = document.createElement("div");
          card.className = "finding-card";
          card.innerHTML = `
            <div class="finding-path">${escapeHtml(finding.path)}</div>
            <div class="finding-meta">SHA-256: <code>${escapeHtml(finding.sha256)}</code> • ${(finding.size || 0).toLocaleString()} bytes</div>
            <div class="finding-flags">
              ${(finding.flags || []).map((f) => `<span class="flag-badge">${escapeHtml(f)}</span>`).join("")}
            </div>
          `;
          grid.appendChild(card);
        }
        panel.appendChild(grid);
      }
    }

    // Telemetry JSON Block
    const pre = document.createElement("pre");
    pre.className = "details-json";
    pre.textContent = JSON.stringify(event.details, null, 2);
    panel.appendChild(pre);

    detailsTd.appendChild(panel);
    detailsRow.appendChild(detailsTd);

    rows.push(row, detailsRow);
  });

  eventsBody.replaceChildren(...rows);
}

eventsBody.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-detail-toggle]");
  if (!toggle) return;
  const key = toggle.dataset.detailKey;
  const details = document.getElementById(toggle.getAttribute("aria-controls"));
  if (!details) return;
  const currentlyExpanded = toggle.getAttribute("aria-expanded") === "true";
  const willExpand = !currentlyExpanded;

  toggle.setAttribute("aria-expanded", String(willExpand));
  details.hidden = !willExpand;

  if (toggle.textContent.trim() === "Inspect" || toggle.textContent.trim() === "Close") {
    toggle.textContent = willExpand ? "Close" : "Inspect";
  }

  if (key) {
    if (willExpand) {
      expandedInspectionKeys.add(key);
    } else {
      expandedInspectionKeys.delete(key);
    }
  }
});

async function loadEvents(showStatus = true) {
  if (eventsLoadInProgress) return;
  eventsLoadInProgress = true;
  try {
    const response = await fetch("/api/v1/events?limit=150");
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const events = await response.json();
    renderEvents(events);
    apiStatus.textContent = "ONLINE (ACTIVE)";
    connection.classList.remove("is-unavailable");
    connection.classList.add("is-connected");
    if (showStatus) {
      showMessage(`Loaded ${events.length} event${events.length === 1 ? "" : "s"}.`);
    }
  } catch (error) {
    apiStatus.textContent = "OFFLINE";
    connection.classList.remove("is-connected");
    connection.classList.add("is-unavailable");
    showMessage(error.message, true);
  } finally {
    eventsLoadInProgress = false;
  }
}

document.querySelector("#refresh-events")?.addEventListener("click", () => loadEvents(true));

const clearEventsBtn = document.querySelector("#clear-events-btn");
if (clearEventsBtn) {
  clearEventsBtn.addEventListener("click", async () => {
    if (!confirm("Are you sure you want to clear all recorded USB events from the database?")) return;
    try {
      const response = await fetch("/api/v1/events", { method: "DELETE" });
      if (!response.ok) throw new Error(`API returned ${response.status}`);
      const data = await response.json();
      showMessage(`Cleared ${data.deleted || 0} event${data.deleted === 1 ? "" : "s"} from database.`);
      await loadEvents(false);
    } catch (err) {
      showMessage(`Failed to clear events: ${err.message}`, true);
    }
  });
}

// Quick Authorize directly from inspection drawer
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".quick-whitelist-btn");
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = "Authorizing...";
  try {
    const res = await fetch("/api/v1/policy/whitelist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: btn.dataset.name || "Approved Corporate Peripheral",
        vendor_id: btn.dataset.vid || null,
        product_id: btn.dataset.pid || null,
        serial_number: btn.dataset.serial || null,
        device_id: btn.dataset.deviceId || null,
        notes: "Approved via one-click SOC audit triage",
      }),
    });
    if (!res.ok) throw new Error("Could not add to whitelist");
    showMessage(`Device '${btn.dataset.name}' added to Whitelist and marked SAFE!`, false);
    await loadWhitelist();
    await loadEvents(false);
  } catch (err) {
    showMessage(`Failed to authorize: ${err.message}`, true);
    btn.disabled = false;
    btn.textContent = "+ Trust & Add to Whitelist";
  }
});

// Initial bootstrap
loadWhitelist();
loadEvents(false);

window.setInterval(() => {
  if (document.visibilityState === "visible") loadEvents(false);
}, 3500);
