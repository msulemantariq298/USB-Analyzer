const eventsBody = document.querySelector("#events-body");
const whitelistBody = document.querySelector("#whitelist-body");
const message = document.querySelector("#message");
const apiStatus = document.querySelector("#api-status");
const connection = document.querySelector(".connection");
const themeToggle = document.querySelector("#theme-toggle");
const alertBanner = document.querySelector("#security-alert-banner");
const alertSummary = document.querySelector("#alert-summary");
const alertDetail = document.querySelector("#alert-detail");
const dismissAlertBtn = document.querySelector("#dismiss-alert-btn");
const policyToggleBtn = document.querySelector("#policy-toggle-btn");
const policyModeText = document.querySelector("#policy-mode-text");
const showAddWlBtn = document.querySelector("#show-add-whitelist-btn");
const addWlForm = document.querySelector("#add-whitelist-form");
const cancelWlBtn = document.querySelector("#cancel-whitelist-btn");
const simulateBadusbBtn = document.querySelector("#simulate-badusb-btn");

const themeStorageKey = "usb-analyzer-theme";
let eventsLoadInProgress = false;
let currentPolicyMode = "enforce";
let severityChart = null;
let activityChart = null;
let dismissedAlertIds = new Set();

function updateThemeToggle(isDark) {
  const label = `Switch to ${isDark ? "light" : "dark"} mode`;
  themeToggle.setAttribute("aria-label", label);
  themeToggle.setAttribute("title", label);
  themeToggle.setAttribute("aria-pressed", String(isDark));
}

function setTheme(isDark) {
  const theme = isDark ? "dark" : "light";
  document.documentElement.dataset.theme = theme;
  updateThemeToggle(isDark);
  if (severityChart && activityChart) {
    updateChartsTheme(isDark);
  }
}

function getInitialTheme() {
  try {
    const savedTheme = localStorage.getItem(themeStorageKey);
    if (savedTheme === "dark" || savedTheme === "light") return savedTheme;
  } catch (error) {
    console.warn("Theme load error:", error);
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

setTheme(getInitialTheme() === "dark");

themeToggle.addEventListener("click", () => {
  const isDark = document.documentElement.dataset.theme !== "dark";
  setTheme(isDark);
  try {
    localStorage.setItem(themeStorageKey, isDark ? "dark" : "light");
  } catch (error) {
    console.warn("Theme save error:", error);
  }
});

function showMessage(text, isError = false) {
  message.textContent = text;
  message.className = `message ${isError ? "error" : "success"}`;
}

function formatTime(value) {
  return new Date(value).toLocaleString([], {
    dateStyle: "short",
    timeStyle: "short",
  });
}

// Dismiss alert banner
dismissAlertBtn.addEventListener("click", () => {
  alertBanner.hidden = true;
});

// BadUSB Simulation
simulateBadusbBtn.addEventListener("click", async () => {
  simulateBadusbBtn.disabled = true;
  simulateBadusbBtn.textContent = "Simulating...";
  try {
    const res = await fetch("/api/v1/simulate/badusb", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_id: "USB\\VID_16C0&PID_05DF\\DIGISPARK_DEMO",
        device_name: "Digispark BadUSB (Live Demo)",
        char_count: 35,
        delay_ms: 4.0,
      }),
    });
    const data = await res.json();
    showMessage(data.summary, false);
    await loadEvents(false);
  } catch (err) {
    showMessage(`Simulation failed: ${err.message}`, true);
  } finally {
    simulateBadusbBtn.disabled = false;
    simulateBadusbBtn.textContent = "Simulate BadUSB";
  }
});

// Toggle Whitelist Form
showAddWlBtn.addEventListener("click", () => {
  addWlForm.hidden = !addWlForm.hidden;
});

cancelWlBtn.addEventListener("click", () => {
  addWlForm.hidden = true;
});

// Add to Whitelist Submit
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
    showMessage(`Device '${entry.name}' added to whitelist!`, false);
    await loadWhitelist();
  } catch (err) {
    showMessage(`Failed to whitelist device: ${err.message}`, true);
  }
});

// Policy Mode Toggle
policyToggleBtn.addEventListener("click", async () => {
  const targetMode = currentPolicyMode === "enforce" ? "audit_only" : "enforce";
  try {
    const res = await fetch("/api/v1/policy/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: targetMode }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    currentPolicyMode = data.mode;
    updatePolicyUI();
    showMessage(`Policy mode changed to ${currentPolicyMode.toUpperCase()}`);
  } catch (err) {
    showMessage(`Failed to change policy mode: ${err.message}`, true);
  }
});

function updatePolicyUI() {
  if (currentPolicyMode === "enforce") {
    policyModeText.textContent = "ENFORCE (Active Blocking)";
    policyToggleBtn.className = "btn btn-badge badge-enforce";
  } else {
    policyModeText.textContent = "AUDIT ONLY (Log Violations)";
    policyToggleBtn.className = "btn btn-badge badge-audit";
  }
}

async function loadPolicyStatus() {
  try {
    const res = await fetch("/api/v1/policy/status");
    if (!res.ok) return;
    const data = await res.json();
    currentPolicyMode = data.mode;
    updatePolicyUI();
  } catch (err) {
    console.debug("Policy status fetch failed:", err);
  }
}

async function loadWhitelist() {
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
    whitelistBody.innerHTML = '<tr><td colspan="5" class="empty-state">No devices whitelisted yet.</td></tr>';
    return;
  }

  whitelistBody.innerHTML = "";
  for (const item of items) {
    const tr = document.createElement("tr");

    const vidPid = item.vendor_id || item.product_id
      ? `${item.vendor_id || "????"}:${item.product_id || "????"}`
      : "Any";

    tr.innerHTML = `
      <td><strong>${escapeHtml(item.name)}</strong></td>
      <td><code>${escapeHtml(item.serial_number || "Any")}</code></td>
      <td><code>${escapeHtml(vidPid)}</code></td>
      <td>${formatTime(item.created_at)}</td>
      <td>
        <button class="btn btn-sm btn-danger" data-remove-wl="${item.id}" type="button">Remove</button>
      </td>
    `;
    whitelistBody.appendChild(tr);
  }
}

whitelistBody.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-remove-wl]");
  if (!btn) return;
  const id = btn.dataset.removeWl;
  if (!confirm("Remove this device from the whitelist?")) return;

  try {
    const res = await fetch(`/api/v1/policy/whitelist/${id}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showMessage("Device removed from whitelist.");
    await loadWhitelist();
  } catch (err) {
    showMessage(`Failed to delete entry: ${err.message}`, true);
  }
});

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderCharts(events) {
  if (typeof Chart === "undefined") return;

  const infoCount = events.filter((e) => e.severity === "info").length;
  const warnCount = events.filter((e) => e.severity === "warning").length;
  const critCount = events.filter((e) => e.severity === "critical").length;

  const sevCtx = document.getElementById("severity-chart")?.getContext("2d");
  if (sevCtx) {
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sevCtx, {
      type: "doughnut",
      data: {
        labels: ["Info (Safe)", "Warning", "Critical"],
        datasets: [{
          data: [infoCount, warnCount, critCount],
          backgroundColor: ["#3b82f6", "#eab308", "#ef4444"],
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: getTextColor() } },
        },
      },
    });
  }

  // Count by event type
  const typeCounts = {};
  for (const e of events) {
    typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1;
  }
  const topTypes = Object.entries(typeCounts).slice(0, 6);

  const actCtx = document.getElementById("activity-chart")?.getContext("2d");
  if (actCtx) {
    if (activityChart) activityChart.destroy();
    activityChart = new Chart(actCtx, {
      type: "bar",
      data: {
        labels: topTypes.map(([k]) => k.replace(".", "\n")),
        datasets: [{
          label: "Events",
          data: topTypes.map(([, v]) => v),
          backgroundColor: "#6366f1",
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: { ticks: { color: getTextColor() } },
          y: { beginAtZero: true, ticks: { precision: 0, color: getTextColor() } },
        },
      },
    });
  }
}

function getTextColor() {
  return document.documentElement.dataset.theme === "dark" ? "#94a3b8" : "#475569";
}

function updateChartsTheme(isDark) {
  if (severityChart) {
    severityChart.options.plugins.legend.labels.color = getTextColor();
    severityChart.update();
  }
  if (activityChart) {
    activityChart.options.scales.x.ticks.color = getTextColor();
    activityChart.options.scales.y.ticks.color = getTextColor();
    activityChart.update();
  }
}

function checkLiveAlerts(events) {
  const criticalEvent = events.find(
    (e) => e.severity === "critical" && !dismissedAlertIds.has(e.id)
  );

  if (criticalEvent) {
    alertBanner.hidden = false;
    alertSummary.textContent = `${criticalEvent.event_type}: ${criticalEvent.details?.reason || criticalEvent.details?.summary || criticalEvent.details?.threat || "Critical security condition detected"}`;
    alertDetail.textContent = `Device: ${criticalEvent.device_id} (${formatTime(criticalEvent.time)})`;
  }
}

function renderEvents(events) {
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

  checkLiveAlerts(events);
  renderCharts(events);

  if (!events.length) {
    eventsBody.innerHTML = '<tr><td colspan="6" class="empty-state">No device activity yet. Connect a USB device while the monitor is running.</td></tr>';
    return;
  }

  const rows = [];
  events.forEach((event, index) => {
    const row = document.createElement("tr");
    row.className = `event-row sev-${event.severity}`;

    const timeTd = document.createElement("td");
    timeTd.textContent = formatTime(event.time);

    const actTd = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.className = "activity-toggle";
    toggle.type = "button";
    toggle.dataset.detailToggle = "";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", `event-details-${index}`);
    toggle.innerHTML = `<strong>${escapeHtml(event.event_type)}</strong><span class="activity-chevron" aria-hidden="true"></span>`;
    actTd.appendChild(toggle);

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

    const srcTd = document.createElement("td");
    srcTd.textContent = event.source;

    const sevTd = document.createElement("td");
    const sevSpan = document.createElement("span");
    sevSpan.className = `severity ${event.severity}`;
    sevSpan.textContent = event.severity;
    sevTd.appendChild(sevSpan);

    const actActionTd = document.createElement("td");
    if (event.details?.serial_number || event.details?.vendor_id) {
      const wlBtn = document.createElement("button");
      wlBtn.className = "btn btn-sm btn-outline";
      wlBtn.textContent = "+ Whitelist";
      wlBtn.title = "Add device to authorized whitelist";
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

    // Details row
    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.id = `event-details-${index}`;
    detailsRow.hidden = true;

    const detailsTd = document.createElement("td");
    detailsTd.colSpan = 6;
    const panel = document.createElement("div");
    panel.className = "details-panel";

    if (event.event_type === "scan.completed") {
      const caveat = document.createElement("p");
      caveat.className = "scan-caveat text-muted small";
      caveat.textContent = "These findings include filename-based indicators and signature matches.";
      panel.appendChild(caveat);
    }

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
  const details = document.getElementById(toggle.getAttribute("aria-controls"));
  const isExpanded = toggle.getAttribute("aria-expanded") === "true";
  toggle.setAttribute("aria-expanded", String(!isExpanded));
  details.hidden = isExpanded;
});

async function loadEvents(showStatus = true) {
  if (eventsLoadInProgress) return;
  eventsLoadInProgress = true;
  try {
    const response = await fetch("/api/v1/events?limit=100");
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const events = await response.json();
    renderEvents(events);
    apiStatus.textContent = "API connected";
    connection.classList.remove("is-unavailable");
    connection.classList.add("is-connected");
    if (showStatus) {
      showMessage(`Loaded ${events.length} event${events.length === 1 ? "" : "s"}.`);
    }
  } catch (error) {
    apiStatus.textContent = "API unavailable";
    connection.classList.remove("is-connected");
    connection.classList.add("is-unavailable");
    showMessage(error.message, true);
  } finally {
    eventsLoadInProgress = false;
  }
}

document.querySelector("#refresh-events").addEventListener("click", () => loadEvents(true));

// Initial bootstrap
loadPolicyStatus();
loadWhitelist();
loadEvents(false);

window.setInterval(() => {
  if (document.visibilityState === "visible") loadEvents(false);
}, 4000);
