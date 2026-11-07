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
const eventSearchInput = document.querySelector("#event-search");

const themeStorageKey = "usb-analyzer-theme";
let allEventsCache = [];
let eventsLoadInProgress = false;
let currentPolicyMode = "enforce";
let severityChart = null;
let activityChart = null;
let dismissedAlertIds = new Set();
let searchQuery = "";

// Theme handling
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
  return "dark"; // Default to dark for professional SOC styling
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
  if (!message) return;
  message.textContent = text;
  message.className = `toast-message ${isError ? "error" : "success"}`;
  message.hidden = false;
  setTimeout(() => {
    message.hidden = true;
  }, 4500);
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
    alertBanner.hidden = true;
  });
}

// BadUSB Simulation
if (simulateBadusbBtn) {
  simulateBadusbBtn.addEventListener("click", async () => {
    simulateBadusbBtn.disabled = true;
    simulateBadusbBtn.querySelector("span").textContent = "Simulating...";
    try {
      const res = await fetch("/api/v1/simulate/badusb", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: "USB\\VID_16C0&PID_05DF\\DIGISPARK_DEMO",
          device_name: "Digispark BadUSB (Live Simulation)",
          char_count: 35,
          delay_ms: 3.0,
        }),
      });
      const data = await res.json();
      showMessage(data.summary, false);
      await loadEvents(false);
    } catch (err) {
      showMessage(`Simulation failed: ${err.message}`, true);
    } finally {
      simulateBadusbBtn.disabled = false;
      simulateBadusbBtn.querySelector("span").textContent = "Simulate BadUSB";
    }
  });
}

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

// Policy Mode Toggle
if (policyToggleBtn) {
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
      showMessage(`Security Policy Mode: ${currentPolicyMode.toUpperCase()}`);
    } catch (err) {
      showMessage(`Policy mode update failed: ${err.message}`, true);
    }
  });
}

function updatePolicyUI() {
  if (!policyModeText || !policyToggleBtn) return;
  if (currentPolicyMode === "enforce") {
    policyModeText.textContent = "ENFORCE";
    policyToggleBtn.className = "policy-toggle-btn badge-enforce";
    policyToggleBtn.title = "Current: ENFORCE (Active Blocking). Click to switch to AUDIT ONLY.";
  } else {
    policyModeText.textContent = "AUDIT ONLY";
    policyToggleBtn.className = "policy-toggle-btn badge-audit";
    policyToggleBtn.title = "Current: AUDIT ONLY (Passive Logging). Click to switch to ENFORCE.";
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

// Chart.js High-Contrast SOC Theme
function renderCharts(events) {
  if (typeof Chart === "undefined") return;

  const isDark = document.documentElement.dataset.theme === "dark";
  const textColor = isDark ? "#94a3b8" : "#475569";
  const gridColor = isDark ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 0, 0, 0.05)";

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
          backgroundColor: ["#38bdf8", "#fbbf24", "#f87171"],
          borderColor: isDark ? "#111827" : "#ffffff",
          borderWidth: 3,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: textColor, boxWidth: 12, padding: 14, font: { family: "var(--font-sans)", size: 11 } },
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
          backgroundColor: "#38bdf8",
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
          x: {
            grid: { display: false },
            ticks: { color: textColor, font: { family: "var(--font-mono)", size: 10 } },
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

function updateChartsTheme(isDark) {
  if (severityChart) {
    severityChart.data.datasets[0].borderColor = isDark ? "#111827" : "#ffffff";
    severityChart.options.plugins.legend.labels.color = isDark ? "#94a3b8" : "#475569";
    severityChart.update();
  }
  if (activityChart) {
    const textColor = isDark ? "#94a3b8" : "#475569";
    const gridColor = isDark ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 0, 0, 0.05)";
    activityChart.options.scales.x.ticks.color = textColor;
    activityChart.options.scales.y.ticks.color = textColor;
    activityChart.options.scales.y.grid.color = gridColor;
    activityChart.update();
  }
}

function checkLiveAlerts(events) {
  if (!alertBanner) return;
  const criticalEvent = events.find(
    (e) => e.severity === "critical" && !dismissedAlertIds.has(e.id)
  );

  if (criticalEvent) {
    alertBanner.hidden = false;
    alertSummary.textContent = `${criticalEvent.event_type.toUpperCase()}: ${criticalEvent.details?.reason || criticalEvent.details?.summary || criticalEvent.details?.threat || "High-risk hardware event intercepted"}`;
    alertDetail.textContent = `Target: ${criticalEvent.device_id} • Telemetry recorded at ${formatTime(criticalEvent.time)}`;
  }
}

function renderEvents(events) {
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
  renderCharts(events);
  filterAndRenderEvents();
}

function displayEventRows(events) {
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
    const actTd = document.createElement("td");
    const toggle = document.createElement("button");
    toggle.className = "activity-toggle";
    toggle.type = "button";
    toggle.dataset.detailToggle = "";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-controls", `event-details-${index}`);
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
    detailsRow.id = `event-details-${index}`;
    detailsRow.hidden = true;

    const detailsTd = document.createElement("td");
    detailsTd.colSpan = 6;
    const panel = document.createElement("div");
    panel.className = "details-panel";

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
  const details = document.getElementById(toggle.getAttribute("aria-controls"));
  const isExpanded = toggle.getAttribute("aria-expanded") === "true";
  toggle.setAttribute("aria-expanded", String(!isExpanded));
  details.hidden = isExpanded;
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

// Initial bootstrap
loadPolicyStatus();
loadWhitelist();
loadEvents(false);

window.setInterval(() => {
  if (document.visibilityState === "visible") loadEvents(false);
}, 3500);
