const eventsBody = document.querySelector("#events-body");
const message = document.querySelector("#message");
const apiStatus = document.querySelector("#api-status");
const connection = document.querySelector(".connection");
const themeToggle = document.querySelector("#theme-toggle");
const themeStorageKey = "usb-analyzer-theme";
let eventsLoadInProgress = false;

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
}

function getInitialTheme() {
  try {
    const savedTheme = localStorage.getItem(themeStorageKey);
    if (savedTheme === "dark" || savedTheme === "light") return savedTheme;
  } catch (error) {
    showMessage(`Theme preference could not be loaded: ${error.message}`, true);
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
    showMessage(`Theme changed for this session but could not be saved: ${error.message}`, true);
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

function latestScanStates(events) {
  const latestByVolume = new Map();
  for (const event of events) {
    if (!["scan.started", "scan.completed", "scan.failed"].includes(event.event_type)) {
      continue;
    }
    const volume = event.details?.volume_path ?? "unknown";
    const key = `${event.device_id}|${volume}`;
    if (!latestByVolume.has(key)) latestByVolume.set(key, event);
  }
  return [...latestByVolume.values()];
}

function renderEvents(events) {
  document.querySelector("#total-events").textContent = events.length;
  document.querySelector("#warning-events").textContent =
    events.filter((event) => event.severity === "warning").length;
  document.querySelector("#critical-events").textContent =
    events.filter((event) => event.severity === "critical").length;
  document.querySelector("#last-update").textContent =
    events.length ? formatTime(events[0].time) : "—";
  const scanStates = latestScanStates(events);
  document.querySelector("#active-scans").textContent =
    scanStates.filter((event) => event.event_type === "scan.started").length;
  document.querySelector("#flagged-files").textContent = scanStates
    .filter((event) => event.event_type === "scan.completed")
    .reduce((total, event) => {
      const count = Number(event.details?.flagged_count ?? 0);
      return total + (Number.isFinite(count) && count > 0 ? count : 0);
    }, 0);

  if (!events.length) {
    eventsBody.innerHTML = '<tr><td colspan="5" class="empty-state">No device activity yet. Connect a USB device while the monitor is running.</td></tr>';
    return;
  }

  const rows = events.flatMap((event, index) => {
    const row = document.createElement("tr");
    row.className = "event-row";
    const cells = [
      { label: "Time", value: formatTime(event.time) },
      { label: "Activity" },
      { label: "Device ID", value: event.device_id, tag: "code" },
      { label: "Source", value: event.source },
    ];

    for (const { label, value, tag } of cells) {
      const cell = document.createElement("td");
      if (label === "Activity") {
        const toggle = document.createElement("button");
        toggle.className = "activity-toggle";
        toggle.type = "button";
        toggle.dataset.detailToggle = "";
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-controls", `event-details-${index}`);
        toggle.setAttribute("aria-label", `Show details for ${event.event_type}`);
        const activity = document.createElement("strong");
        activity.textContent = event.event_type;
        const chevron = document.createElement("span");
        chevron.className = "activity-chevron";
        chevron.setAttribute("aria-hidden", "true");
        toggle.append(activity, chevron);
        cell.append(toggle);
      } else if (tag) {
        const content = document.createElement(tag);
        content.textContent = value;
        cell.append(content);
      } else {
        cell.textContent = value;
      }
      cell.dataset.label = label;
      row.append(cell);
    }

    const severityCell = document.createElement("td");
    severityCell.dataset.label = "Severity";
    const severity = document.createElement("span");
    const severityValue = ["info", "warning", "critical"].includes(event.severity)
      ? event.severity
      : "info";
    severity.className = `severity ${severityValue}`;
    severity.textContent = event.severity;
    severityCell.append(severity);
    row.append(severityCell);

    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.id = `event-details-${index}`;
    detailsRow.hidden = true;
    const detailsCell = document.createElement("td");
    detailsCell.colSpan = 5;
    const detailsPanel = document.createElement("div");
    detailsPanel.className = "details-panel";
    const detailsHeading = document.createElement("h3");
    detailsHeading.textContent = "Event details";
    const detailsList = document.createElement("dl");
    detailsList.className = "details-list";
    const entries = event.details && typeof event.details === "object" && !Array.isArray(event.details)
      ? Object.entries(event.details)
      : [["Details", event.details]];

    for (const [key, value] of entries) {
      const field = document.createElement("div");
      field.className = key === "flagged" || key === "errors"
        ? "details-field details-field-wide"
        : "details-field";
      const term = document.createElement("dt");
      term.textContent = key.replaceAll("_", " ");
      const description = document.createElement("dd");
      if (key === "flagged" && Array.isArray(value)) {
        if (value.length === 0) {
          description.textContent = "No filename indicators were found.";
        } else {
          const list = document.createElement("ul");
          list.className = "finding-list";
          for (const finding of value) {
            const findingDetails = finding && typeof finding === "object" && !Array.isArray(finding)
              ? finding
              : {};
            const item = document.createElement("li");
            item.className = "finding-entry";
            const path = document.createElement("strong");
            path.className = "finding-path";
            path.textContent = findingDetails.path ?? "Unknown path";
            const metadata = document.createElement("span");
            metadata.className = "finding-meta";
            metadata.textContent = `${Number(findingDetails.size ?? 0).toLocaleString()} bytes · SHA-256 ${findingDetails.sha256 ?? "unavailable"}`;
            const flags = document.createElement("div");
            flags.className = "finding-flags";
            for (const flag of Array.isArray(findingDetails.flags) ? findingDetails.flags : []) {
              const label = document.createElement("span");
              label.className = "flag-label";
              label.textContent = String(flag).replaceAll("_", " ");
              flags.append(label);
            }
            item.append(path, metadata, flags);
            list.append(item);
          }
          description.append(list);
        }
      } else if (key === "errors" && Array.isArray(value)) {
        if (value.length === 0) {
          description.textContent = "No file access errors.";
        } else {
          const list = document.createElement("ul");
          list.className = "scan-errors";
          for (const scanError of value) {
            const errorDetails = scanError && typeof scanError === "object" && !Array.isArray(scanError)
              ? scanError
              : {};
            const item = document.createElement("li");
            item.textContent = `${errorDetails.path ?? "Unknown path"}: ${errorDetails.error ?? "Unknown error"}`;
            list.append(item);
          }
          description.append(list);
        }
      } else {
        description.textContent = value !== null && typeof value === "object"
          ? JSON.stringify(value)
          : String(value ?? "—");
      }
      field.append(term, description);
      detailsList.append(field);
    }

    if (!entries.length) {
      const field = document.createElement("div");
      field.className = "details-field";
      const term = document.createElement("dt");
      term.textContent = "Details";
      const emptyDetails = document.createElement("dd");
      emptyDetails.textContent = "No additional details were recorded.";
      field.append(term, emptyDetails);
      detailsList.append(field);
    }

    if (event.event_type === "scan.completed" && Number(event.details?.flagged_count ?? 0) > 0) {
      const caveat = document.createElement("p");
      caveat.className = "scan-caveat";
      caveat.textContent = "These are filename-based indicators only, not confirmed malware detections.";
      detailsPanel.append(detailsHeading, caveat, detailsList);
    } else {
      detailsPanel.append(detailsHeading, detailsList);
    }
    detailsCell.append(detailsPanel);
    detailsRow.append(detailsCell);
    return [row, detailsRow];
  });
  eventsBody.replaceChildren(...rows);
}

eventsBody.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-detail-toggle]");
  if (!toggle) return;

  const details = document.getElementById(toggle.getAttribute("aria-controls"));
  const isExpanded = toggle.getAttribute("aria-expanded") === "true";
  toggle.setAttribute("aria-expanded", String(!isExpanded));
  toggle.setAttribute("aria-label", `${isExpanded ? "Show" : "Hide"} details for ${toggle.querySelector("strong").textContent}`);
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

document.querySelector("#refresh-events").addEventListener("click", loadEvents);

loadEvents();
window.setInterval(() => {
  if (document.visibilityState === "visible") loadEvents(false);
}, 5000);
