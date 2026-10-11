const eventsBody = document.querySelector("#events-body");
const message = document.querySelector("#message");

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

function renderEvents(events) {
  document.querySelector("#total-events").textContent = events.length;
  document.querySelector("#warning-events").textContent =
    events.filter((event) => event.severity === "warning").length;
  document.querySelector("#critical-events").textContent =
    events.filter((event) => event.severity === "critical").length;
  document.querySelector("#last-update").textContent =
    events.length ? formatTime(events[0].time) : "—";

  if (!events.length) {
    eventsBody.innerHTML = '<tr><td colspan="6" class="empty-state">No events recorded yet.</td></tr>';
    return;
  }

  eventsBody.innerHTML = events.map((event) => `
    <tr>
      <td>${formatTime(event.time)}</td>
      <td><strong>${event.event_type}</strong></td>
      <td><code>${event.device_id}</code></td>
      <td>${event.source}</td>
      <td><span class="severity ${event.severity}">${event.severity}</span></td>
      <td><code>${JSON.stringify(event.details)}</code></td>
    </tr>
  `).join("");
}

async function loadEvents() {
  try {
    const response = await fetch("/api/v1/events?limit=100");
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const events = await response.json();
    renderEvents(events);
    document.querySelector("#api-status").textContent = "API connected";
    showMessage(`Loaded ${events.length} event${events.length === 1 ? "" : "s"}.`);
  } catch (error) {
    document.querySelector("#api-status").textContent = "API unavailable";
    showMessage(error.message, true);
  }
}

async function simulateEvent() {
  const response = await fetch("/api/v1/events", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      device_id: "demo:usb:001",
      source: "week-1-demo",
      severity: "warning",
      event_type: "device.connected",
      details: {
        vendor_id: "1234",
        product_id: "5678",
        manufacturer: "Demo device",
        note: "Replace with a real Device Monitor event",
      },
    }),
  });
  if (!response.ok) throw new Error(`Could not create event (${response.status})`);
  await loadEvents();
}

document.querySelector("#refresh-events").addEventListener("click", loadEvents);
document.querySelector("#simulate-event").addEventListener("click", async () => {
  try {
    await simulateEvent();
    showMessage("Demo USB event added.");
  } catch (error) {
    showMessage(error.message, true);
  }
});

loadEvents();
