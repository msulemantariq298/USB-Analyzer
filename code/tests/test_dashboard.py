from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_dashboard_is_served() -> None:
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert "USB Analyzer Dashboard" in response.text
    assert 'id="simulate-event"' not in response.text
    assert 'id="sim-safe-btn"' not in response.text
    assert 'id="section-diagnostics"' not in response.text
    assert "NUST" not in response.text
    assert "Montserrat" in response.text
    assert 'id="sidebar-toggle-btn"' in response.text
    assert 'id="sidebar-close-btn"' in response.text
    assert 'id="app-sidebar"' in response.text
    assert "status-pulse-dot" not in response.text
    assert "monitor-pulse-dot" not in response.text
    assert "linearGradient" not in response.text
    assert 'id="theme-toggle"' in response.text
    assert 'id="active-scans"' in response.text
    assert 'id="flagged-files"' in response.text
    assert 'id="wl-mode-connected-btn"' in response.text
    assert 'id="wl-mode-manual-btn"' in response.text
    assert 'id="wl-device-picker"' in response.text
    assert "kpi-strip" in response.text
    assert "custom-menu-panel" in response.text
    assert "<select" not in response.text
    assert 'id="audit-filter-menu-wrap"' in response.text
    assert 'id="settings-policy-menu-wrap"' in response.text
    assert 'id="scan-storage-btn"' in response.text
    assert 'id="view-file-analysis-btn"' in response.text
    assert 'id="file-analysis-table"' in response.text
    assert 'class="btn-secondary btn-danger-ghost btn-sm" id="clear-log-btn"' in response.text
    assert "custom-checkbox-box" in response.text
    assert "mitre-matrix-table" in response.text
    assert "mitre-item" not in response.text

    css = client.get("/static/styles.css")
    assert css.status_code == 200
    assert "Montserrat" in css.text
    assert "linear-gradient" not in css.text
    assert "radial-gradient" not in css.text
    assert "action-dot-" not in css.text
    assert "border-left: 3px solid var(--danger);" not in css.text
    assert "--sidebar-bg: #FFFFFF" in css.text
    assert "::-webkit-scrollbar" in css.text
    assert ".custom-menu-panel" in css.text
    assert ".custom-checkbox-box" in css.text
    assert ".seg-glider" in css.text

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "scan.started" in script.text
    assert "filename-based indicators" in script.text
    assert "createLinearGradient" not in script.text
    assert "/reports/events.csv" in script.text
    assert "toast_action" in script.text
    assert "syncSegmentedGlider" in script.text
    assert "classifyEventVerdict" in script.text
    assert "runSimulation" not in script.text
