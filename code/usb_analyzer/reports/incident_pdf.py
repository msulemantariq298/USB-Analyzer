from datetime import datetime, timezone
import io
from typing import Any

from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.policy.models import WhitelistEntry


class SimplePdfWriter:
    """Zero-dependency pure-Python PDF-1.4 document generator."""

    def __init__(self, page_width: float = 612.0, page_height: float = 792.0) -> None:
        self.width = page_width
        self.height = page_height
        self.pages: list[str] = []
        self._current_stream: list[str] = []

    def start_page(self) -> None:
        if self._current_stream:
            self.pages.append("\n".join(self._current_stream))
            self._current_stream = []

    def add_text(
        self,
        text: str,
        x: float,
        y: float,
        font: str = "F1",
        size: float = 10.0,
        r: float = 0.0,
        g: float = 0.0,
        b: float = 0.0,
    ) -> None:
        clean_text = (
            text.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .encode("latin-1", "replace")
            .decode("latin-1")
        )
        self._current_stream.append(
            f"BT\n/{font} {size:.1f} Tf\n{r:.2f} {g:.2f} {b:.2f} rg\n{x:.1f} {y:.1f} Td\n({clean_text}) Tj\nET"
        )

    def add_line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        r: float = 0.7,
        g: float = 0.7,
        b: float = 0.7,
        width: float = 1.0,
    ) -> None:
        self._current_stream.append(
            f"{width:.1f} w\n{r:.2f} {g:.2f} {b:.2f} RG\n{x1:.1f} {y1:.1f} m\n{x2:.1f} {y2:.1f} l\nS"
        )

    def add_rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill_r: float = 0.95,
        fill_g: float = 0.95,
        fill_b: float = 0.95,
    ) -> None:
        self._current_stream.append(
            f"{fill_r:.2f} {fill_g:.2f} {fill_b:.2f} rg\n{x:.1f} {y:.1f} {w:.1f} {h:.1f} re\nf"
        )

    def build(self) -> bytes:
        if self._current_stream:
            self.pages.append("\n".join(self._current_stream))
            self._current_stream = []

        total_pages = max(1, len(self.pages))
        out = io.BytesIO()

        # Header
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = [0]

        # 1: Catalog
        offsets.append(out.tell())
        out.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # 2: Pages Root
        page_obj_refs = " ".join(f"{i + 4} 0 R" for i in range(total_pages))
        offsets.append(out.tell())
        out.write(f"2 0 obj\n<< /Type /Pages /Kids [{page_obj_refs}] /Count {total_pages} >>\nendobj\n".encode())

        # 3: Fonts (Helvetica, Helvetica-Bold)
        offsets.append(out.tell())
        out.write(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
        font_bold_obj = 3 + total_pages + 1

        # Page Objects: 4 .. (4 + total_pages - 1)
        # Content Stream Objects: (4 + total_pages) ..
        page_start_id = 4
        content_start_id = page_start_id + total_pages

        for i in range(total_pages):
            p_id = page_start_id + i
            c_id = content_start_id + i
            offsets.append(out.tell())
            page_str = (
                f"{p_id} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R\n"
                f"/MediaBox [0 0 {self.width:.1f} {self.height:.1f}]\n"
                f"/Resources << /Font << /F1 3 0 R /F2 {font_bold_obj} 0 R >> >>\n"
                f"/Contents {c_id} 0 R >>\nendobj\n"
            )
            out.write(page_str.encode())

        # Content Streams
        for i, page_content in enumerate(self.pages):
            c_id = content_start_id + i
            content_bytes = page_content.encode("latin-1")
            offsets.append(out.tell())
            out.write(f"{c_id} 0 obj\n<< /Length {len(content_bytes)} >>\nstream\n".encode())
            out.write(content_bytes)
            out.write(b"\nendstream\nendobj\n")

        # Bold font obj
        offsets.append(out.tell())
        out.write(f"{font_bold_obj} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n".encode())

        # Cross reference table
        xref_offset = out.tell()
        out.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode())

        # Trailer
        out.write(
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
        )
        return out.getvalue()


def generate_incident_pdf(
    events: list[DeviceEvent],
    whitelist: list[WhitelistEntry],
    policy_mode: str = "enforce",
) -> bytes:
    """Generate professional PDF Incident & Forensic Audit Report."""
    pdf = SimplePdfWriter()

    # --- Page 1: Executive Summary & Critical Incident Alerts ---
    margin_x = 45.0
    y = 750.0

    # Header banner
    pdf.add_rect(margin_x, y - 10, 522.0, 42.0, fill_r=0.08, fill_g=0.12, fill_b=0.20)
    pdf.add_text("USB ANALYZER - SECURITY INCIDENT REPORT", margin_x + 15, y + 14, font="F2", size=14.0, r=1.0, g=1.0, b=1.0)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf.add_text(f"Generated: {now_str} | Mode: {policy_mode.upper()}", margin_x + 15, y + 2, font="F1", size=8.5, r=0.75, g=0.85, b=0.95)

    y -= 45.0

    # Stats cards
    total_events = len(events)
    critical_events = [e for e in events if e.severity.value == "critical"]
    warning_events = [e for e in events if e.severity.value == "warning"]
    blocked_count = sum(1 for e in events if e.event_type == "device.blocked")

    pdf.add_rect(margin_x, y - 35, 120.0, 32.0, fill_r=0.94, fill_g=0.96, fill_b=0.98)
    pdf.add_text(f"{total_events}", margin_x + 10, y - 18, font="F2", size=14.0, r=0.1, g=0.2, b=0.3)
    pdf.add_text("Total Events", margin_x + 10, y - 30, font="F1", size=8.0, r=0.4, g=0.5, b=0.6)

    pdf.add_rect(margin_x + 130, y - 35, 120.0, 32.0, fill_r=0.98, fill_g=0.92, fill_b=0.92)
    pdf.add_text(f"{len(critical_events)}", margin_x + 140, y - 18, font="F2", size=14.0, r=0.8, g=0.1, b=0.1)
    pdf.add_text("Critical Threats", margin_x + 140, y - 30, font="F1", size=8.0, r=0.5, g=0.2, b=0.2)

    pdf.add_rect(margin_x + 260, y - 35, 120.0, 32.0, fill_r=0.99, fill_g=0.96, fill_b=0.90)
    pdf.add_text(f"{len(warning_events)}", margin_x + 270, y - 18, font="F2", size=14.0, r=0.7, g=0.5, b=0.1)
    pdf.add_text("Warnings", margin_x + 270, y - 30, font="F1", size=8.0, r=0.5, g=0.4, b=0.2)

    pdf.add_rect(margin_x + 390, y - 35, 132.0, 32.0, fill_r=0.92, fill_g=0.95, fill_b=0.98)
    pdf.add_text(f"{blocked_count}", margin_x + 400, y - 18, font="F2", size=14.0, r=0.1, g=0.4, b=0.7)
    pdf.add_text("Devices Blocked", margin_x + 400, y - 30, font="F1", size=8.0, r=0.3, g=0.4, b=0.5)

    y -= 55.0

    # Section 1: Security Threats & Incident Log
    pdf.add_text("1. DETECTED SECURITY THREATS & INCIDENTS", margin_x, y, font="F2", size=11.0, r=0.1, g=0.2, b=0.3)
    pdf.add_line(margin_x, y - 4, margin_x + 522.0, y - 4, r=0.3, g=0.4, b=0.5, width=1.0)
    y -= 18.0

    threat_events = [e for e in events if e.severity.value in ("critical", "warning")]
    if not threat_events:
        pdf.add_text("No critical threats or policy violations recorded during this monitoring period.", margin_x + 10, y, font="F1", size=9.0, r=0.3, g=0.5, b=0.3)
        y -= 25.0
    else:
        for t_event in threat_events[:6]:
            bg_r, bg_g, bg_b = (0.99, 0.94, 0.94) if t_event.severity.value == "critical" else (0.99, 0.98, 0.93)
            pdf.add_rect(margin_x, y - 28, 522.0, 26.0, fill_r=bg_r, fill_g=bg_g, fill_b=bg_b)

            ev_time = t_event.time.strftime("%H:%M:%S UTC")
            pdf.add_text(f"[{t_event.severity.value.upper()}] {t_event.event_type}", margin_x + 8, y - 10, font="F2", size=9.0, r=0.8 if t_event.severity.value == "critical" else 0.6, g=0.1, b=0.1)
            pdf.add_text(f"Time: {ev_time} | Device: {t_event.device_id[:45]}", margin_x + 220, y - 10, font="F1", size=8.0, r=0.4, g=0.4, b=0.4)

            reason = str(t_event.details.get("reason") or t_event.details.get("summary") or t_event.details.get("threat") or "Suspicious activity detected")
            if len(reason) > 95:
                reason = reason[:92] + "..."
            pdf.add_text(reason, margin_x + 8, y - 22, font="F1", size=8.0, r=0.2, g=0.2, b=0.2)
            y -= 34.0

    y -= 10.0

    # Section 2: Active Device Whitelist
    pdf.add_text("2. AUTHORIZED DEVICE WHITELIST", margin_x, y, font="F2", size=11.0, r=0.1, g=0.2, b=0.3)
    pdf.add_line(margin_x, y - 4, margin_x + 522.0, y - 4, r=0.3, g=0.4, b=0.5, width=1.0)
    y -= 18.0

    if not whitelist:
        pdf.add_text("No devices currently registered on the whitelist (All unknown devices will be evaluated per policy).", margin_x + 10, y, font="F1", size=8.5, r=0.5, g=0.5, b=0.5)
        y -= 25.0
    else:
        for w in whitelist[:5]:
            pdf.add_text(f"* {w.name}", margin_x + 10, y, font="F2", size=8.5, r=0.1, g=0.2, b=0.3)
            id_parts = []
            if w.serial_number:
                id_parts.append(f"SN: {w.serial_number}")
            if w.vendor_id and w.product_id:
                id_parts.append(f"VID:PID: {w.vendor_id}:{w.product_id}")
            desc = " | ".join(id_parts) or "General Match"
            pdf.add_text(desc, margin_x + 180, y, font="F1", size=8.0, r=0.4, g=0.4, b=0.4)
            y -= 14.0

    y -= 15.0

    # Section 3: Recent Device Activity Audit Log
    pdf.add_text("3. RECENT ACTIVITY AUDIT TRAIL", margin_x, y, font="F2", size=11.0, r=0.1, g=0.2, b=0.3)
    pdf.add_line(margin_x, y - 4, margin_x + 522.0, y - 4, r=0.3, g=0.4, b=0.5, width=1.0)
    y -= 18.0

    pdf.add_rect(margin_x, y - 12, 522.0, 14.0, fill_r=0.90, fill_g=0.92, fill_b=0.95)
    pdf.add_text("TIME", margin_x + 5, y - 9, font="F2", size=7.5, r=0.2, g=0.2, b=0.3)
    pdf.add_text("EVENT TYPE", margin_x + 65, y - 9, font="F2", size=7.5, r=0.2, g=0.2, b=0.3)
    pdf.add_text("SEVERITY", margin_x + 175, y - 9, font="F2", size=7.5, r=0.2, g=0.2, b=0.3)
    pdf.add_text("DEVICE ID / SUMMARY", margin_x + 235, y - 9, font="F2", size=7.5, r=0.2, g=0.2, b=0.3)
    y -= 18.0

    for ev in events[:12]:
        if y < 45.0:
            break
        ev_time = ev.time.strftime("%H:%M:%S")
        pdf.add_text(ev_time, margin_x + 5, y, font="F1", size=7.5, r=0.3, g=0.3, b=0.3)
        pdf.add_text(ev.event_type[:24], margin_x + 65, y, font="F2", size=7.5, r=0.1, g=0.2, b=0.3)

        sev_r, sev_g, sev_b = (0.7, 0.1, 0.1) if ev.severity.value == "critical" else ((0.6, 0.4, 0.1) if ev.severity.value == "warning" else (0.2, 0.4, 0.6))
        pdf.add_text(ev.severity.value.upper(), margin_x + 175, y, font="F2", size=7.5, r=sev_r, g=sev_g, b=sev_b)

        desc = ev.device_id
        if "name" in ev.details and ev.details["name"]:
            desc += f" ({ev.details['name']})"
        if len(desc) > 65:
            desc = desc[:62] + "..."
        pdf.add_text(desc, margin_x + 235, y, font="F1", size=7.0, r=0.2, g=0.2, b=0.2)
        y -= 13.0

    # Footer
    pdf.add_line(margin_x, 30.0, margin_x + 522.0, 30.0, r=0.8, g=0.8, b=0.8, width=0.5)
    pdf.add_text("USB Analyzer - Automated Defense & Forensic Report", margin_x, 20.0, font="F1", size=7.5, r=0.5, g=0.5, b=0.5)
    pdf.add_text("Page 1 of 1", margin_x + 475.0, 20.0, font="F1", size=7.5, r=0.5, g=0.5, b=0.5)

    return pdf.build()

