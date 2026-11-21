"""Zero-dependency pure-Python PDF-1.4 forensic report matching dashboard design language."""

from dataclasses import dataclass
from datetime import datetime, timezone
import io
import math
from typing import Any, Callable

from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.policy.models import WhitelistEntry
from usb_analyzer.reports.common import (
    classify_event_verdict,
    collect_file_analyses,
    extract_device_name,
    summarize_telemetry,
)

# Color tokens aligned verbatim with static/styles.css Light Theme
RGB = tuple[float, float, float]

C_BG_APP: RGB = (0.961, 0.969, 0.980)       # #F5F7FA
C_SURFACE: RGB = (1.000, 1.000, 1.000)      # #FFFFFF
C_SUBTLE: RGB = (0.973, 0.980, 0.988)       # #F8FAFC
C_HOVER: RGB = (0.945, 0.961, 0.976)        # #F1F5F9
C_BORDER: RGB = (0.886, 0.910, 0.941)       # #E2E8F0
C_BORDER_SUB: RGB = (0.933, 0.949, 0.965)   # #EEF2F6
C_BORDER_STR: RGB = (0.796, 0.835, 0.882)   # #CBD5E1

C_BLUE: RGB = (0.114, 0.306, 0.847)         # #1D4ED8
C_BLUE_TINT: RGB = (0.937, 0.965, 1.000)    # #EFF6FF
C_BLUE_BORDER: RGB = (0.749, 0.859, 0.996)  # #BFDBFE

C_TEXT_MAIN: RGB = (0.059, 0.090, 0.165)    # #0F172A
C_TEXT_BODY: RGB = (0.200, 0.255, 0.333)    # #334155
C_TEXT_MUTED: RGB = (0.392, 0.455, 0.545)   # #64748B
C_TEXT_DIM: RGB = (0.580, 0.639, 0.722)     # #94A3B8

C_SAFE: RGB = (0.020, 0.588, 0.412)         # #059669
C_SAFE_BG: RGB = (0.925, 0.992, 0.961)      # #ECFDF5
C_SAFE_BORDER: RGB = (0.655, 0.953, 0.816)  # #A7F3D0
C_SAFE_TEXT: RGB = (0.024, 0.373, 0.275)    # #065F46

C_WARN: RGB = (0.851, 0.467, 0.024)         # #D97706
C_WARN_BG: RGB = (1.000, 0.984, 0.922)      # #FFFBEB
C_WARN_BORDER: RGB = (0.992, 0.902, 0.541)  # #FDE68A
C_WARN_TEXT: RGB = (0.573, 0.251, 0.055)    # #92400E

C_DANGER: RGB = (0.863, 0.149, 0.149)       # #DC2626
C_DANGER_BG: RGB = (0.996, 0.949, 0.949)    # #FEF2F2
C_DANGER_BORDER: RGB = (0.996, 0.792, 0.792)# #FECACA
C_DANGER_TEXT: RGB = (0.600, 0.106, 0.106)  # #991B1B

BADGE_STYLES: dict[str, tuple[RGB, RGB, RGB]] = {
    "safe": (C_SAFE_BG, C_SAFE_BORDER, C_SAFE_TEXT),
    "warning": (C_WARN_BG, C_WARN_BORDER, C_WARN_TEXT),
    "danger": (C_DANGER_BG, C_DANGER_BORDER, C_DANGER_TEXT),
    "critical": (C_DANGER_BG, C_DANGER_BORDER, C_DANGER_TEXT),
    "blue": (C_BLUE_TINT, C_BLUE_BORDER, C_BLUE),
    "neutral": (C_SUBTLE, C_BORDER, C_TEXT_BODY),
}

_NARROW_CHARS = set("iIljtf!|.,:;'\"`()[] ")
_WIDE_CHARS = set("MWmw@#%&QGHO")


def _pdf_escape(text: str) -> str:
    normalized = (
        text.replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("\u2022", "*")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2026", "...")
        .replace("\u00a0", " ")
    )
    return (
        normalized.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def estimate_text_width(text: str, font: str = "F1", size: float = 10.0) -> float:
    """Estimate PDF string width in points for Base14 Helvetica / Courier fonts."""
    if not text:
        return 0.0
    if font == "F3":
        return len(text) * size * 0.60
    bold_factor = 1.05 if font == "F2" else 1.0
    total = 0.0
    for ch in text:
        if ch in _NARROW_CHARS:
            w = 0.29
        elif ch in _WIDE_CHARS:
            w = 0.78
        elif ch.isupper():
            w = 0.65
        elif ch.isdigit():
            w = 0.55
        else:
            w = 0.51
        total += w * size * bold_factor
    return total


def wrap_text(text: str, max_width: float, font: str = "F1", size: float = 8.0, max_lines: int = 3) -> list[str]:
    """Wrap text smoothly within max_width points, breaking oversized tokens cleanly."""
    clean = " ".join(str(text or "").split())
    if not clean:
        return [""]
    lines: list[str] = []
    words = clean.split(" ")
    current = ""

    def _push_line(line: str) -> None:
        if len(lines) < max_lines:
            lines.append(line)

    for word in words:
        candidate = word if not current else f"{current} {word}"
        if estimate_text_width(candidate, font, size) <= max_width:
            current = candidate
            continue

        if current:
            _push_line(current)
            current = ""
            if len(lines) >= max_lines:
                break

        if estimate_text_width(word, font, size) <= max_width:
            current = word
        else:
            chunk = ""
            for ch in word:
                if estimate_text_width(chunk + ch, font, size) <= max_width:
                    chunk += ch
                else:
                    if chunk:
                        _push_line(chunk)
                    chunk = ch
                    if len(lines) >= max_lines:
                        chunk = ""
                        break
            current = chunk

    if current and len(lines) < max_lines:
        _push_line(current)

    if len(lines) == max_lines:
        joined_orig = clean
        joined_out = " ".join(lines)
        if len(joined_out) + 2 < len(joined_orig):
            last = lines[-1]
            while last and estimate_text_width(last + "...", font, size) > max_width:
                last = last[:-1]
            lines[-1] = f"{last}..."

    return lines or [""]


class SimplePdfWriter:
    """Zero-dependency pure-Python PDF-1.4 document generator."""

    def __init__(self, page_width: float = 612.0, page_height: float = 792.0) -> None:
        self.width = page_width
        self.height = page_height
        self.pages: list[str] = []
        self._current_stream: list[str] = []
        self._page_hook: Callable[["SimplePdfWriter", int, int], None] | None = None

    def set_page_footer_hook(self, hook: Callable[["SimplePdfWriter", int, int], None]) -> None:
        """Register callback invoked per page inside build() with (writer, page_no, total_pages)."""
        self._page_hook = hook

    def start_page(self, background_rgb: RGB | None = None) -> None:
        if self._current_stream:
            self.pages.append("\n".join(self._current_stream))
            self._current_stream = []
        if background_rgb is not None:
            self.add_rect(0.0, 0.0, self.width, self.height, fill_rgb=background_rgb)

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
        rgb: RGB | None = None,
        align: str = "left",
    ) -> None:
        if rgb is not None:
            r, g, b = rgb
        draw_x = x
        if align == "right":
            draw_x = x - estimate_text_width(text, font, size)
        elif align == "center":
            draw_x = x - (estimate_text_width(text, font, size) / 2.0)
        clean_text = _pdf_escape(text)
        self._current_stream.append(
            f"BT\n/{font} {size:.1f} Tf\n{r:.3f} {g:.3f} {b:.3f} rg\n{draw_x:.2f} {y:.2f} Td\n({clean_text}) Tj\nET"
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
        rgb: RGB | None = None,
    ) -> None:
        if rgb is not None:
            r, g, b = rgb
        self._current_stream.append(
            f"{width:.2f} w\n{r:.3f} {g:.3f} {b:.3f} RG\n{x1:.2f} {y1:.2f} m\n{x2:.2f} {y2:.2f} l\nS"
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
        fill_rgb: RGB | None = None,
        stroke_rgb: RGB | None = None,
        stroke_width: float = 0.75,
        radius: float = 0.0,
    ) -> None:
        # Backwards compatibility: if neither fill_rgb nor stroke_rgb provided, use fill_r/g/b fill
        use_fill = fill_rgb is not None or stroke_rgb is None
        fr, fg, fb = fill_rgb if fill_rgb is not None else (fill_r, fill_g, fill_b)
        do_fill = use_fill and (fill_rgb is not None or stroke_rgb is None)
        do_stroke = stroke_rgb is not None

        if not do_fill and not do_stroke:
            return

        cmds: list[str] = []
        if do_fill:
            cmds.append(f"{fr:.3f} {fg:.3f} {fb:.3f} rg")
        if do_stroke:
            sr, sg, sb = stroke_rgb  # type: ignore[misc]
            cmds.append(f"{stroke_width:.2f} w\n{sr:.3f} {sg:.3f} {sb:.3f} RG")

        r = min(radius, abs(w) / 2.0, abs(h) / 2.0)
        if r <= 0.1:
            cmds.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        else:
            k = 0.55228 * r
            cmds.extend([
                f"{x + w - r:.2f} {y:.2f} m",
                f"{x + w - r + k:.2f} {y:.2f} {x + w:.2f} {y + r - k:.2f} {x + w:.2f} {y + r:.2f} c",
                f"{x + w:.2f} {y + h - r:.2f} l",
                f"{x + w:.2f} {y + h - r + k:.2f} {x + w - r + k:.2f} {y + h:.2f} {x + w - r:.2f} {y + h:.2f} c",
                f"{x + r:.2f} {y + h:.2f} l",
                f"{x + r - k:.2f} {y + h:.2f} {x:.2f} {y + h - r + k:.2f} {x:.2f} {y + h - r:.2f} c",
                f"{x:.2f} {y + r:.2f} l",
                f"{x:.2f} {y + r - k:.2f} {x + r - k:.2f} {y:.2f} {x + r:.2f} {y:.2f} c",
                "h",
            ])

        op = "B" if (do_fill and do_stroke) else ("f" if do_fill else "S")
        cmds.append(op)
        self._current_stream.append("\n".join(cmds))

    def add_badge(
        self,
        text: str,
        x: float,
        y: float,
        *,
        style: str = "neutral",
        font: str = "F2",
        size: float = 6.8,
        height: float = 13.5,
        min_width: float = 34.0,
        align_right_x: float | None = None,
    ) -> tuple[float, float]:
        """Draw bordered semantic badge pill matching dashboard badges. Returns (x_left, x_right)."""
        fill_c, border_c, text_c = BADGE_STYLES.get(style, BADGE_STYLES["neutral"])
        pill_w = max(min_width, estimate_text_width(text, font, size) + 12.0)
        draw_x = (align_right_x - pill_w) if align_right_x is not None else x
        self.add_rect(draw_x, y, pill_w, height, fill_rgb=fill_c, stroke_rgb=border_c, stroke_width=0.65, radius=2.2)
        baseline = y + (height - 0.72 * size) / 2.0
        self.add_text(text, draw_x + pill_w / 2.0, baseline, font=font, size=size, rgb=text_c, align="center")
        return draw_x, draw_x + pill_w

    def add_progress_bar(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fraction: float,
        fill_rgb: RGB,
    ) -> None:
        """Draw rounded track and colored indicator bar matching UI entropy/risk bars."""
        self.add_rect(x, y, w, h, fill_rgb=C_BORDER, radius=h / 2.0)
        clamped = max(0.0, min(1.0, fraction))
        fill_w = max(h if clamped > 0 else 0.0, w * clamped)
        if fill_w > 0.2:
            self.add_rect(x, y, fill_w, h, fill_rgb=fill_rgb, radius=h / 2.0)

    def add_shield_logo(self, x: float, y: float, size: float = 28.0) -> None:
        """Draw `#1D4ED8` rounded square mark with crisp vector shield matching `.brand-icon-box`."""
        self.add_rect(x, y, size, size, fill_rgb=C_BLUE, radius=4.5)
        cx = x + size / 2.0
        top = y + size * 0.78
        mid = y + size * 0.56
        bot = y + size * 0.20
        half_w = size * 0.27
        cmds = [
            f"1.6 w\n1.000 1.000 1.000 RG\n1 J\n1 j",
            f"{cx:.2f} {bot:.2f} m",
            f"{cx - half_w * 0.85:.2f} {bot + size * 0.14:.2f} {cx - half_w:.2f} {mid - size * 0.08:.2f} {cx - half_w:.2f} {top - size * 0.07:.2f} c",
            f"{cx:.2f} {top:.2f} l",
            f"{cx + half_w:.2f} {top - size * 0.07:.2f} l",
            f"{cx + half_w:.2f} {mid - size * 0.08:.2f} {cx + half_w * 0.85:.2f} {bot + size * 0.14:.2f} {cx:.2f} {bot:.2f} c",
            "h\nS",
        ]
        self._current_stream.append("\n".join(cmds))

    def add_donut_chart(
        self,
        cx: float,
        cy: float,
        outer_r: float,
        inner_r: float,
        segments: list[tuple[float, RGB]],
        center_text: str,
    ) -> None:
        """Render vector donut chart ring + centered percentage metric."""
        positive = [(val, rgb) for val, rgb in segments if val > 0]
        total = sum(val for val, _ in positive)
        if total <= 0:
            positive = [(1.0, C_BORDER)]
            total = 1.0

        angle = math.pi / 2.0  # start at 12 o'clock, sweep clockwise
        for val, rgb in positive:
            sweep = -2.0 * math.pi * (val / total)
            steps = max(8, int(abs(sweep) / 0.08))
            a_pts = [angle + sweep * (i / steps) for i in range(steps + 1)]
            cmds = [f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg"]
            ox0 = cx + outer_r * math.cos(a_pts[0])
            oy0 = cy + outer_r * math.sin(a_pts[0])
            cmds.append(f"{ox0:.2f} {oy0:.2f} m")
            for a in a_pts[1:]:
                cmds.append(f"{cx + outer_r * math.cos(a):.2f} {cy + outer_r * math.sin(a):.2f} l")
            for a in reversed(a_pts):
                cmds.append(f"{cx + inner_r * math.cos(a):.2f} {cy + inner_r * math.sin(a):.2f} l")
            cmds.append("h\nf")
            self._current_stream.append("\n".join(cmds))
            angle += sweep

        # Crisp white separator stroke at slice seams only when multiple slices exist
        if len(positive) > 1:
            sep_angle = math.pi / 2.0
            for val, _ in positive:
                self.add_line(
                    cx + inner_r * math.cos(sep_angle),
                    cy + inner_r * math.sin(sep_angle),
                    cx + outer_r * math.cos(sep_angle),
                    cy + outer_r * math.sin(sep_angle),
                    rgb=C_SURFACE,
                    width=1.0,
                )
                sep_angle += -2.0 * math.pi * (val / total)

        self.add_text(center_text, cx, cy - 4.0, font="F2", size=11.0, rgb=C_TEXT_MAIN, align="center")

    def add_activity_chart(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        labels: list[str],
        counts: list[int],
    ) -> None:
        """Render minimalist vector timeline line & points matching dashboard activity chart."""
        pad_l = 18.0
        pad_b = 14.0
        pad_r = 8.0
        pad_t = 6.0
        plot_x = x + pad_l
        plot_y = y + pad_b
        plot_w = max(40.0, w - pad_l - pad_r)
        plot_h = max(24.0, h - pad_b - pad_t)
        max_val = max(max(counts, default=0), 4)
        # Round axis cap neatly
        step_val = max(1, math.ceil(max_val / 2.0))
        axis_top = step_val * 2

        for idx in range(3):
            gy = plot_y + plot_h * (idx / 2.0)
            self.add_line(plot_x, gy, plot_x + plot_w, gy, rgb=C_BORDER_SUB, width=0.6)
            tick_v = step_val * idx
            self.add_text(str(tick_v), plot_x - 4.0, gy - 2.2, font="F1", size=6.2, rgb=C_TEXT_MUTED, align="right")

        n = len(counts)
        if n == 0:
            return

        pts: list[tuple[float, float]] = []
        for i, val in enumerate(counts):
            px = plot_x + (plot_w * (i / max(1, n - 1)))
            py = plot_y + (plot_h * (min(axis_top, max(0, val)) / axis_top))
            pts.append((px, py))

        # Subtle shaded area under curve matching `--primary-blue-tint`
        poly_cmds = [f"{C_BLUE_TINT[0]:.3f} {C_BLUE_TINT[1]:.3f} {C_BLUE_TINT[2]:.3f} rg"]
        poly_cmds.append(f"{pts[0][0]:.2f} {plot_y:.2f} m")
        for px, py in pts:
            poly_cmds.append(f"{px:.2f} {py:.2f} l")
        poly_cmds.append(f"{pts[-1][0]:.2f} {plot_y:.2f} l\nh\nf")
        self._current_stream.append("\n".join(poly_cmds))

        # Crisp blue stroke line
        line_cmds = [f"1.3 w\n{C_BLUE[0]:.3f} {C_BLUE[1]:.3f} {C_BLUE[2]:.3f} RG\n1 J\n1 j"]
        line_cmds.append(f"{pts[0][0]:.2f} {pts[0][1]:.2f} m")
        for px, py in pts[1:]:
            line_cmds.append(f"{px:.2f} {py:.2f} l")
        line_cmds.append("S")
        self._current_stream.append("\n".join(line_cmds))

        # Point markers + X labels
        for i, (px, py) in enumerate(pts):
            self.add_rect(px - 2.0, py - 2.0, 4.0, 4.0, fill_rgb=C_SURFACE, stroke_rgb=C_BLUE, stroke_width=1.0, radius=2.0)
            if i < len(labels):
                self.add_text(labels[i], px, y + 2.0, font="F1", size=6.0, rgb=C_TEXT_MUTED, align="center")

    def build(self) -> bytes:
        if self._current_stream:
            self.pages.append("\n".join(self._current_stream))
            self._current_stream = []

        if not self.pages:
            self.pages.append("")

        if self._page_hook is not None:
            total_pages = len(self.pages)
            rendered_pages: list[str] = []
            for idx, existing in enumerate(self.pages):
                self._current_stream = [existing] if existing else []
                self._page_hook(self, idx + 1, total_pages)
                rendered_pages.append("\n".join(self._current_stream))
            self._current_stream = []
            self.pages = rendered_pages

        total_pages = len(self.pages)
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = [0]

        # 1: Catalog
        offsets.append(out.tell())
        out.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # 2: Pages Root (pages occupy object IDs 4 .. 4 + total_pages - 1)
        page_start_id = 4
        content_start_id = page_start_id + total_pages
        font_bold_id = content_start_id + total_pages
        font_mono_id = font_bold_id + 1

        page_obj_refs = " ".join(f"{page_start_id + i} 0 R" for i in range(total_pages))
        offsets.append(out.tell())
        out.write(f"2 0 obj\n<< /Type /Pages /Kids [{page_obj_refs}] /Count {total_pages} >>\nendobj\n".encode())

        # 3: F1 Helvetica
        offsets.append(out.tell())
        out.write(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

        for i in range(total_pages):
            p_id = page_start_id + i
            c_id = content_start_id + i
            offsets.append(out.tell())
            page_str = (
                f"{p_id} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R\n"
                f"/MediaBox [0 0 {self.width:.1f} {self.height:.1f}]\n"
                f"/Resources << /Font << /F1 3 0 R /F2 {font_bold_id} 0 R /F3 {font_mono_id} 0 R >> >>\n"
                f"/Contents {c_id} 0 R >>\nendobj\n"
            )
            out.write(page_str.encode())

        for i, page_content in enumerate(self.pages):
            c_id = content_start_id + i
            content_bytes = page_content.encode("latin-1")
            offsets.append(out.tell())
            out.write(f"{c_id} 0 obj\n<< /Length {len(content_bytes)} >>\nstream\n".encode())
            out.write(content_bytes)
            out.write(b"\nendstream\nendobj\n")

        offsets.append(out.tell())
        out.write(f"{font_bold_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n".encode())

        offsets.append(out.tell())
        out.write(f"{font_mono_id} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n".encode())

        xref_offset = out.tell()
        out.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
        for off in offsets[1:]:
            out.write(f"{off:010d} 00000 n \n".encode())

        out.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode())
        return out.getvalue()


_MARGIN_X = 36.0
_CONTENT_W = 540.0
_TOP_Y = 758.0
_FOOTER_LIMIT = 46.0


@dataclass(slots=True)
class _ReportCursor:
    """Tracks vertical layout cursor and manages continuation pages cleanly."""

    pdf: SimplePdfWriter
    now_str: str
    policy_mode: str
    y: float = _TOP_Y

    def new_page(self) -> None:
        self.pdf.start_page(background_rgb=C_BG_APP)
        self.y = _TOP_Y
        bar_h = 30.0
        bar_bot = self.y - bar_h
        self.pdf.add_rect(_MARGIN_X, bar_bot, _CONTENT_W, bar_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
        self.pdf.add_shield_logo(_MARGIN_X + 10.0, bar_bot + 5.0, size=20.0)
        self.pdf.add_text("USB Analyzer", _MARGIN_X + 36.0, bar_bot + 14.5, font="F2", size=9.5, rgb=C_TEXT_MAIN)
        self.pdf.add_text("Forensic Report (cont.)", _MARGIN_X + 36.0, bar_bot + 5.5, font="F1", size=7.2, rgb=C_TEXT_MUTED)
        self.pdf.add_badge(
            f"POLICY: {self.policy_mode.upper().replace('_', ' ')}",
            0,
            bar_bot + 8.0,
            style="blue" if self.policy_mode == "enforce" else "warning",
            align_right_x=_MARGIN_X + _CONTENT_W - 10.0,
        )
        self.y = bar_bot - 10.0


def _draw_band_header(pdf: SimplePdfWriter, x: float, top_y: float, w: float, title: str, subtitle: str, right_badge: tuple[str, str] | None = None) -> float:
    """Draw a top `.band-header` box cleanly rounded only visually inside band container."""
    h = 32.0
    bot_y = top_y - h
    pdf.add_rect(x, bot_y, w, h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
    pdf.add_text(title, x + 12.0, bot_y + 17.5, font="F2", size=10.0, rgb=C_TEXT_MAIN)
    pdf.add_text(subtitle, x + 12.0, bot_y + 6.5, font="F1", size=7.2, rgb=C_TEXT_MUTED)
    if right_badge is not None:
        label, style = right_badge
        pdf.add_badge(label, 0, bot_y + 9.0, style=style, align_right_x=x + w - 12.0)
    return bot_y


def _draw_paginated_table(
    cursor: _ReportCursor,
    *,
    title: str,
    subtitle: str,
    badge: tuple[str, str] | None,
    columns: list[tuple[str, float, float]],  # (header_label, rel_x, col_width)
    rows: list[tuple[float, Callable[[float], None]]],
    empty_message: str,
) -> None:
    """Render an architectural table band with seamless page splits and repeated headers."""
    band_hdr_h = 30.0
    col_hdr_h = 18.0

    if not rows:
        block_h = band_hdr_h + 34.0
        if cursor.y - block_h < _FOOTER_LIMIT:
            cursor.new_page()
        bot = cursor.y - block_h
        cursor.pdf.add_rect(_MARGIN_X, bot, _CONTENT_W, block_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
        cursor.pdf.add_text(title, _MARGIN_X + 12.0, cursor.y - 13.0, font="F2", size=10.0, rgb=C_TEXT_MAIN)
        cursor.pdf.add_text(subtitle, _MARGIN_X + 12.0, cursor.y - 23.0, font="F1", size=7.2, rgb=C_TEXT_MUTED)
        if badge:
            cursor.pdf.add_badge(badge[0], 0, cursor.y - 21.0, style=badge[1], align_right_x=_MARGIN_X + _CONTENT_W - 12.0)
        cursor.pdf.add_line(_MARGIN_X, cursor.y - band_hdr_h, _MARGIN_X + _CONTENT_W, cursor.y - band_hdr_h, rgb=C_BORDER, width=0.7)
        cursor.pdf.add_text(empty_message, _MARGIN_X + 12.0, bot + 13.0, font="F1", size=8.0, rgb=C_TEXT_MUTED)
        cursor.y = bot - 10.0
        return

    idx = 0
    chunk_idx = 0
    while idx < len(rows):
        first_row_h = rows[idx][0]
        min_needed = band_hdr_h + col_hdr_h + first_row_h + 2.0
        if cursor.y - min_needed < _FOOTER_LIMIT:
            cursor.new_page()

        avail = cursor.y - _FOOTER_LIMIT - band_hdr_h - col_hdr_h
        slice_rows: list[tuple[float, Callable[[float], None]]] = []
        used_h = 0.0
        while idx < len(rows) and (not slice_rows or used_h + rows[idx][0] <= avail):
            slice_rows.append(rows[idx])
            used_h += rows[idx][0]
            idx += 1

        block_h = band_hdr_h + col_hdr_h + used_h
        top_y = cursor.y
        bot_y = top_y - block_h
        hdr_title = title if chunk_idx == 0 else f"{title} (cont.)"

        # White bordered band + subtle column header strip
        cursor.pdf.add_rect(_MARGIN_X, bot_y, _CONTENT_W, block_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
        cursor.pdf.add_text(hdr_title, _MARGIN_X + 12.0, top_y - 13.0, font="F2", size=10.0, rgb=C_TEXT_MAIN)
        cursor.pdf.add_text(subtitle, _MARGIN_X + 12.0, top_y - 23.0, font="F1", size=7.2, rgb=C_TEXT_MUTED)
        if badge and chunk_idx == 0:
            cursor.pdf.add_badge(badge[0], 0, top_y - 21.0, style=badge[1], align_right_x=_MARGIN_X + _CONTENT_W - 12.0)

        col_top = top_y - band_hdr_h
        col_bot = col_top - col_hdr_h
        cursor.pdf.add_rect(_MARGIN_X + 0.5, col_bot, _CONTENT_W - 1.0, col_hdr_h, fill_rgb=C_SUBTLE)
        cursor.pdf.add_line(_MARGIN_X, col_top, _MARGIN_X + _CONTENT_W, col_top, rgb=C_BORDER, width=0.7)
        cursor.pdf.add_line(_MARGIN_X, col_bot, _MARGIN_X + _CONTENT_W, col_bot, rgb=C_BORDER, width=0.7)

        for col_label, rel_x, _ in columns:
            cursor.pdf.add_text(col_label, _MARGIN_X + rel_x, col_bot + 6.0, font="F2", size=6.6, rgb=C_TEXT_MUTED)

        row_top = col_bot
        for r_i, (row_h, draw_fn) in enumerate(slice_rows):
            row_bot = row_top - row_h
            if r_i > 0:
                cursor.pdf.add_line(_MARGIN_X + 1.0, row_top, _MARGIN_X + _CONTENT_W - 1.0, row_top, rgb=C_BORDER_SUB, width=0.55)
            draw_fn(row_top)
            row_top = row_bot

        cursor.y = bot_y - 10.0
        chunk_idx += 1


def generate_incident_pdf(
    events: list[DeviceEvent],
    whitelist: list[WhitelistEntry],
    policy_mode: str = "enforce",
) -> bytes:
    """Generate flat architectural PDF Incident & Forensic Report matching dashboard UI."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarize_telemetry(events)
    file_rows = collect_file_analyses(events)

    pdf = SimplePdfWriter()
    pdf.start_page(background_rgb=C_BG_APP)

    def _stamp_footer(writer: SimplePdfWriter, page_no: int, total_pages: int) -> None:
        writer.add_line(_MARGIN_X, 34.0, _MARGIN_X + _CONTENT_W, 34.0, rgb=C_BORDER, width=0.7)
        writer.add_text(
            "USB Analyzer  -  Endpoint Hardware Defense & Forensic Report",
            _MARGIN_X,
            21.0,
            font="F1",
            size=7.2,
            rgb=C_TEXT_MUTED,
        )
        writer.add_text(
            f"Page {page_no} of {total_pages}",
            _MARGIN_X + _CONTENT_W,
            21.0,
            font="F1",
            size=7.2,
            rgb=C_TEXT_MUTED,
            align="right",
        )

    pdf.set_page_footer_hook(_stamp_footer)
    cursor = _ReportCursor(pdf=pdf, now_str=now_str, policy_mode=policy_mode, y=_TOP_Y)

    # 1. Top Architectural Console Header Band
    hdr_h = 48.0
    hdr_bot = cursor.y - hdr_h
    pdf.add_rect(_MARGIN_X, hdr_bot, _CONTENT_W, hdr_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
    pdf.add_shield_logo(_MARGIN_X + 12.0, hdr_bot + 10.0, size=28.0)
    pdf.add_text("USB Analyzer", _MARGIN_X + 48.0, hdr_bot + 26.0, font="F2", size=13.0, rgb=C_TEXT_MAIN)
    pdf.add_text("Incident & Forensic Audit Report", _MARGIN_X + 48.0, hdr_bot + 13.0, font="F1", size=8.0, rgb=C_TEXT_MUTED)

    if summary.blocked_devices > 0:
        health_lbl, health_style = "Threat Detected", "danger"
    elif summary.warning_devices > 0:
        health_lbl, health_style = "Needs Review", "warning"
    else:
        health_lbl, health_style = "Healthy", "safe"

    left_edge, _ = pdf.add_badge(
        health_lbl,
        0,
        hdr_bot + 23.0,
        style=health_style,
        align_right_x=_MARGIN_X + _CONTENT_W - 12.0,
    )
    policy_label = f"POLICY: {policy_mode.upper().replace('_', ' ')}"
    pdf.add_badge(
        policy_label,
        0,
        hdr_bot + 23.0,
        style="blue" if policy_mode == "enforce" else "warning",
        align_right_x=left_edge - 6.0,
    )
    pdf.add_text(f"Generated {now_str}", _MARGIN_X + _CONTENT_W - 12.0, hdr_bot + 10.0, font="F1", size=7.0, rgb=C_TEXT_MUTED, align="right")
    cursor.y = hdr_bot - 10.0

    # 2. Unified Continuous 4-Cell KPI Strip
    kpi_h = 54.0
    kpi_bot = cursor.y - kpi_h
    cell_w = _CONTENT_W / 4.0
    pdf.add_rect(_MARGIN_X, kpi_bot, _CONTENT_W, kpi_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
    for col_i in (1, 2, 3):
        div_x = _MARGIN_X + cell_w * col_i
        pdf.add_line(div_x, kpi_bot + 1.0, div_x, kpi_bot + kpi_h - 1.0, rgb=C_BORDER, width=0.7)

    kpi_cells = [
        ("CONNECTED", str(summary.connected_devices), C_TEXT_MAIN, "Active USB peripherals"),
        ("CRITICAL ALERTS", str(summary.critical_alerts), C_DANGER if summary.critical_alerts else C_TEXT_MAIN, f"Warnings: {summary.warning_alerts}"),
        ("BLOCKED", str(summary.blocked_devices), C_WARN if summary.blocked_devices else C_TEXT_MAIN, "Ports isolated"),
        ("EVENTS & SCANS", str(summary.total_events), C_TEXT_MAIN, f"Scans: {summary.storage_scans} | Flagged: {summary.flagged_files}"),
    ]
    for i, (lbl, val, val_rgb, foot) in enumerate(kpi_cells):
        cx = _MARGIN_X + cell_w * i + 12.0
        pdf.add_text(lbl, cx, kpi_bot + 40.0, font="F2", size=6.6, rgb=C_TEXT_MUTED)
        pdf.add_text(val, cx, kpi_bot + 20.0, font="F2", size=15.0, rgb=val_rgb)
        pdf.add_text(foot, cx, kpi_bot + 7.5, font="F1", size=7.0, rgb=C_TEXT_MUTED)

    cursor.y = kpi_bot - 10.0

    # 3. Unified Activity & Health Band (Mirrors #section-analytics)
    ah_h = 122.0
    ah_bot = cursor.y - ah_h
    band_hdr_h = 28.0
    body_top = cursor.y - band_hdr_h
    split_x = _MARGIN_X + 312.0

    pdf.add_rect(_MARGIN_X, ah_bot, _CONTENT_W, ah_h, fill_rgb=C_SURFACE, stroke_rgb=C_BORDER, radius=4.0)
    pdf.add_text("Activity & Health", _MARGIN_X + 12.0, cursor.y - 12.5, font="F2", size=10.0, rgb=C_TEXT_MAIN)
    pdf.add_text("USB event cadence and monitored device posture.", _MARGIN_X + 12.0, cursor.y - 22.0, font="F1", size=7.2, rgb=C_TEXT_MUTED)
    pdf.add_line(_MARGIN_X, body_top, _MARGIN_X + _CONTENT_W, body_top, rgb=C_BORDER, width=0.7)
    pdf.add_line(split_x, ah_bot + 1.0, split_x, body_top, rgb=C_BORDER, width=0.7)

    # Left Sub-pane: Activity
    pdf.add_text("Activity", _MARGIN_X + 12.0, body_top - 13.0, font="F2", size=8.0, rgb=C_TEXT_MAIN)
    pdf.add_activity_chart(
        _MARGIN_X + 10.0,
        ah_bot + 8.0,
        220.0,
        66.0,
        summary.activity_labels,
        summary.activity_counts,
    )
    stat_x = _MARGIN_X + 240.0
    pdf.add_line(stat_x - 8.0, ah_bot + 12.0, stat_x - 8.0, body_top - 10.0, rgb=C_BORDER_SUB, width=0.6)
    pdf.add_text("EVENTS (1H)", stat_x, body_top - 26.0, font="F2", size=6.2, rgb=C_TEXT_MUTED)
    pdf.add_text(str(summary.window_events), stat_x, body_top - 41.0, font="F2", size=13.0, rgb=C_TEXT_MAIN)
    pdf.add_text("ALERTS (1H)", stat_x, body_top - 59.0, font="F2", size=6.2, rgb=C_TEXT_MUTED)
    pdf.add_text(str(summary.window_alerts), stat_x, body_top - 74.0, font="F2", size=13.0, rgb=C_DANGER if summary.window_alerts else C_TEXT_MAIN)

    # Right Sub-pane: Health Donut
    pdf.add_text("Health", split_x + 12.0, body_top - 13.0, font="F2", size=8.0, rgb=C_TEXT_MAIN)
    pdf.add_badge(health_lbl, 0, body_top - 17.0, style=health_style, align_right_x=_MARGIN_X + _CONTENT_W - 12.0)

    donut_cx = split_x + 42.0
    donut_cy = ah_bot + 40.0
    pdf.add_donut_chart(
        donut_cx,
        donut_cy,
        outer_r=26.0,
        inner_r=19.0,
        segments=[
            (float(summary.safe_devices), C_SAFE),
            (float(summary.warning_devices), C_WARN),
            (float(summary.blocked_devices), C_DANGER),
        ],
        center_text=f"{summary.health_score_pct}%",
    )

    legend_x = split_x + 82.0
    legend_right = _MARGIN_X + _CONTENT_W - 12.0
    legend_rows = [
        ("Safe", C_SAFE, summary.safe_devices),
        ("Warnings", C_WARN, summary.warning_devices),
        ("Blocked", C_DANGER, summary.blocked_devices),
    ]
    for li, (l_name, l_rgb, l_count) in enumerate(legend_rows):
        ly = ah_bot + 54.0 - li * 16.0
        pdf.add_rect(legend_x, ly + 1.0, 6.5, 6.5, fill_rgb=l_rgb, radius=1.2)
        pdf.add_text(l_name, legend_x + 11.0, ly + 1.0, font="F1", size=7.5, rgb=C_TEXT_BODY)
        pdf.add_text(str(l_count), legend_right, ly + 1.0, font="F2", size=7.8, rgb=C_TEXT_MAIN, align="right")

    cursor.y = ah_bot - 10.0

    # 4. Connected Peripherals & Incident Verdicts Table
    dev_columns = [
        ("DEVICE / HARDWARE ID", 12.0, 165.0),
        ("VERDICT", 184.0, 68.0),
        ("DIAGNOSTIC / POLICY REASON", 258.0, 180.0),
        ("ACTION TAKEN", 446.0, 82.0),
    ]
    dev_rows: list[tuple[float, Callable[[float], None]]] = []
    for d in summary.devices[:24]:
        reason_lines = wrap_text(d.reason, 174.0, font="F1", size=7.2, max_lines=2)
        action_lines = wrap_text(d.action, 80.0, font="F1", size=7.0, max_lines=2)
        name_txt = d.name[:32] + ("..." if len(d.name) > 32 else "")
        sn_disp = d.serial_number[:12] + ("..." if len(d.serial_number) > 12 else "")
        id_line = f"VID: {d.vendor_id} | PID: {d.product_id} | SN: {sn_disp}"
        row_h = max(28.0, 10.0 + max(len(reason_lines), len(action_lines)) * 9.5)
        v_style = "danger" if d.verdict == "BLOCKED" else ("warning" if d.verdict == "CONTAINED" else "safe")

        def _make_dev_drawer(
            _n: str = name_txt,
            _id: str = id_line,
            _v: str = d.verdict,
            _vs: str = v_style,
            _rl: list[str] = reason_lines,
            _al: list[str] = action_lines,
        ) -> Callable[[float], None]:
            def _draw(r_top: float) -> None:
                pdf.add_text(_n, _MARGIN_X + 12.0, r_top - 11.5, font="F2", size=7.6, rgb=C_TEXT_MAIN)
                pdf.add_text(_id, _MARGIN_X + 12.0, r_top - 21.0, font="F3", size=6.2, rgb=C_TEXT_MUTED)
                pdf.add_badge(_v, _MARGIN_X + 184.0, r_top - 19.5, style=_vs, size=6.2, height=12.5, min_width=54.0)
                for li, ln in enumerate(_rl):
                    pdf.add_text(ln, _MARGIN_X + 258.0, r_top - 11.5 - li * 9.2, font="F1", size=7.2, rgb=C_TEXT_BODY)
                for li, ln in enumerate(_al):
                    pdf.add_text(ln, _MARGIN_X + 446.0, r_top - 11.5 - li * 9.2, font="F1", size=7.0, rgb=C_TEXT_BODY)
            return _draw

        dev_rows.append((row_h, _make_dev_drawer()))

    _draw_paginated_table(
        cursor,
        title="Audit Log - Devices & Policy Verdicts",
        subtitle="Consolidated per-device threat classification and enforcement status.",
        badge=(f"{len(summary.devices)} Devices", "neutral"),
        columns=dev_columns,
        rows=dev_rows,
        empty_message="No hardware devices recorded during this monitoring window.",
    )

    # 5. Storage Malware Forensic Analysis Table (when storage files analyzed)
    if file_rows:
        flagged_cnt = sum(1 for r in file_rows if int(r.get("risk_score", 0)) >= 20)
        max_score = max(int(r.get("risk_score", 0)) for r in file_rows)
        file_badge_style = "danger" if max_score >= 50 else ("warning" if flagged_cnt > 0 else "safe")

        file_columns = [
            ("FILE & VOLUME", 12.0, 118.0),
            ("FILE TYPE", 134.0, 82.0),
            ("ENTROPY", 220.0, 62.0),
            ("RISK SCORE", 288.0, 74.0),
            ("DIGESTS (SHA-256 / MD5) & INDICATORS", 368.0, 160.0),
        ]
        file_table_rows: list[tuple[float, Callable[[float], None]]] = []
        for item in file_rows[:40]:
            fpath = str(item.get("path") or "")
            vol = str(item.get("volume_path") or "")
            size_b = int(item.get("size_bytes") or item.get("size") or 0)
            size_str = f"{size_b / 1024:.1f} KB" if size_b >= 1024 else f"{size_b} B"
            meta = item.get("metadata") or {}
            ext = str(meta.get("extension") or "")
            ftype = str(item.get("file_type") or "Unknown")
            ent = float(item.get("entropy", 0.0))
            score = int(item.get("risk_score", 0))
            verdict = str(item.get("verdict") or "CLEAN")
            sha256 = str(item.get("sha256") or "")
            md5 = str(item.get("md5") or "")
            flags = [str(fl) for fl in (item.get("flags") or [])]

            path_lines = wrap_text(fpath, 114.0, font="F2", size=7.2, max_lines=2)
            sub_origin = f"{vol} - {size_str}".strip(" -")
            type_lines = wrap_text(ftype, 78.0, font="F1", size=7.2, max_lines=2)
            ext_note = f"Ext: {ext}" + (" (Mismatch)" if meta.get("extension_mismatch") else "")

            sha_line = f"SHA256: {sha256[:28]}..." if len(sha256) > 28 else f"SHA256: {sha256 or 'N/A'}"
            md5_line = f"MD5:    {md5}" if md5 else "MD5:    N/A"
            ind_str = ", ".join(flags) if flags else "No suspicious indicators"
            ind_lines = wrap_text(ind_str, 156.0, font="F1", size=6.5, max_lines=2)

            row_h = max(36.0, 24.0 + len(ind_lines) * 8.2)
            ent_rgb = C_DANGER if (ent >= 7.2 and not meta.get("expected_compressed")) else (C_WARN if ent >= 6.8 else C_BLUE)
            risk_rgb = C_DANGER if score >= 50 else (C_WARN if score >= 20 else C_SAFE)
            risk_badge_style = "danger" if score >= 50 else ("warning" if score >= 20 else "safe")

            def _make_file_drawer(
                _pl: list[str] = path_lines,
                _so: str = sub_origin,
                _tl: list[str] = type_lines,
                _en: str = ext_note,
                _ent: float = ent,
                _ec: RGB = ent_rgb,
                _sc: int = score,
                _rc: RGB = risk_rgb,
                _rb: str = risk_badge_style,
                _vd: str = verdict,
                _sh: str = sha_line,
                _md: str = md5_line,
                _il: list[str] = ind_lines,
            ) -> Callable[[float], None]:
                def _draw(r_top: float) -> None:
                    for li, ln in enumerate(_pl):
                        pdf.add_text(ln, _MARGIN_X + 12.0, r_top - 10.5 - li * 8.8, font="F2", size=7.2, rgb=C_TEXT_MAIN)
                    pdf.add_text(_so, _MARGIN_X + 12.0, r_top - 11.5 - len(_pl) * 8.8, font="F1", size=6.4, rgb=C_TEXT_MUTED)

                    for li, ln in enumerate(_tl):
                        pdf.add_text(ln, _MARGIN_X + 134.0, r_top - 10.5 - li * 8.8, font="F1", size=7.2, rgb=C_TEXT_BODY)
                    pdf.add_text(_en, _MARGIN_X + 134.0, r_top - 11.5 - len(_tl) * 8.8, font="F1", size=6.4, rgb=C_TEXT_MUTED)

                    pdf.add_text(f"{_ent:.2f} b/B", _MARGIN_X + 220.0, r_top - 11.0, font="F2", size=7.2, rgb=C_TEXT_MAIN)
                    pdf.add_progress_bar(_MARGIN_X + 220.0, r_top - 18.0, 52.0, 3.8, _ent / 8.0, _ec)

                    pdf.add_text(f"{_sc}/100", _MARGIN_X + 288.0, r_top - 11.0, font="F2", size=7.4, rgb=_rc)
                    pdf.add_badge(_vd, _MARGIN_X + 288.0, r_top - 30.5, style=_rb, size=5.8, height=11.0, min_width=44.0)
                    pdf.add_progress_bar(_MARGIN_X + 288.0, r_top - 17.5, 58.0, 3.8, _sc / 100.0, _rc)

                    pdf.add_text(_sh, _MARGIN_X + 368.0, r_top - 10.0, font="F3", size=6.1, rgb=C_TEXT_BODY)
                    pdf.add_text(_md, _MARGIN_X + 368.0, r_top - 18.0, font="F3", size=6.1, rgb=C_TEXT_MUTED)
                    for li, ln in enumerate(_il):
                        pdf.add_text(ln, _MARGIN_X + 368.0, r_top - 27.0 - li * 8.0, font="F1", size=6.5, rgb=C_WARN_TEXT if _sc >= 20 else C_TEXT_MUTED)
                return _draw

            file_table_rows.append((row_h, _make_file_drawer()))

        _draw_paginated_table(
            cursor,
            title="File Analysis - Signatures, Entropy & Hashes",
            subtitle="Static & YARA inspection results across mounted USB volumes.",
            badge=(f"{len(file_rows)} Scanned / {flagged_cnt} Flagged", file_badge_style),
            columns=file_columns,
            rows=file_table_rows,
            empty_message="No USB storage files scanned.",
        )

    # 6. Whitelist Band
    wl_columns = [
        ("DEVICE NAME", 12.0, 155.0),
        ("VENDOR ID", 174.0, 68.0),
        ("PRODUCT ID", 248.0, 68.0),
        ("SERIAL NUMBER", 322.0, 108.0),
        ("NOTES", 436.0, 92.0),
    ]
    wl_rows: list[tuple[float, Callable[[float], None]]] = []
    for w in whitelist[:20]:
        note_lines = wrap_text(w.notes or "Authorized device", 90.0, font="F1", size=7.0, max_lines=2)
        row_h = max(22.0, 8.0 + len(note_lines) * 9.0)
        vid = f"0x{w.vendor_id.upper()}" if w.vendor_id else "ANY"
        pid = f"0x{w.product_id.upper()}" if w.product_id else "ANY"
        sn = w.serial_number or "ANY"

        def _make_wl_drawer(
            _nm: str = w.name[:30],
            _v: str = vid,
            _p: str = pid,
            _s: str = sn[:20],
            _nl: list[str] = note_lines,
        ) -> Callable[[float], None]:
            def _draw(r_top: float) -> None:
                pdf.add_text(_nm, _MARGIN_X + 12.0, r_top - 13.0, font="F2", size=7.4, rgb=C_TEXT_MAIN)
                pdf.add_text(_v, _MARGIN_X + 174.0, r_top - 13.0, font="F3", size=7.0, rgb=C_TEXT_BODY)
                pdf.add_text(_p, _MARGIN_X + 248.0, r_top - 13.0, font="F3", size=7.0, rgb=C_TEXT_BODY)
                pdf.add_text(_s, _MARGIN_X + 322.0, r_top - 13.0, font="F3", size=6.8, rgb=C_TEXT_BODY)
                for li, ln in enumerate(_nl):
                    pdf.add_text(ln, _MARGIN_X + 436.0, r_top - 13.0 - li * 8.8, font="F1", size=7.0, rgb=C_TEXT_MUTED)
            return _draw

        wl_rows.append((row_h, _make_wl_drawer()))

    _draw_paginated_table(
        cursor,
        title="Whitelist - Authorized Hardware Rules",
        subtitle="Explicitly trusted USB peripherals permitted by policy.",
        badge=(f"{len(whitelist)} Trusted", "blue" if whitelist else "neutral"),
        columns=wl_columns,
        rows=wl_rows,
        empty_message="No whitelisted devices registered.",
    )

    # 7. Recent Event Trail Band
    ev_columns = [
        ("TIME", 12.0, 56.0),
        ("EVENT TYPE", 72.0, 108.0),
        ("VERDICT", 184.0, 66.0),
        ("DEVICE & SUMMARY", 256.0, 272.0),
    ]
    ev_rows: list[tuple[float, Callable[[float], None]]] = []
    for ev in events[:25]:
        ev_time = ev.time.strftime("%H:%M:%S")
        verdict, reason, _ = classify_event_verdict(ev)
        dev_name = extract_device_name(ev.device_id, ev.details)
        summary_str = f"{dev_name} - {reason}"
        sum_lines = wrap_text(summary_str, 268.0, font="F1", size=7.1, max_lines=2)
        row_h = max(21.0, 7.0 + len(sum_lines) * 9.0)
        v_style = "danger" if verdict == "BLOCKED" else ("warning" if verdict == "CONTAINED" else "safe")

        def _make_ev_drawer(
            _tm: str = ev_time,
            _et: str = ev.event_type[:22],
            _vd: str = verdict,
            _vs: str = v_style,
            _sl: list[str] = sum_lines,
        ) -> Callable[[float], None]:
            def _draw(r_top: float) -> None:
                pdf.add_text(_tm, _MARGIN_X + 12.0, r_top - 12.5, font="F3", size=6.8, rgb=C_TEXT_MUTED)
                pdf.add_text(_et, _MARGIN_X + 72.0, r_top - 12.5, font="F2", size=7.1, rgb=C_TEXT_MAIN)
                pdf.add_badge(_vd, _MARGIN_X + 184.0, r_top - 16.0, style=_vs, size=5.9, height=11.5, min_width=50.0)
                for li, ln in enumerate(_sl):
                    pdf.add_text(ln, _MARGIN_X + 256.0, r_top - 12.5 - li * 8.8, font="F1", size=7.1, rgb=C_TEXT_BODY)
            return _draw

        ev_rows.append((row_h, _make_ev_drawer()))

    _draw_paginated_table(
        cursor,
        title="Recent Event Stream",
        subtitle=f"Most recent {min(len(events), 25)} recorded USB & scan events.",
        badge=(f"{len(events)} Total", "neutral"),
        columns=ev_columns,
        rows=ev_rows,
        empty_message="No telemetry events recorded yet.",
    )

    return pdf.build()
