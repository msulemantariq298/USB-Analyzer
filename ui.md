# USB Analyzer — Next-Gen Endpoint Hardware Defense Console
## UI Architecture & Design Specification (`ui.md`)

*Synthesized from `design-taste-frontend` (app-screens.md), `impeccable` (Operate Mode), and `emil-design-eng`.*

---

## 1. Executive Design Philosophy

The objective is to replace generic "AI-generated" dashboard tropes (floating card soup, random gradient fills, colored circle icons, multicolored zeros, pill-button mismatches) with an authentic, high-precision **Security Operations Terminal**. 

This console is built for long-duration monitoring, rapid forensic triage, and automated hardware containment.

### The Three Skill Pillars
1. **`design-taste-frontend` (`references/app-screens.md`)**:
   - **Archetype**: `data-terminal` meets `framed-sheet`.
   - **Color Budget**: Chromatic pixels strictly ≤ 5%. Color exists exclusively on **data and security verdicts**, never as decorative chrome.
   - **Type-Led Metrics**: KPIs are type and tabular numbers, not boxy cards with icons in colored circles.
   - **Data Honesty**: Zeros print in standard neutral ink (`var(--text-main)`). No fake celebratory green deltas or multicolored zeros on empty states.
   - **Flat Precision**: No heavy drop shadows on resting surfaces; separation achieved through 1px border rules and subtle tone steps.
   - **No Display Hero Headings**: Restrained 20–22px section titles; no giant marketing banners.

2. **`impeccable` (Operate Mode)**:
   - **Scanability & Ergonomics**: Dense hardware attributes (VID, PID, Serial, Class) formatted with monospaced precision for instantaneous pattern recognition.
   - **Unified Geometry**: Strict corner-radius scale: `4px` (chips/badges), `6px` (controls/inputs/buttons), `8px` (panels/tables/containers). Zero mismatched pill buttons.
   - **Guaranteed Contrast**: WCAG AAA/AA compliance across both light (`#f8fafc` canvas / `#ffffff` card / `#0f172a` ink) and dark (`#070c18` canvas / `#0e172a` card / `#f8fafc` text) themes.
   - **Edge-to-Edge Grid Balance**: Compartments land on exact grid axes with zero orphan space or dead vertical bands.

3. **`emil-design-eng` (Motion & Micro-Interactions)**:
   - **Spring Dynamics**: All interactive transitions use custom cubic-bezier easing (`--ease-spring: cubic-bezier(0.16, 1, 0.3, 1)` and `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)`).
   - **Tactile Feedback**: Pressable elements depress slightly on `:active` (`transform: scale(0.97)`).
   - **Origin-Aware Scaling**: Modals and dropdowns animate from realistic starting points (`scale(0.95)`, opacity 0) rather than cartoonish `scale(0)`.
   - **Cinematic Venom Symbiote Transition**: Organic liquid goo displacement filter combining SVG turbulence, alpha thresholding, and staggered tendril crawling for dark/light mode toggling.

---

## 2. Color System & Architectural Tokens

The palette strictly adheres to **Black, White, and Deep Technical Blue**, supported by restrained semantic signals.

### Light Mode (`:root`)
- **Canvas / Ground**: `#f8fafc` (Ultra-subtle cool slate)
- **Surfaces**: `#ffffff` (Crisp white panels)
- **Subtle Surface / Toolbar**: `#f1f5f9` (Working band)
- **Surface Hover**: `#e2e8f0` (Direct feedback state)
- **Hairline Rules & Borders**: `#e2e8f0` (1px crisp structural division)
- **Text Main (Ink)**: `#0f172a` (High-contrast midnight slate)
- **Text Muted**: `#475569` (Slate 600, > 5:1 contrast)
- **Text Dim (Metadata)**: `#64748b` (Slate 500, > 4.5:1 contrast)
- **Cobalt Anchor**: `#0f2b5c` (Deep navy enterprise anchor)
- **Primary Action**: `#1d4ed8` (Royal cobalt CTA, hover `#1e40af`)
- **Blue Tint / Badge**: `#eff6ff` (Ice blue background, border `#bfdbfe`)

### Dark Mode (`:root[data-theme="dark"]`)
- **Canvas / Ground**: `#070c18` (True deep obsidian/navy)
- **Surfaces**: `#0e172a` (Solid dark navy slate)
- **Subtle Surface / Toolbar**: `#131e36` (Compartment background)
- **Surface Hover**: `#192744` (Interactive hover)
- **Hairline Rules & Borders**: `#1e2f4f` (Subtle boundary rule)
- **Text Main**: `#f8fafc` (Crisp optical white)
- **Text Muted**: `#cbd5e1` (Light slate)
- **Text Dim**: `#94a3b8` (Balanced mid-slate)
- **Cobalt Anchor**: `#1e3a8a` (Vibrant deep blue)
- **Primary Action**: `#3b82f6` (Vibrant electric cobalt, hover `#2563eb`)
- **Blue Tint / Badge**: `rgba(59, 130, 246, 0.14)` (border `rgba(59, 130, 246, 0.35)`)

### Restrained Semantic Accents (Data & Verdicts Only)
- **Safe / Approved**: Emerald (`#065f46` text on `#ecfdf5` bg / Dark: `#34d399` on `rgba(16, 185, 129, 0.14)`)
- **Suspicious / Warning**: Burnished Amber (`#92400e` text on `#fffbeb` bg / Dark: `#fbbf24` on `rgba(245, 158, 11, 0.14)`)
- **Critical / Blocked**: Crimson Rose (`#9f1239` text on `#fff1f2` bg / Dark: `#fb7185` on `rgba(244, 63, 94, 0.14)`)

---

## 3. Typography & Hierarchy

- **Primary Grotesk**: `Montserrat` (Clean geometric structure, balanced proportions, enterprise authority).
  - Page Title: `20px` (Weight 700, tracking `-0.015em`)
  - Section Headers: `15px` (Weight 700, tracking `-0.01em`)
  - Body & Table Cells: `13px` (Weight 500/600, line-height 1.45)
  - Labels & Metadata: `11px` (Weight 600, tracking `0.04em`, uppercase/sentence case)
- **Technical Monospace**: `JetBrains Mono` (Zero-ambiguity font for cryptographic hashes, hardware serials, VID:PID, timestamps, and tabular counters).
  - Tabular Numbers (`font-variant-numeric: tabular-nums`): Prevents layout shifting during real-time telemetry updates.

---

## 4. Layout Architecture

### 1. Security Command Topbar
- **Sticky, Minimalist 44px Navigation Bar**:
  - Left: `USB Analyzer Dashboard` text with an executive monospace badge `ENDPOINT DEFENSE BUS`.
  - Center/Status: Live WMI connection heartbeat (`#api-status`) and active hardware protection state (`ACTIVE DEFENSE`).
  - Right: Unified 30px tool buttons with matching stroke icons:
    - Audio Threat Chimes (`Alerts On`)
    - Architecture & MITRE Matrix (`MITRE Matrix`)
    - Forensic Incident Export (`Export PDF`)
    - Dark/Light Venom Symbiote Trigger (`#theme-toggle`)

### 2. Live Security Incident Callout
- Inline high-urgency containment alert (`#security-alert-banner`) that slides down smoothly with a crimson left accent line and immediate isolation details if an unauthorized or malicious device is detected.

### 3. Unified Architectural Telemetry HUD Strip
- Discards the repetitive 6-card box soup.
- Implements a **single continuous architectural HUD container** partitioned into 6 equal compartments by 1px vertical hairlines:
  1. `Total Events` (`#total-events`) — Anchor compartment in deep cobalt.
  2. `Devices Blocked` (`#blocked-count`) — Hardware ports isolated.
  3. `Policy Warnings` (`#warning-events`) — Unregistered devices requiring triage.
  4. `Critical Threats` (`#critical-events`) — BadUSB & malware droppers intercepted.
  5. `Storage Scans` (`#active-scans`) — Removable volumes inspected.
  6. `Flagged Files` (`#flagged-files`) — YARA signature & SHA-256 matches.
- All numbers are tabular figures at 26px. Zeros are printed honestly in neutral ink.

### 4. Hardware Diagnostics & Attack Simulation Console
- Integrated testbench (`.scenario-simulator-bar`) embedded directly above the audit log.
- Clean technical subtitle with 5 instant hardware injection triggers:
  - `Safe Storage` (`safe_usb`)
  - `BadUSB Attack` (`badusb`)
  - `Infected Media` (`malware_drive`)
  - `Unknown Peripheral` (`unauthorized_device`)
  - `Spoofed Hardware` (`spoofed_identity`)
- Standardized 28px buttons with tactile press states and zero contrast bugs in dark mode.

### 5. Real-Time Hardware Event Audit Log & Forensic Drawer
- Controls bar:
  - Segmented View Switcher: `Connected Devices (Summary)` vs `All Raw Events`.
  - Global Search Input: Instant substring filtering with keyboard shortcut hint (`/`).
  - Action Controls: `Clear Log`, `Refresh`, `CSV Log`.
- Data Table:
  - 1px hairline rules, zero zebra striping, 44px row pitch.
  - Device identification: Product string, hardware serial, and `VID:PID` in monospace.
  - Verdict indicators: High-contrast desaturated badges.
  - Interactive Forensic Inspection: Expanding drawer detailing:
    - Infosec Risk Assessment
    - Specific MITRE ATT&CK Framework Mapping
    - Action Justification & Recommendation
    - Quick-Action Triage Buttons (Block Device, Trust & Whitelist, Allow Device)
    - Storage volume file findings & raw JSON payload.

### 6. Analytics Bento Grid
- Card 1: `Threat Severity Ratio` (Clean doughnut ring with thin border and clean legend).
- Card 2: `Activity Distribution` (Crisp column chart with square corners and quiet gridlines).

### 7. Enterprise Hardware Whitelist Console
- Authorized devices table with inline expandable registration form (Device Name, Physical Serial, VID, PID).

### 8. Interactive Modals
- **MITRE ATT&CK Matrix**: Comprehensive 3-tier defense taxonomy mapping endpoint hardware controls (Layer 1), keystroke cadence dynamics (Layer 2), and storage threat scanning (Layer 3).
- **Suspicious Device Triage**: Clean Windows Defender-grade prompt offering immediate one-click actions: Block, Whitelist, or Let It Run.

---

## 5. Animation Specification (Emil Kowalski Physics)

1. **Venom Symbiote Dark/Light Mode Transition**:
   - High-definition SVG overlay (`#venom-transition-overlay`) with `feTurbulence` (baseFrequency 0.04, 4 octaves) and `feColorMatrix` thresholding for visceral liquid slime physics.
   - Dual tendril branches (`branch-1`, `branch-2`) and micro-droplets erupt from `#theme-toggle` coordinates.
   - Snappy spring-like expansion (`cubic-bezier(0.16, 1, 0.3, 1)`) enveloping the viewport in 580ms.
   - Seamless synchronization with `document.startViewTransition` clip-path.
   - Haptic micro-scale bounce on the toggle button (`scale(0.92)` -> `scale(1.08)` -> `scale(1)`).
2. **Interactive Controls**:
   - `:active` press state: `transform: scale(0.97)` on all buttons and tabs.
   - Hover transitions: Snappy 120ms ease-out transitions on borders and backgrounds.
   - Modals: Smooth origin-aware entrance from `scale(0.96) translateY(6px)` to `scale(1) translateY(0)`.
3. **Accessibility**:
   - `@media (prefers-reduced-motion: reduce)` completely disables heavy tendril morphing and instant-toggles theme.
