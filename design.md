# Praxis Scanner — Design System & UX Specification

> Status: active implementation specification  
> Platform: Linux desktop, GTK4 + libadwaita  
> Reference quality: Material 3 / Material You  
> Platform authority: GNOME Human Interface Guidelines and the installed libadwaita API  
> Scope: this document defines the visual language, information architecture, interaction model, component patterns, and acceptance criteria specifically for Praxis Scanner.

## 1. Product design intent

Praxis Scanner should feel like a polished, trustworthy network utility: calm, precise, fast to understand, and effortless for common tasks. Its visual quality should approach the care and consistency of a well-made Material 3 application while behaving like a first-class Linux desktop application.

This is not a literal Android/Compose port. Material 3 is a reference for hierarchy, tonal surfaces, shape, typography, state feedback, and clear primary actions. GTK4/libadwaita conventions govern actual widgets, navigation, focus, keyboard behavior, system integration, and adaptive layouts.

### Design principles

1. One obvious next action. The first screen makes the selected network and primary local scan immediately understandable.
2. Progressive disclosure. Common discovery is prominent; specialist protocols, port customization, and diagnostics remain available but secondary.
3. Evidence before inference. Confirmed facts are distinct from observations and heuristics. A timeout never proves a host is offline.
4. Fast scanning, calm presentation. Network work runs off the GTK main thread; the UI reports progress, phase, counts, cancellation, and completion without freezing.
5. Native desktop first. Use Adwaita controls and system theme behavior; avoid custom web-like chrome and Android-only navigation metaphors.
6. Consistent, accessible details. Clear labels, predictable spacing, visible focus, keyboard access, scalable text, and sufficient contrast.
7. Trust and restraint. Avoid unnecessary permissions, surprise scans, deceptive status colors, and overdecorated dashboards.

## 2. Information architecture

### Primary destinations

- Home: network selection, local-network scan, progress, discovered devices, advanced discovery.
- Device details: identity and evidence, open ports, service hints, discovery sources, per-device scan progress and cancellation.
- Settings: appearance, language, startup behavior, privacy/about.
- Custom ports: manage the user's additional TCP ports.

Keep central destinations in the same application window with libadwaita navigation. Use hierarchical navigation for device details and settings. Do not introduce a multi-pane dashboard unless it demonstrably improves the desktop workflow.

### Home screen hierarchy

1. Header bar: app identity, page title, refresh, settings.
2. Network context: selected interface, local IPv4 address, prefix/subnet and gateway when known. Make interface selection easy to understand.
3. Primary scan surface: one strong, full-width “Scan local network” action. Preselect the default-route eligible interface where possible. Selection must not silently start a scan.
4. Scan feedback: idle, preparing, scanning, cancelling, completed, partial, no-results, and error states. Show meaningful phase and discovered/responsive/observed counts when available.
5. Device results: readable device rows with identity and IP as the first scan targets. Current device is clearly identified. Responsive and merely observed devices remain semantically distinct.
6. Advanced discovery: TCP port configuration and optional mDNS, SSDP, NetBIOS, and ICMP operations in a secondary disclosure area. Results remain associated with their source and target.

### Device details hierarchy

1. Device identity header: icon, display name, IP, current-device indicator and evidence-based reachability.
2. Primary action/status: common TCP port scan, target, progress, cancel, completion.
3. Open ports: port number, conservative service label, and result state. Unknown service labels are preferable to guesses.
4. Network identity: MAC, vendor, hostname, device classification only when supported by evidence.
5. Discovery evidence: mDNS, SSDP, NetBIOS, ICMP and TCP observations in clearly separated sections.
6. Local customization: rename and icon selection, with reset actions.

Do not label a device offline unless there is reliable positive evidence. Use “No response” or “Reachability unknown” where appropriate.

## 3. Visual language

### Overall character

- Clean, modern, precise, and quietly technical.
- Use Adwaita's native window, header bar, list, row, button, dialog, and preference patterns.
- Use meaningful surfaces to group tasks, not a card around every control.
- Avoid neon hacker styling, gradients, glassmorphism, heavy shadows, excessive borders, emoji-as-icons, and decorative data visualizations.
- Avoid a crowded admin-console appearance on the home screen.

### Color and theme

- Respect system light/dark appearance by default.
- Use libadwaita semantic colors and the system accent color for primary actions and focus.
- Use success/warning/error colors only for meaningful status; do not encode reachability by color alone.
- Never hardcode a full Material palette over Adwaita or force a theme independent of the user's system.
- Ensure every state remains understandable in monochrome and with reduced contrast.

### Typography

- Prefer the system UI font and Adwaita semantic text styles: title-1, title-2, title-3, body, caption, and dim-label.
- Use a short, clear page title; headings describe a section, not repeat the application name.
- IP addresses, MAC addresses, ports, and latency are technical values: keep them readable and consistently formatted.
- Avoid all-caps labels and long explanatory paragraphs in the main flow.

### Shape and surfaces

- Use Adwaita native card, boxed-list, and control styling.
- Group network context and primary scan feedback in separate, meaningful surfaces.
- Use a restrained corner/spacing rhythm; do not nest cards unnecessarily.
- Prefer tonal separation and whitespace over strong shadows or custom border colors.
- Keep the primary action visually dominant without making it oversized.

### Spacing and layout

- Use a consistent 4-point base rhythm: 4, 8, 12, 16, 20, 24, 32.
- Use 20–24 px page margins on comfortable desktop widths; reduce margins at narrow widths.
- Use 16 px internal card padding and 12–20 px between related sections.
- Constrain long-form content with AdwClamp (home target maximum around 960 px; detail target around 820 px).
- Avoid long, edge-to-edge text lines on large windows.
- Support at least 1024×600 desktop windows and narrow/split layouts without horizontal scrolling.

## 4. Component patterns

### Network selector

- Use a native GtkListBox/AdwActionRow or equivalent native selector.
- Each option shows interface name, IPv4 address, prefix, and a concise connection hint where known.
- Clearly indicate the selected interface.
- Preselect the eligible default-route interface, otherwise the first eligible interface.
- Never silently scan merely because the interface is selected.

### Primary scan action

- Use a single prominent suggested-action button with a concise verb label.
- Keep the action in the natural reading order after network context.
- Disable it only when no eligible network exists or an incompatible operation is active; explain why.
- Provide immediate visual feedback after activation and prevent duplicate concurrent scans.
- Cancellation must be visible while work is active.

### Device rows

- Use AdwActionRow/boxed-list patterns.
- Primary line: user-defined name or useful hostname; fallback to IPv4 address.
- Secondary line: IPv4 address and a small set of high-value evidence fields.
- Keep the current-device marker visible but quiet.
- Use a dedicated icon action for one-click per-device port inspection, with an accessible tooltip/label.
- Do not pack every discovery fact into one subtitle; put detailed evidence on the device page.
- Keep list sorting deterministic: current device, positively responsive devices, then observations with unknown reachability; numeric IP ordering within groups.

### Progress and empty states

- Show a human-readable phase, progress indicator, and useful counts.
- Use a clear empty state for no interface, idle, no devices found, no open ports, and scan failure.
- Explain the next useful action in one sentence.
- Do not use a success-looking 100% bar for an operation that failed or was cancelled.
- Cancellation and timeout are distinct states.

### Port results

- Group results into open and non-open/inconclusive only when useful; prioritize open ports.
- Show port/protocol, service hint, and evidence status.
- Never imply a service/version is confirmed by port number alone.
- Use a compact, scannable list with consistent alignment.

### Settings and dialogs

- Follow native libadwaita preferences patterns.
- Group related settings with concise explanatory subtitles.
- Use confirmation only for costly or destructive operations; provide reversible actions when possible.
- Preserve native focus, keyboard navigation, and dialog behavior.

## 5. Interaction model

### Main workflow: local network

1. Detect eligible IPv4 interfaces and default route.
2. Preselect the most likely active interface.
3. User presses Scan local network once.
4. Run bounded discovery without blocking the UI.
5. Update progress and device results incrementally.
6. User selects a device or its port-scan action.
7. Show device detail and bounded common-port results with cancellation.

### Per-device port workflow

- Target must be explicit and visible.
- Use the standard common TCP set plus enabled custom ports by default.
- Full 1–65535 scans are not a default action; if introduced, require explicit scope, confirmation, strict rate/timeout bounds, and cancellation.
- A one-click action is permitted only for the selected device's bounded standard scan.
- Do not describe an IP as an API endpoint unless the user or discovery data establishes that context.

### Keyboard and accessibility

- All actions must be reachable by keyboard.
- Maintain logical focus order and visible focus.
- Provide accessible names for icon-only actions.
- Do not rely on color alone for state.
- Respect system text scaling and high-contrast preferences.
- Use concise labels and meaningful tooltips.

## 6. Localization and writing

- English and Turkish must be equally complete.
- All visible labels, tooltips, empty states, progress messages, errors, and accessibility labels use the localization helper/catalog.
- Avoid hard-coded English strings in dynamic scan callbacks.
- Prefer short, action-oriented language:
  - “Scan local network” / “Yerel ağı tara”
  - “Scanning devices…” / “Cihazlar taranıyor…”
  - “Reachability unknown” / “Erişilebilirlik bilinmiyor”
  - “Scan ports” / “Portları tara”
- Technical identifiers (IP, MAC, port numbers, protocol names) are not translated.

## 7. Motion and feedback

- Prefer native GTK/libadwaita transitions and state changes.
- Keep progress updates calm and non-flashy.
- Avoid decorative animation that competes with scan feedback.
- Ensure reduced-motion settings are respected.
- Use toasts/status messages only for concise transient feedback; persistent operation state belongs in the page.

## 8. Security and trust UX

- Scanning is local and explicit; no root, sudo, raw sockets, setuid, privileged daemon, or automatic firewall/sysctl changes.
- Explain bounded scan limits in advanced/help text, not as a wall of copy on the home screen.
- Treat mDNS, SSDP, NetBIOS and banner data as untrusted.
- Never automatically fetch arbitrary SSDP URLs or open discovered endpoints without explicit user activation.
- Do not overstate device identity, operating system, vendor, online/offline status, or service detection.

## 9. Implementation order

1. Stabilize formatting, tests, Clippy, release build, and Flatpak CI before large UI refactors.
2. Complete the home screen hierarchy, selected-network context, empty/loading/error states, and device row visual quality.
3. Refine device detail and port results, preserving existing scan lifecycle and cancellation.
4. Complete English/Turkish localization of all visible states.
5. Validate light/dark themes, narrow/wide windows, keyboard navigation, and text scaling.
6. Compare against Android reference screens and document intentional Linux differences.
7. Only then add further visual effects or advanced layout changes.

## 10. Visual acceptance checklist

A design change is not complete until checked in a running application at 1024×600 and a large desktop size, in both light and dark appearance.

- [ ] Home idle with a selected interface
- [ ] No eligible interface / no network state
- [ ] Scan in progress with meaningful progress and cancellation
- [ ] Scan completed with multiple devices
- [ ] No devices found
- [ ] Error and cancellation states
- [ ] Device row with custom name and evidence
- [ ] Device detail with open ports and no-open-port state
- [ ] Port scan in progress and cancelled
- [ ] Settings and custom-port pages
- [ ] English and Turkish text fit without clipping
- [ ] Keyboard-only operation and visible focus
- [ ] Narrow and wide layout behavior
- [ ] Light and dark theme behavior
- [ ] No unnecessary permissions or network behavior changes

## 11. Research references

GNOME/libadwaita governs platform implementation; Material 3 is used as a design-quality reference.

- [GNOME Human Interface Guidelines](https://developer.gnome.org/hig/) — platform design principles, widgets, writing, typography, accessibility, navigation.
- [GNOME Design Principles](https://developer.gnome.org/hig/principles.html) — simplicity, progressive disclosure, reducing user effort, consideration.
- [GNOME Adaptive Design](https://developer.gnome.org/hig/guidelines/adaptive.html) — narrow/wide layouts, responsive containers, window sizing.
- [GNOME Navigation](https://developer.gnome.org/hig/guidelines/navigation.html) — hierarchical navigation and focused views.
- [libadwaita Adaptive Layouts](https://gnome.pages.gitlab.gnome.org/libadwaita/doc/1.8/adaptive-layouts.html) — AdwClamp, breakpoints, adaptive dialogs and split views.
- [Material 3 Design in Compose](https://developer.android.com/develop/ui/compose/designsystems/material3) — typography, tonal surfaces/elevation, component states and design-system consistency.
