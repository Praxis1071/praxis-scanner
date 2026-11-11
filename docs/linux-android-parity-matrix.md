# Android → Linux Feature-Parity Matrix

> **Status:** Initial source-backed audit, 2026-11-11  
> **Target branch:** `linux/gtk4-port-planning`  
> **Purpose:** Track the Android Praxis Scanner product experience feature by feature. This is a living acceptance checklist, not a promise that an item works merely because a similarly named Linux control exists.

## Status legend

- **Missing:** no corresponding Linux implementation has been identified.
- **Partial:** some of the behavior exists, but the Android workflow or result contract is not reproduced.
- **Implemented / unverified:** source implementation exists, but host and/or Flatpak behavior is not yet verified.
- **Verified:** implementation and the named verification gates have passed. A status must say which gates passed.
- **Different by design:** Linux requires a platform-native equivalent; the behavior and reason must be documented and reviewed.

No item is complete until the Android reference has been examined, the Linux behavior implemented, and the relevant automated, host, Flatpak, and visual-parity checks recorded.

## 1. Navigation and application structure

| Android reference | Expected user-visible behavior | Linux branch status | Remaining work |
|---|---|---|---|
| `NavGraph.kt` — Home route | Home is the start destination; navigation to detail and settings | **Partial** — one main window only | Add native page navigation and back/close behavior |
| `NavGraph.kt` — DeviceDetail route | Open a selected device by IP | **Missing** | Implement device detail page and lifecycle |
| `NavGraph.kt` — Settings route | Open settings | **Implemented in source / unverified** — native settings page and navigation added | Verify navigation, keyboard operation, persistence and visual parity |
| `NavGraph.kt` — CustomPorts route | Navigate to custom TCP port management | **Implemented in source / unverified** — add, enable/disable, delete and persistent storage | Verify validation, persistence, empty state and visual parity |
| Android expressive navigation/transitions | Clear, consistent screen transitions and back behavior | **Missing / desktop adaptation needed** | Define GTK/libadwaita-native equivalent; verify keyboard and window navigation |

## 2. Home screen and device list

| Android reference | Expected behavior | Linux branch status | Remaining work |
|---|---|---|---|
| `HomeScreen.kt` | Main screen with app title and settings action | **Partial** — settings action now opens a native settings page; home information hierarchy still differs | Match home header/actions and screen spacing |
| `HomeScreen.kt` auto-scan preference | Automatically start a scan on launch when enabled (Android default: enabled) | **Implemented in source / unverified** — persisted toggle; disabled by default as a deliberate Linux safety difference; when enabled selects default-route interface and starts bounded scan | Verify startup selection, no-route fallback, persistence and cancellation |
| `NetworkInfoBar.kt` | Show current network information and selectable interfaces | **Partial** — interface list/selection and route summary exist | Match information fields, selection presentation, unavailable states |
| `DeviceList.kt`, `DeviceCard.kt` | Separate online/offline devices; readable identity/type/IP/status; custom icon; current-device marker | **Partial** — responsive and unverified observations are grouped without falsely claiming offline; saved custom names/icons appear in rows; local IP is shown in interface status | Add dedicated current-device card, automatic type classification and visual card/list parity |
| `EmptyState.kt` | Distinct idle, no Wi-Fi, and no-results states | **Partial** — status text only | Implement equivalent empty/no-interface/no-result/error states |
| `ScanProgressCard.kt` | Visible progress, phase/message, found-device count, cancel action | **Partial** — scan status/progress and cancellation exist in source; UI needs parity review | Match phases, progress semantics, counters, cancellation feedback |
| Snackbar/error flow in `HomeScreen.kt` | Surface errors and useful recovery guidance | **Partial** — status labels are used | Add consistent error presentation and actionable recovery |
| Online/offline ordering in `MainViewModel.kt` | Current device first, online then offline, numerically ordered IPs | **Missing / partial** | Define and test equivalent ordering and online confidence semantics |

## 3. Device details

Android references: `DeviceDetailScreen.kt`, `DeviceInfoCard.kt`, `DetailSection.kt`, `PortItem.kt`, `DeepScanSection.kt`, `EditDeviceNameDialog.kt`, `EditDeviceIconDialog.kt`.

| Expected behavior | Linux branch status | Remaining work |
|---|---|---|
| Open detail view for a selected device | **Partial — source committed, CI pending** | An initial Adw NavigationView detail page opens from device rows and displays currently collected evidence; complete identity, status, customization, deep-scan workflow, and visual parity remain missing |
| Device header with icon, display name, type, online/offline and current-device badges | **Partial / source implemented** — custom display name and icon are shown; type, online/offline and current-device badges remain missing | Add confidence-scored type and evidence-based reachability/current-device badges |
| Edit custom device name and restore default | **Implemented in source / unverified** — validated local name editor, reset action and list/header update; key is IPv4 address | Verify persistence and DHCP address-change behavior |
| Choose a custom device icon and restore automatic icon | **Implemented in source / unverified** — icon chooser includes automatic plus eight local icon mappings | Verify icon theme availability, restart persistence and visual parity |
| Identity/network information (IP, MAC, vendor, hostname, device type) | **Partial** — raw IP/MAC and evidence summary only | Add structured fields and clear unavailable/unknown states |
| Latency and TTL/OS hint | **Missing** — TCP response is not equivalent to ICMP latency/TTL | Implement only if safe Linux method is verified; never mislabel TCP timing as ping latency |
| Discovery method, UPnP metadata, NetBIOS workgroup, mDNS services | **Partial** — mDNS, SSDP and NetBIOS evidence are displayed; identity remains unverified and presentation is incomplete | Complete evidence sections and verify on real devices |
| Open web interface from SSDP LOCATION | **Not implemented by design** — Linux currently treats LOCATION as untrusted text and does not fetch it | Decide safe external-browser behavior; validate scheme/URL and require explicit user activation |
| Automatic standard deep scan when opening a device detail page | **Implemented in source / unverified** — bounded parallel common-port scan starts on detail navigation with progress and cancellation | Verify repeated navigation, cancellation, timeouts and runtime behavior |
| Standard deep scan: common ports plus enabled custom ports | **Implemented in source / unverified** — Android common-port list plus enabled persisted custom ports are passed to the bounded per-device scan | Verify exact standard-port parity and ensure the 256-port limit is never exceeded |
| Full TCP port scan (1–65535) with explicit confirmation | **Missing** — current global scan has strict target/probe limits | Design a safe, rate-limited, cancellable full-scan equivalent; explain limits and require explicit confirmation |
| Deep scan results: open ports, service labels, duration, detected OS/confidence | **Missing / partial** — simple conventional labels exist for a small port set; no OS result or detail page | Implement structured result model and conservative, confidence-labelled identification |
| Deep scan idle/scanning/completed/error states and cancellation | **Partial / implemented in source** — scanning, progress, completion, cancellation and bounded banners are present; error/empty states and richer result model remain | Verify UI state transitions and error reporting |

## 4. Network discovery and enrichment

Android references: `NetworkScanner.kt`, `ArpReader.kt`, `DnsLookup.kt`, `NetworkUtils.kt`, `MacVendorLookup.kt`, `PrivilegedNeighborSource.kt`, `Device.kt`.

| Android capability | Linux branch status | Required parity work / constraints |
|---|---|---|
| Network/interface/subnet discovery | **Partial / implemented in source, runtime unverified** | Verify interface selection, prefix, route/gateway and subnet behavior on host and Flatpak |
| ICMP host discovery, latency and TTL | **Missing** | Investigate datagram ping sockets without raw sockets/capabilities; do not substitute TCP connect timing |
| TCP reachability fallback | **Implemented / unverified** | Keep inconclusive timeouts distinct from offline; test cancellation and bounds |
| Read-only ARP/neighbour MAC enrichment | **Partial / unverified** | Verify permissions and correct interface-scoped lookup; do not add privileged fallback |
| mDNS/DNS-SD service discovery | **Implemented / unverified** | Verify protocol coverage, host and Flatpak multicast behavior, parsing, bounds, and service presentation |
| SSDP/UPnP discovery | **Implemented / unverified** | Verify response parsing, bounds and sandbox behavior; treat all advertisements/URLs as untrusted |
| NetBIOS NBSTAT name/workgroup discovery | **Implemented in source; CI/runtime pending** | Bounded UDP NBSTAT query/parser with selected-interface source binding, response-source validation, cancellation, hostname/workgroup merge, and detail presentation; verify on host and in Flatpak |
| Reverse DNS/PTR hostname resolution, including gateway DNS behavior | **Missing** | Implement bounded resolver strategy with clear timeout and privacy behavior |
| MAC vendor/OUI lookup | **Missing** | Audit upstream database source/license/update strategy before bundling; support unknown/randomized MACs |
| Device type classification from hostname/vendor/mDNS/SSDP/NetBIOS/ports | **Missing / partial** — conventional TCP port labels only | Implement explainable heuristic classification with confidence/uncertainty; never present guesses as facts |
| Port-based device heuristics | **Missing** | Audit source rules; implement safe bounded probes and tests, avoid overclaiming device identity |
| Banner collection and service/version hints | **Partial — bounded plain-protocol banner collection** | Initial greeting / HTTP HEAD response is read with a 350 ms timeout and 512-byte cap; no TLS banner support, service-version extraction or OS inference yet |
| Current-device identification | **Partial / implemented in source** — selected interface address is explicitly identified as this device's local IPv4 address; no dedicated device card/badge yet | Add a consistent current-device card/badge and verify multi-interface behavior |
| Device cache/last-seen/first-seen state | **Missing / partial** | Define scan-session and persistence semantics; avoid falsely marking unresponsive devices offline |

## 5. Settings and custom ports

Android references: `SettingsScreen.kt`, `SettingsViewModel.kt`, `CustomPortsScreen.kt`, `CustomPortsViewModel.kt`, `ThemeSegmentedButtons.kt`, `LanguageOptions.kt`, `NeighborSourcePickerSheet.kt`, `AboutDialog.kt`, `PrivacyDialog.kt`.

| Android setting/action | Linux branch status | Remaining work |
|---|---|---|
| Theme mode selection | **Implemented in source / unverified** — system/light/dark persisted and applied through libadwaita StyleManager | Verify restart persistence and GNOME theme integration |
| Dynamic colors | **Android-specific** | Provide a Linux-native theme/accent equivalent where supported; document platform difference |
| Language selection | **Missing** | Add gettext/localization infrastructure and a language preference; document system-language behavior |
| Auto-scan on startup | **Implemented in source / unverified** — opt-in persisted toggle, default off for safety | Verify default-route selection and first-launch behavior |
| Neighbour/MAC source selection and availability/probe feedback | **Missing** | Design safe Linux-native source choices; no privileged source or permission escalation |
| Custom ports list | **Implemented in source / unverified** — persistent add, enable/disable, delete, validation and empty state; enabled ports are included in per-device deep scans | Verify persistence, scan integration, duplicate handling and UI parity |
| About dialog/version | **Partial / source implemented** — information dialog includes product identity and GPL-3.0-only statement | Verify exact app version and full about-window parity |
| Privacy dialog/policy | **Implemented in source / unverified** — describes local-only behavior, explicit scan initiation and untrusted SSDP data | Review every statement against final implementation and verify dialog behavior |
| GitHub project link | **Implemented in source / unverified** — opens the project repository through a user-activated link | Verify launch behavior and accessibility |
| Settings persistence | **Partial / implemented in source** — versioned local INI storage for theme, auto-scan and custom ports; no migration beyond version 1 yet | Verify corruption handling, permissions, atomic replacement and future migrations |
| Custom device names/icons persistence | **Partial / source implemented** — versioned local preferences store name/icon by IPv4 address | Verify on restart and consider MAC-based identity for DHCP changes |

## 6. Quality, security, packaging, and parity verification

| Gate | Current status | Acceptance evidence |
|---|---|---|
| Android source and behavior audit | **Partial** | Complete source-backed feature inventory and inspect every relevant implementation/resource |
| Visual reference set | **Missing** | Capture/review Android home, detail, settings, custom ports, dialogs, and all major states |
| Linux visual parity review | **Missing** | Screen-by-screen comparison with documented differences |
| Automated tests | **Partial** | Unit, parser, model, concurrency, cancellation, failure and preference-store tests; dedicated Linux workflow runs formatting, tests, Clippy, release build, dependency-source generation, metadata validation, Flatpak build and headless launch smoke test; no passing result yet recorded |
| Host runtime validation | **Pending** | Reproducible test report on supported Linux hosts, including CachyOS |
| Flatpak runtime validation | **Pending** | Clean sandbox build/install/run and feature-specific network tests |
| Permission/security audit | **Partial** | Verify no root/sudo, raw sockets, privileged helpers, elevated capabilities, or unnecessary Flatpak permissions |
| Performance/resource audit | **Pending** | Bounded CPU, memory, socket count, responsiveness and cancellation under realistic scans |
| Accessibility and keyboard operation | **Pending** | Keyboard-only navigation, accessible names, focus order, scalable layouts |
| Regression review | **Pending** | Re-run relevant suite after every repair and full suite before release candidate |
| Maintainer acceptance | **Not started** | Only request after major parity gaps and blocking defects are resolved |

## 7. Immediate audit findings (2026-11-11)

The Linux UI currently has a main page containing interface selection, route/neighbour summary, a basic discovered-device list, manual TCP port entry and scan action, optional mDNS, SSDP and NetBIOS actions, separate result lists, and status text. Device rows open a partial evidence-detail page; it automatically runs a bounded common-port scan plus enabled custom ports with progress/cancellation and displays limited service banners. Native Settings and Custom TCP Ports pages now exist, with persisted theme, auto-scan and custom-port preferences. These screens are source implementations only; CI, host, Flatpak and visual verification are still pending. It is a useful technical foundation, but it is **not yet a clone of the Android application**.

The Android source tree clearly defines four primary destinations: Home, Device Detail, Settings, and Custom Ports. The Linux implementation now has native navigation for all four destinations, but Settings and Custom Ports are early source implementations and Device Detail remains partial. The Android home flow also has auto-scan preference, online/offline device grouping, rich device cards, current-device indication, empty states and a scan progress card. The Android detail flow includes automatic per-device deep scanning, full-scan confirmation, device identity/customization, network/protocol evidence and detailed results. Android settings include theme, language, auto-scan, neighbour source, custom ports, about, privacy and project link.

The largest current parity gaps are **home-screen visual/state parity, a dedicated current-device card, language selection, dynamic colors, neighbour-source selection, ICMP reachability/latency/TTL, MAC vendor enrichment, DNS/reverse DNS, device classification/OS inference, and a safe reviewed full-scan equivalent**. Settings, custom-port management and basic per-device name/icon customization now have initial source implementations but still require automated, host, Flatpak and visual verification.

## 8. Verification record

Record each verification run with commit SHA, date, environment, command, result, and logs/artifacts. Keep host and Flatpak results separate.

| Date | Commit | Check | Environment | Result / evidence |
|---|---|---|---|---|
| 2026-11-11 | Initial audit | Android source tree + primary navigation/screens inspected; Linux UI and TCP scanner inspected | GitHub source review | Four Android routes confirmed; major Linux parity gaps documented above. No runtime claim. |\n| 2026-11-11 | `6bcf9fa` | Initial device detail navigation and evidence page added; libadwaita NavigationView enabled | CI run `43092906677` | Pending. Do not treat as build/test verified until CI completes. |



### 2026-11-11 — follow-up implementation

- Added a parallel, bounded single-device deep-scan engine using the Android standard common-port set; progress and cancellation are surfaced in the detail view.
- Added capped, sanitized initial service banners for plain TCP services; TLS endpoints are not probed with plaintext.
- Added bounded NetBIOS NBSTAT query/parser code and merged hostname/workgroup evidence into the device catalog and detail view.
- Added native Settings and Custom TCP Ports pages, versioned local preferences for theme/auto-scan/custom ports, and enabled custom-port integration into device deep scans.
- Added a Linux-specific CI/Flatpak pipeline covering format, tests, Clippy, release build, generated offline Cargo sources, AppStream/desktop validation, Flatpak build, and a headless launch smoke test. Its first successful result has not yet been observed. Host behavior, controlled-network behavior, and visual parity remain unverified.
