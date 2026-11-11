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
| `NavGraph.kt` — Settings route | Open settings | **Missing** | Implement settings page |
| `NavGraph.kt` — CustomPorts route | Navigate to custom TCP port management | **Missing** | Implement custom ports page |
| Android expressive navigation/transitions | Clear, consistent screen transitions and back behavior | **Missing / desktop adaptation needed** | Define GTK/libadwaita-native equivalent; verify keyboard and window navigation |

## 2. Home screen and device list

| Android reference | Expected behavior | Linux branch status | Remaining work |
|---|---|---|---|
| `HomeScreen.kt` | Main screen with app title and settings action | **Partial** — title/window and Refresh exist; no settings action | Match home header/actions |
| `HomeScreen.kt` auto-scan preference | Automatically start a scan on launch when enabled (Android default: enabled) | **Missing** — Linux requires explicit scan action | Add persisted auto-scan setting and safe startup behavior |
| `NetworkInfoBar.kt` | Show current network information and selectable interfaces | **Partial** — interface list/selection and route summary exist | Match information fields, selection presentation, unavailable states |
| `DeviceList.kt`, `DeviceCard.kt` | Separate online/offline devices; readable identity/type/IP/status; custom icon; current-device marker | **Partial** — basic unified rows show IP/MAC/TCP/mDNS/SSDP evidence | Add online/offline semantics, device type/name/icon, current-device indication, card/list visual parity |
| `EmptyState.kt` | Distinct idle, no Wi-Fi, and no-results states | **Partial** — status text only | Implement equivalent empty/no-interface/no-result/error states |
| `ScanProgressCard.kt` | Visible progress, phase/message, found-device count, cancel action | **Partial** — scan status/progress and cancellation exist in source; UI needs parity review | Match phases, progress semantics, counters, cancellation feedback |
| Snackbar/error flow in `HomeScreen.kt` | Surface errors and useful recovery guidance | **Partial** — status labels are used | Add consistent error presentation and actionable recovery |
| Online/offline ordering in `MainViewModel.kt` | Current device first, online then offline, numerically ordered IPs | **Missing / partial** | Define and test equivalent ordering and online confidence semantics |

## 3. Device details

Android references: `DeviceDetailScreen.kt`, `DeviceInfoCard.kt`, `DetailSection.kt`, `PortItem.kt`, `DeepScanSection.kt`, `EditDeviceNameDialog.kt`, `EditDeviceIconDialog.kt`.

| Expected behavior | Linux branch status | Remaining work |
|---|---|---|
| Open detail view for a selected device | **Partial — source committed, CI pending** | An initial Adw NavigationView detail page opens from device rows and displays currently collected evidence; complete identity, status, customization, deep-scan workflow, and visual parity remain missing |
| Device header with icon, display name, type, online/offline and current-device badges | **Missing** | Implement visual and semantic equivalent |
| Edit custom device name and restore default | **Missing** | Implement validated name editor and persistence |
| Choose a custom device icon and restore automatic icon | **Missing** | Implement icon chooser, mapping, and persistence |
| Identity/network information (IP, MAC, vendor, hostname, device type) | **Partial** — raw IP/MAC and evidence summary only | Add structured fields and clear unavailable/unknown states |
| Latency and TTL/OS hint | **Missing** — TCP response is not equivalent to ICMP latency/TTL | Implement only if safe Linux method is verified; never mislabel TCP timing as ping latency |
| Discovery method, UPnP metadata, NetBIOS workgroup, mDNS services | **Partial** — mDNS and limited SSDP evidence exist; no NetBIOS | Complete safe parsing and detail presentation |
| Open web interface from SSDP LOCATION | **Not implemented by design** — Linux currently treats LOCATION as untrusted text and does not fetch it | Decide safe external-browser behavior; validate scheme/URL and require explicit user activation |
| Automatic standard deep scan when opening an online device | **Missing** | Implement per-device scan lifecycle, cancellation, and progress |
| Standard deep scan: common ports plus enabled custom ports | **Partial** — current network scan accepts a bounded custom comma-separated list but is not the detail-screen deep scan workflow | Reproduce the Android standard scan's target/port behavior within safe limits |
| Full TCP port scan (1–65535) with explicit confirmation | **Missing** — current global scan has strict target/probe limits | Design a safe, rate-limited, cancellable full-scan equivalent; explain limits and require explicit confirmation |
| Deep scan results: open ports, service labels, duration, detected OS/confidence | **Missing / partial** — simple conventional labels exist for a small port set; no OS result or detail page | Implement structured result model and conservative, confidence-labelled identification |
| Deep scan idle/scanning/completed/error states and cancellation | **Partial — automatic common-port scan added** | Bounded parallel per-device scan now reports port progress, cancellation, port labels, and capped service banners; add error/empty states, richer result model, and full parity review |

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
| NetBIOS NBSTAT name/workgroup discovery | **Implemented in source; CI/runtime pending** | Bounded UDP NBSTAT query/parser with response-source validation, cancellation, hostname/workgroup merge, and detail presentation; verify on host and in Flatpak |
| Reverse DNS/PTR hostname resolution, including gateway DNS behavior | **Missing** | Implement bounded resolver strategy with clear timeout and privacy behavior |
| MAC vendor/OUI lookup | **Missing** | Audit upstream database source/license/update strategy before bundling; support unknown/randomized MACs |
| Device type classification from hostname/vendor/mDNS/SSDP/NetBIOS/ports | **Missing / partial** — conventional TCP port labels only | Implement explainable heuristic classification with confidence/uncertainty; never present guesses as facts |
| Port-based device heuristics | **Missing** | Audit source rules; implement safe bounded probes and tests, avoid overclaiming device identity |
| Banner collection and service/version hints | **Partial — bounded plain-protocol banner collection** | Initial greeting / HTTP HEAD response is read with a 350 ms timeout and 512-byte cap; no TLS banner support, service-version extraction or OS inference yet |
| Current-device identification | **Missing** | Identify local interface address safely and mark it consistently |
| Device cache/last-seen/first-seen state | **Missing / partial** | Define scan-session and persistence semantics; avoid falsely marking unresponsive devices offline |

## 5. Settings and custom ports

Android references: `SettingsScreen.kt`, `SettingsViewModel.kt`, `CustomPortsScreen.kt`, `CustomPortsViewModel.kt`, `ThemeSegmentedButtons.kt`, `LanguageOptions.kt`, `NeighborSourcePickerSheet.kt`, `AboutDialog.kt`, `PrivacyDialog.kt`.

| Android setting/action | Linux branch status | Remaining work |
|---|---|---|
| Theme mode selection | **Missing** | Add system/light/dark preference using libadwaita conventions |
| Dynamic colors | **Android-specific** | Provide a Linux-native theme/accent equivalent where supported; document platform difference |
| Language selection | **Missing** | Add localization infrastructure and language preference |
| Auto-scan on startup | **Missing** | Add persistent toggle and test startup behavior |
| Neighbour/MAC source selection and availability/probe feedback | **Missing** | Design safe Linux-native source choices; no privileged source or permission escalation |
| Custom ports list | **Partial** — one transient comma-separated scan entry | Add persistent records, service labels, enabled toggle, delete, add dialog, validation and empty state |
| About dialog/version | **Missing** | Add app/version/license information |
| Privacy dialog/policy | **Missing** | Add accurate privacy information consistent with actual network behavior |
| GitHub project link | **Missing** | Add verified repository link |
| Settings persistence | **Missing** | Implement versioned, migration-aware user preferences |
| Custom device names/icons persistence | **Missing** | Implement versioned persistence and stable identity strategy |

## 6. Quality, security, packaging, and parity verification

| Gate | Current status | Acceptance evidence |
|---|---|---|
| Android source and behavior audit | **Partial** | Complete source-backed feature inventory and inspect every relevant implementation/resource |
| Visual reference set | **Missing** | Capture/review Android home, detail, settings, custom ports, dialogs, and all major states |
| Linux visual parity review | **Missing** | Screen-by-screen comparison with documented differences |
| Automated tests | **Partial** | Unit, parser, model, concurrency, cancellation, failure and UI/state tests |
| Host runtime validation | **Pending** | Reproducible test report on supported Linux hosts, including CachyOS |
| Flatpak runtime validation | **Pending** | Clean sandbox build/install/run and feature-specific network tests |
| Permission/security audit | **Partial** | Verify no root/sudo, raw sockets, privileged helpers, elevated capabilities, or unnecessary Flatpak permissions |
| Performance/resource audit | **Pending** | Bounded CPU, memory, socket count, responsiveness and cancellation under realistic scans |
| Accessibility and keyboard operation | **Pending** | Keyboard-only navigation, accessible names, focus order, scalable layouts |
| Regression review | **Pending** | Re-run relevant suite after every repair and full suite before release candidate |
| Maintainer acceptance | **Not started** | Only request after major parity gaps and blocking defects are resolved |

## 7. Immediate audit findings (2026-11-11)

The Linux UI currently has a main page containing interface selection, route/neighbour summary, a basic discovered-device list, manual TCP port entry and scan action, optional mDNS, SSDP and NetBIOS actions, separate result lists, and status text. Device rows open a partial evidence-detail page; it automatically runs a bounded common-port scan with progress/cancellation and displays limited service banners. CI/runtime verification is pending. It is a useful technical foundation, but it is **not yet a clone of the Android application**.

The Android source tree clearly defines four primary destinations: Home, Device Detail, Settings, and Custom Ports. The Linux implementation currently lacks the latter three. The Android home flow also has auto-scan preference, online/offline device grouping, rich device cards, current-device indication, empty states and a scan progress card. The Android detail flow includes automatic per-device deep scanning, full-scan confirmation, device identity/customization, network/protocol evidence and detailed results. Android settings include theme, language, auto-scan, neighbour source, custom ports, about, privacy and project link.

The largest current parity gaps are therefore **navigation/screens, full device identity and detail parity, persistent preferences/customizations, custom-port management, ICMP reachability/latency/TTL, MAC vendor enrichment, DNS/reverse DNS, device classification/OS inference, and the home screen's visual/state behavior**. The next implementation milestone must start with a complete visual/source reference audit and architecture for these screens, not add unrelated discovery features ahead of core product parity.

## 8. Verification record

Record each verification run with commit SHA, date, environment, command, result, and logs/artifacts. Keep host and Flatpak results separate.

| Date | Commit | Check | Environment | Result / evidence |
|---|---|---|---|---|
| 2026-11-11 | Initial audit | Android source tree + primary navigation/screens inspected; Linux UI and TCP scanner inspected | GitHub source review | Four Android routes confirmed; major Linux parity gaps documented above. No runtime claim. |\n| 2026-11-11 | `6bcf9fa` | Initial device detail navigation and evidence page added; libadwaita NavigationView enabled | CI run `43092906677` | Pending. Do not treat as build/test verified until CI completes. |



### 2026-11-11 — follow-up implementation

- Added a parallel, bounded single-device deep-scan engine using the Android standard common-port set; progress and cancellation are surfaced in the detail view.
- Added capped, sanitized initial service banners for plain TCP services; TLS endpoints are not probed with plaintext.
- Added bounded NetBIOS NBSTAT query/parser code and merged hostname/workgroup evidence into the device catalog and detail view.
- Automated parser/engine tests are present in source. CI, host behavior, Flatpak behavior, and visual parity are still unverified.
