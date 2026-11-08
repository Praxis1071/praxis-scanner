# Linux Port — Android Source Audit

> **Scope:** Static source audit of the Android implementation on `main`, performed for the Linux port planning branch.
>
> **Status:** Initial source audit completed. No Linux implementation has been started. Runtime feasibility and Flatpak behavior remain unverified.

## 1. Existing Android scan lifecycle

The Android scanner currently runs this sequence:

1. Read the selected interface's IPv4 address, prefix, and Wi-Fi metadata.
2. Add the current Android device to the result set.
3. Probe the gateway and read the existing neighbor/ARP cache.
4. Sweep the calculated IPv4 range using ICMP ping with TCP-connect fallback.
5. Re-read neighbor data and enrich discovered hosts with MAC/OUI information.
6. Discover DNS-SD/mDNS services.
7. Discover SSDP/UPnP devices and retrieve their device-description XML.
8. Query NetBIOS NBSTAT for hostnames and workgroups.
9. Resolve hostnames, including reverse PTR queries against the gateway DNS server.
10. Apply TCP-port and other heuristics to classify devices.
11. Publish the completed device list and scan status.

The deep-scan path is separate: TCP port connection checks, banner collection, service/version hints, and best-effort OS-family detection.

The Linux implementation should preserve the useful workflow, not the Android-specific implementation details.

## 2. Android source responsibilities

| Android source area | Current responsibility | Linux-port direction |
| --- | --- | --- |
| `network/NetworkScanner.kt` | Scan orchestration, reachability, mDNS, SSDP, NetBIOS, DNS, port scans, banners, heuristics, progress | Split into orchestration and independently testable protocol modules |
| `util/NetworkUtils.kt` | Interface enumeration, IPv4/prefix calculation, ping/TCP fallback, hostname lookup, MAC bit checks | Replace Android APIs and shell ping invocation with Linux networking APIs |
| `util/ArpReader.kt` | Reads `/proc/net/arp` and invokes `ip neigh`; parses and caches entries | Prefer read-only rtnetlink neighbor-table dump; no shell dependency |
| `util/PrivilegedNeighborSource.kt` | Shizuku/root access to neighbor entries | Do not port; violates the non-negotiable privilege policy |
| `util/DnsLookup.kt` | Minimal UDP DNS PTR client | Reuse the protocol behavior only after parser tests and bounded-response handling |
| `util/MacVendorLookup.kt` and `assets/oui_vendors.txt` | OUI lookup and bundled vendor data | Keep optional until the data source's redistribution terms are confirmed |
| `data/*` | Device, scan, port, OS, protocol and progress models | Define platform-neutral Rust domain models |
| `data/repository/*` | JSON-serialized custom ports and device customizations in Android preferences | Use an XDG-compliant local persistence layer with versioned schema |
| `ui/*` | Home, device list/details, deep scan, settings and dialogs | Rebuild as desktop-native GTK4/libadwaita views |
| `NetworkScannerApp.kt` | Android application-level dependency ownership and initialization | Replace with explicit Rust application state and service construction |

The Android project also contains Android manifest permissions, Android lifecycle/ViewModels, Jetpack Compose/Material components, Android NSD APIs, Wi-Fi APIs and Shizuku AIDL/service code. These are platform-specific and must not be copied into the Linux core.

## 3. Discovery and inspection behavior

### Host discovery and network context

- The current IPv4 sweep is derived from the interface prefix, not hard-coded to /24.
- It sweeps up to 1,024 usable addresses; wider networks fall back to the local /24.
- /31 and /32 are treated as a single-host range.
- The current reachability check tries ping first, then parallel TCP connects to a small set of common ports.
- A failed ping and failed TCP probes do not prove that a host is offline; firewalls and filtered ports can hide live devices.
- The Android implementation's ping path invokes `/system/bin/ping`. This is not portable and must not be retained in the Linux application.

### Neighbor table and MAC addresses

- The Android implementation reads `/proc/net/arp` and runs `ip neigh show`.
- It can optionally use Shizuku or root because recent Android versions restrict visibility into neighbor entries.
- Linux exposes neighbor-table retrieval through rtnetlink's `RTM_GETNEIGH` operation. A read-only dump is the preferred candidate, but ordinary-user access and Flatpak behavior must be tested on target systems.
- Neighbor data is cache data, not a complete inventory of every host. Entries may be absent until traffic causes neighbor resolution.
- Do not infer that every discovered IP has a known MAC address.
- A locally administered MAC bit is not definitive proof of randomized addressing; present it as a hint only.

### mDNS / DNS-SD

The Android implementation asks for multiple service types, including workstation, SMB, AirPlay, RAOP, Google Cast, printers, SSH/SFTP, HomeKit and Matter. It resolves service instances and merges multiple services for the same host.

Linux candidate: DNS-SD over UDP multicast. The exact library or implementation should be selected during dependency research. Multicast availability, interface selection, IPv4/IPv6 behavior and Flatpak operation need integration tests.

### SSDP / UPnP

The Android implementation sends an SSDP M-SEARCH request to `239.255.255.250:1900`, parses responses, then fetches a device-description XML document.

Linux candidate: ordinary UDP multicast sockets plus a bounded HTTP client. Treat all responses and description URLs as untrusted input: enforce strict timeouts and response-size limits, disable unsafe XML entity processing, validate URL schemes and destinations, and never allow a device response to turn the scanner into an unrestricted URL fetcher.

### NetBIOS and reverse DNS

- NetBIOS uses a UDP NBSTAT query to port 137 and parses host/workgroup names.
- Reverse DNS uses a UDP PTR query, preferring the gateway's DNS service when available.
- Both are optional enrichment methods; silence or filtering must not fail the overall scan.
- Hostnames and protocol fields must be length-limited and validated before display or persistence.

### Port scanning and fingerprinting

- Reachability fallback uses TCP connect attempts; this does not require raw sockets.
- Deep scanning uses TCP connect checks, then attempts bounded banner reads.
- The current Android defaults use a curated common-port list; its full scan can cover all 65,535 TCP ports.
- Current Android concurrency settings are 20 workers for the common-port scan, 128 for the full scan and 10 for banner collection. These are reference values, not Linux defaults.
- Linux should use bounded work queues, per-attempt timeouts, cancellation, global/per-host limits and conservative defaults. Full-port scans should be explicitly opt-in and warn about duration and network impact.
- Service/version and OS identification are heuristics. Results must include confidence or clearly communicate uncertainty; a TCP-only scan cannot promise reliable OS identification.

## 4. Feature parity and Linux feasibility

| Android capability | Linux candidate | Preliminary decision | Verification still required |
| --- | --- | --- | --- |
| Select Wi-Fi/Ethernet/VPN interface | Enumerate interfaces and addresses through Linux APIs/netlink | **Keep** | Confirm route, prefix, interface selection and sandbox visibility |
| Show local IP and subnet | Interface address and prefix data | **Keep** | IPv4/IPv6 scope and Flatpak tests |
| Show Wi-Fi SSID/BSSID/signal | No portable generic API identified that fits the minimal-permission policy | **Omit initially** | Revisit only if a narrow, safe desktop API exists |
| Add current computer | Local interface address and hostname | **Keep** | Multiple addresses and selected-interface behavior |
| ICMP reachability | ICMP datagram/ping socket where kernel policy permits | **Conditional** | `ping_group_range`, kernel and sandbox behavior |
| TCP reachability fallback | Normal TCP connect sockets | **Keep** | Timeouts, rate limits and false-negative messaging |
| ARP/neighbor enrichment | Read-only rtnetlink `RTM_GETNEIGH` dump | **Conditional** | Ordinary-user and Flatpak tests; entries are cache-dependent |
| mDNS / Bonjour | DNS-SD over multicast UDP | **Keep if verified** | Multicast, interface binding, IPv4/IPv6 and sandbox tests |
| SSDP / UPnP | UDP multicast M-SEARCH and bounded description retrieval | **Keep if verified** | Multicast, response parsing, URL and XML safety |
| NetBIOS names/workgroups | UDP NBSTAT | **Optional** | Real-device interoperability and timeout behavior |
| Gateway reverse DNS | UDP PTR query | **Optional** | DNS availability and parser robustness |
| MAC vendor lookup | Local OUI database | **Conditional** | IEEE public-listing redistribution terms and update policy |
| Device category | Service, hostname, vendor and port heuristics | **Keep as hints** | False-positive tests and confidence labeling |
| OS identification | Conservative banner/port heuristics | **Limited** | Must never be represented as definitive |
| Common TCP port scan | TCP connect | **Keep** | Bounded concurrency and safe defaults |
| Full 65,535 TCP scan | TCP connect | **Optional opt-in** | User warning, cancellation and resource/network impact |
| Banner and version hints | Protocol-aware bounded TCP reads | **Keep where safe** | TLS handling, response caps and parser tests |
| Rename devices / assign icons | Local persistence keyed by stable identity | **Keep** | Identity changes, duplicate MACs and migration tests |
| Configure custom ports | Local versioned settings | **Keep** | Input validation and duplicate handling |
| Shizuku/root neighbor access | No Linux equivalent allowed under project policy | **Remove** | Must not reappear as a helper or privileged fallback |
| Android permissions and Wi-Fi multicast lock | Not applicable to Linux | **Remove** | Flatpak permission model replaces Android permissions |

## 5. Desktop UX mapping

The Android README identifies six reference screenshots: main screen, device list, device details, open ports, custom icon selection and settings. The source tree additionally contains custom-port management, edit-name/icon dialogs, progress and empty states, privacy/about screens, and interface/neighbor-source settings.

Desktop UX should preserve these information tasks, not reproduce phone layouts:

- Main window: selected interface/network summary, scan controls, progress and discovered-device list.
- Device list: searchable/filterable list with clear online/offline and confidence states.
- Device details: identifiers, discovery evidence, service information, ports and customization.
- Deep scan: explicit start, progress, cancellation, common/full scan choice and warnings.
- Settings: interface behavior, scan limits, custom ports, theme and language where supported.
- Remove Android-only settings: Shizuku/root neighbor-source picker, Android permission prompts, Wi-Fi-only details and mobile haptics.

A screen-by-screen desktop wireframe review remains outstanding before UI implementation.

## 6. Unprivileged networking and sandbox research

### ICMP

Linux supports ICMP datagram ("ping") sockets, but their availability is controlled by the `net.ipv4.ping_group_range` sysctl. The kernel documentation describes `1 0` as the default range that allows nobody to create ping sockets. Therefore, ICMP cannot be a guaranteed feature across all target systems. It must be probed at runtime and treated as optional; TCP fallback remains the baseline. Never add `CAP_NET_RAW`, setuid, or a privileged helper to make it work.

### Neighbor table

The kernel's rtnetlink specification defines `RTM_GETNEIGH` for retrieving or dumping neighbor entries, distinct from add/delete operations. This is a promising read-only path. The project must still test access as an ordinary user and inside the final Flatpak sandbox before advertising it.

### Flatpak

Flatpak denies network access by default. A network scanner needs `--share=network` to open network sockets. This is a broad network permission and must be explained to users; it is not a reason to request host filesystem access, all devices, system D-Bus, or elevated capabilities. Multicast and broadcast behavior must be tested in the actual packaged sandbox.

### Official references

- Linux kernel IP sysctl documentation: https://docs.kernel.org/networking/ip-sysctl.html
- Linux ping manual: https://man7.org/linux/man-pages/man8/ping.8.html
- Linux rtnetlink manual: https://man7.org/linux/man-pages/man7/rtnetlink.7.html
- Linux kernel neighbor netlink specification: https://www.kernel.org/doc/html/next/networking/netlink_spec/rt-neigh.html
- Flatpak sandbox permissions: https://docs.flatpak.org/en/latest/sandbox-permissions.html
- gtk-rs Rust GTK4 bindings: https://gtk-rs.org/gtk4-rs/stable/latest/book/

## 7. Security, privacy and licensing gates

- Never invoke `sudo`, `su`, privileged helpers, setuid executables or file capabilities.
- Never request `CAP_NET_RAW` or `CAP_NET_ADMIN`.
- Never modify the host's sysctls or neighbor table.
- Use only read-only host/network information and ordinary sockets.
- Keep discovery traffic bounded and cancellable; do not turn the application into an unrestricted scanner.
- Parse all network responses as untrusted input. Apply size limits, timeouts and strict parsing.
- No telemetry or external service calls. Any bundled vendor database must have a documented, reviewed redistribution basis.
- Preserve GPL-3.0 and upstream notices. Mark adapted files and changes clearly.

The existing OUI update script downloads the IEEE MA-L public listing and transforms it into a local text database. The public listing's availability does not by itself establish a redistribution license. Do not carry the existing bundled database into the Linux distribution until its applicable terms are confirmed or a clearly licensed alternative is selected.

## 8. Audit outcome

The Android workflow and major implementation responsibilities are now mapped. The Linux port has several strong unprivileged candidates: TCP connect scanning, local interface inspection, DNS PTR, UDP-based discovery protocols and a read-only neighbor-table query. ICMP and neighbor-table access are conditional and must be proven in the target environment.

The following items remain open before the source-audit phase can be fully closed:

1. Review the screenshot images visually and approve desktop wireframes.
2. Confirm the OUI database's redistribution terms or choose a licensed alternative.
3. Complete the experimental Linux/Flatpak feasibility matrix.
4. Finalize the Rust dependency and architecture design.

**Implementation update (2026-11-08):** an initial Rust/GTK4/libadwaita application shell and read-only IPv4 interface enumerator have now been added under `linux/`. This foundation has not yet been compiled or run on the maintainer's host. No production scanning engine or Flatpak manifest has been approved or completed.


## 9. Preliminary Rust ecosystem research (not a dependency lock)

The following crates are research candidates only. No dependency has been added to the repository, and none is approved for implementation yet.

| Area | Candidate | What the current documentation indicates | Decision |
| --- | --- | --- | --- |
| Linux interfaces, routes and neighbors | `rtnetlink` (latest docs currently show 0.24.x) | Rust netlink API for links, addresses, neighbor/ARP and routes; MIT-licensed upstream | Strong candidate for read-only interface/route/neighbor queries. Wrap only GET/dump operations; do not expose mutation APIs to the scanner core. |
| mDNS / DNS-SD | `mdns-sd` (0.21.7) | Maintained DNS-SD library; uses a dedicated daemon thread and flume channels, so it is not tied to a particular async runtime; Apache-2.0 OR MIT | Strong candidate. Test interface selection, multicast behavior, shutdown and sandbox operation. |
| SSDP / UPnP | `ssdp-client` (2.1.0) | Async SSDP discovery API using Tokio; Apache-2.0 OR MIT | Candidate for discovery only. Device-description fetching and XML parsing still need a separate hardened design. |
| ICMPv4 | `icmp-socket2` (0.6.4) or direct `socket2` use | Exposes a datagram ICMPv4 socket as well as a separate raw-socket type; datagram operation depends on the kernel's `ping_group_range` | Conditional candidate. Only the datagram path may be considered. Never use the raw-socket implementation or add capabilities. |
| GTK4 / GNOME desktop | `gtk4` + `libadwaita` from gtk-rs | Official Rust bindings and GNOME HIG widgets; GTK objects are not thread-safe and must stay on the GTK main thread | Confirmed technology direction. Keep all scan/network work away from GTK objects and deliver state changes to the main context. |

### Runtime and integration implications

- `rtnetlink`'s common configuration uses Tokio; `ssdp-client` also uses Tokio. This makes Tokio a plausible scan-engine runtime, but it is not yet a final decision.
- `mdns-sd` owns its own daemon thread and communicates through channels; it does not require the scanner to adopt its runtime.
- GTK/GLib owns the UI main loop. GTK widgets must only be accessed from that main thread. If the scanner uses a separate Tokio runtime, the boundary must be explicit and use channels or main-context dispatch.
- Do not run blocking socket operations, large scans, XML parsing or persistence work on the GTK main thread.
- Pin compatible crate versions only after a minimal proof-of-concept has built against the selected Flatpak runtime and the complete dependency tree has passed license and security review.

### Research links

- `rtnetlink`: https://docs.rs/rtnetlink/latest/rtnetlink/
- `mdns-sd`: https://docs.rs/mdns-sd/latest/mdns_sd/
- `ssdp-client`: https://docs.rs/ssdp-client/latest/ssdp_client/
- `icmp-socket2`: https://docs.rs/icmp-socket2/latest/icmp_socket2/
- `socket2`: https://docs.rs/socket2/latest/socket2/
- gtk-rs main-loop and async integration: https://gtk-rs.org/gtk4-rs/stable/latest/book/main_event_loop.html

**Dependency decision:** deferred. API suitability, transitive dependency count, security advisories, exact license metadata, platform compatibility, and behavior in Flatpak must all be reviewed before implementation.


## 10. Updated ecosystem and sandbox review (2026-11-05)

This section records a fresh documentation review. These findings refine the candidate list; they do **not** count as host/Flatpak runtime test results and do not approve production dependencies.

### Important ICMP library safety finding

- The Linux kernel documents `net.ipv4.ping_group_range` as the group-ID range allowed to create ICMP datagram sockets. The documented default `1 0` permits nobody. This setting must be observed, never modified by Praxis Scanner.
- `icmp-socket2` exposes a distinct `DgramIcmpSocket4` (`SOCK_DGRAM`) type and a separate raw `IcmpSocket4` type. If ICMP is implemented, the code must instantiate only the datagram type and return an unavailable/permission-denied result if it cannot be created.
- **Do not adopt `ping-tokio` without a strict audit/configuration:** its current documentation says it tries an unprivileged datagram socket first but automatically falls back to a raw socket when denied. That fallback conflicts with this project's non-negotiable policy. The same concern applies to any library that silently changes socket type or asks for capabilities.
- A successful call to the system `ping` command is not proof that the application's exact datagram-socket path is available. The Rust proof of concept must directly test the datagram socket.

### rtnetlink read-only boundary

- The kernel's rtnetlink implementation distinguishes GET requests/dumps from mutating operations and applies a generic `CAP_NET_ADMIN` check to non-GET operations. This supports investigating read-only `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, and `RTM_GETNEIGH` operations.
- This is not a blanket guarantee: operation-specific checks, network namespaces, sandboxing and distribution behavior still need tests. Keep the scanner API read-only and do not expose add/delete/set requests.
- Neighbor entries remain cache observations. Preserve their interface index and NUD state; never label STALE, INCOMPLETE or FAILED entries as confirmed live devices.

### Current Rust/GTK candidate documentation

- Current documentation snapshots surfaced `rtnetlink` 0.24.0, `mdns-sd` 0.21.7, `icmp-socket2` 0.6.4, `gtk4` 0.11.5 and `libadwaita` 0.9.2. However, the rust-netlink GitHub release page still identifies v0.23.0 as its latest tagged release. Treat the apparent 0.24.0 docs.rs version as unconfirmed until the crates.io index and `cargo info rtnetlink` agree. These are research snapshots, not pinned dependency choices. Re-check exact versions, MSRV, system-library requirements, transitive licenses and security advisories at implementation time.
- `mdns-sd` documents itself as beta software and runs its daemon on a dedicated thread with flume channels. It remains a candidate, but lifecycle, interface selection, shutdown and resource limits need explicit tests.
- `ssdp-client` 2.1.0 remains a discovery candidate using Tokio. Its presence on docs.rs is not sufficient evidence of maintenance quality or production suitability. Review recent upstream activity, open issues, parser behavior, and whether a small audited in-house M-SEARCH implementation would be safer and simpler.
- gtk-rs documents GTK objects as not `Send`/`Sync` and GTK calls from other threads as invalid. Keep every GTK object on the main thread. The network engine may use worker tasks, but must communicate using owned, thread-safe domain messages and main-context dispatch.

### Flatpak permission security nuance

- Flatpak's official permissions documentation confirms network access is denied by default and `--share=network` grants network access.
- The same documentation warns that sharing the host network namespace also exposes host abstract Unix-domain sockets to the sandbox. Treat this as a meaningful security trade-off, not a harmless checkbox. The application still needs network access for its core purpose, but must request no unrelated host filesystem, system D-Bus, device, or capability permissions; document the permission and test its actual effective sandbox.
- Flathub's current requirements emphasize keeping static permissions to an absolute minimum and using portals where they fit. A network-scanning use case has no obvious portal substitute for raw local-network socket discovery, but the manifest must still be minimal and justified.

### Sources reviewed

- Linux kernel IP sysctl (`ping_group_range`): https://kernel.org/doc/html/latest/networking/ip-sysctl.html
- `icmp-socket2` datagram and raw socket API: https://docs.rs/icmp-socket2/latest/icmp_socket2/socket/index.html
- `ping-tokio` permission behavior and automatic raw fallback: https://docs.rs/ping-tokio/latest/ping_tokio/
- Linux rtnetlink manual: https://man7.org/linux/man-pages/man7/rtnetlink.7.html
- Linux kernel rtnetlink implementation: https://github.com/torvalds/linux/blob/master/net/core/rtnetlink.c
- Linux kernel neighbor netlink specification: https://docs.kernel.org/next/networking/netlink_spec/rt-neigh.html
- `rtnetlink`: https://docs.rs/rtnetlink/latest/rtnetlink/
- `mdns-sd`: https://docs.rs/mdns-sd/latest/mdns_sd/
- `ssdp-client`: https://docs.rs/ssdp-client/latest/ssdp_client/
- gtk-rs GTK4 thread-safety and MSRV notes: https://docs.rs/gtk4/latest/gtk4/
- Rust libadwaita bindings: https://docs.rs/libadwaita/latest/libadwaita/
- Official Flatpak sandbox permissions: https://docs.flatpak.org/en/latest/sandbox-permissions.html
- Flathub application requirements: https://docs.flathub.org/docs/for-app-authors/requirements

**Updated research conclusion:** TCP connect remains the dependable baseline. ICMP is optional and must use an explicitly datagram-only path. Read-only rtnetlink is promising but unverified in the target environment. Flatpak network sharing is likely necessary but has a documented abstract-socket exposure trade-off. No production dependency has been selected or added.


## 11. Runtime lifecycle and dependency-source cross-check (2026-11-05)

This review adds a source-of-truth check for the Flatpak runtime and resolves a version discrepancy found during dependency research.

### Flatpak / Freedesktop runtime lifecycle

The Freedesktop SDK release timeline currently lists:

- **26.08** — supported until September 2028.
- **25.08** — supported until September 2027.
- **24.08** — reached end of life in September 2026.

For a project being developed in November 2026, do not select 24.08 as the new baseline. 26.08 is the longest-lived current candidate; 25.08 remains a supported compatibility candidate. The final choice must still be checked against the matching GNOME runtime/SDK, GTK4 and libadwaita versions, Rust toolchain availability, and Flathub build requirements. Do not infer that the Freedesktop runtime lifecycle automatically establishes the GNOME runtime lifecycle.

### rtnetlink version discrepancy

The current docs.rs documentation view displays `rtnetlink` 0.24.0, while the upstream `rust-netlink/rtnetlink` GitHub releases page identifies 0.23.0 as its latest tagged release (2026-08-18). This is a source discrepancy, not a reason to guess or pin 0.24.0.

**Decision:** keep rtnetlink as an unapproved candidate. Before adding it, verify the published crates.io version and exact dependency graph using the Cargo registry (for example, `cargo info rtnetlink` and `cargo tree` after creating an isolated POC). Record the resolved version and lockfile, then audit every transitive dependency. The application must expose only read/dump operations even if the crate also provides mutation APIs.

### mDNS-SD maintenance signal

The upstream `mdns-sd` changelog records version 0.21.7 as a bug-fix release on 2026-11-01, with fixes during late October and CI modernization. This is evidence of recent maintenance, improving confidence that the project is active. It does not replace our own review of its daemon-thread lifecycle, interface selection, bounded resource use, multicast behavior, cancellation/shutdown, dependency licenses, or Flatpak behavior.

### Sources reviewed

- Freedesktop SDK release lifecycle: https://freedesktop-sdk.gitlab.io/documentation/wiki/Releases.html
- rtnetlink upstream releases: https://github.com/rust-netlink/rtnetlink/releases
- rtnetlink docs.rs version view: https://docs.rs/rtnetlink/latest/rtnetlink/
- mdns-sd upstream changelog: https://github.com/keepsimple1/mdns-sd/blob/main/CHANGELOG.md

**Conclusion:** use a currently supported Flatpak runtime (26.08 preferred for lifecycle, subject to GNOME runtime compatibility); do not treat docs.rs' apparent rtnetlink 0.24.0 as a confirmed published release; and retain mdns-sd only as a candidate pending isolated runtime and sandbox tests.


## 12. GNOME runtime selection for the Linux application (2026-11-08)

The GNOME release calendar identifies **GNOME 51 as the current stable series** (released 2026-09-16; GNOME 51.1 stable point release listed for 2026-10-10). The GNOME build metadata documents the matching Flatpak runtime naming convention as `org.gnome.Platform//51` and `org.gnome.Sdk//51`.

This is distinct from the generic Freedesktop SDK lifecycle reviewed in section 11. Do not choose `org.freedesktop.Platform//26.08` and `org.gnome.Platform//51` interchangeably: the app uses GTK4/libadwaita, so the GNOME runtime is the more direct packaging candidate.

**Current packaging candidate:** `org.gnome.Platform//51` with the matching `org.gnome.Sdk//51`. This is a candidate, not a finalized manifest. Before release, confirm that the exact runtime is available from the intended remote, that the Rust bindings build against its GTK/libadwaita ABI, and that the resulting Flatpak runs with only the required network permission.

The initial Cargo manifest uses GTK4 0.11.5 and libadwaita 0.9.2. The GTK4 binding documentation lists Rust 1.83 as its current minimum; the project currently declares Rust 1.85. The exact transitive graph and system-library compatibility still require CI and Flatpak build verification.

### Sources reviewed

- GNOME release calendar: https://release.gnome.org/calendar/
- GNOME published Flatpak build outputs: https://gnome.pages.gitlab.gnome.org/gnome-build-meta/docs/ci-outputs.html
- gtk4 0.11.5 documentation and MSRV: https://docs.rs/gtk4/latest/gtk4/
- libadwaita 0.9.2 package metadata: https://docs.rs/crate/libadwaita/latest

**Decision:** prefer GNOME 51 runtime/SDK for the first GTK4/libadwaita Flatpak build, pending an actual build and sandbox test. Keep this separate from the generic Freedesktop runtime lifecycle note above.
