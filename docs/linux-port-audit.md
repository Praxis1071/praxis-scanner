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

**No Rust source, GTK UI, Flatpak manifest or executable Linux code has been created.**
