# Praxis Scanner for Linux

This directory contains the native Linux implementation. The Android Kotlin/Gradle application remains in the repository's existing Android project and is not replaced by this port.

## Technology

- Rust 2024 (declared minimum Rust version: 1.92)
- GTK4 and libadwaita
- Flatpak as the planned distribution format
- Linux-only networking implementation

## Security boundary

The application is designed to run as an ordinary user. It does not use root, sudo, raw sockets, setuid helpers, privileged daemons, file capabilities, or elevated Linux capabilities. It does not modify host sysctls.

Network probes start only after the user explicitly selects an eligible interface and initiates the corresponding action. Discovery is scoped to previously discovered devices where practical; the app does not automatically sweep the entire network on launch unless the user opts into the startup setting.

TCP discovery is restricted to private IPv4 and IPv4 link-local interfaces, at most 1024 target addresses, at most 256 unique TCP ports, at most 8192 total connection attempts per scan, at most 32 concurrent workers, and a per-connection timeout no longer than five seconds. The UI currently uses a 450 ms TCP timeout. Cancellation stops scheduling new work and is observed between in-flight connection attempts.

Per-device deep scans use a bounded common-port list plus enabled custom ports, capped by the same 256-port/8192-attempt limits and 32-worker limit. Service banners are conservative hints only: reads are capped at 512 bytes with a 350 ms read timeout, HTTP uses HEAD, TLS ports are not probed with plaintext, and no exploit payloads are sent.

ICMP reachability is optional and uses Linux `SOCK_DGRAM` with `IPPROTO_ICMP` (IPv4 ping sockets) only. It is bound to the selected local IPv4 address and checks the selected IPv4 subnet only, with at most 1024 candidate hosts, at most 32 workers, and a 450 ms default timeout. Availability depends on the kernel `ping_group_range` policy. If the kernel denies the socket, the UI reports the error; there is no raw-socket fallback, privilege escalation, or sysctl modification. A missing echo reply is inconclusive, not proof that a device is offline. TTL extraction is not implemented.

mDNS/DNS-SD is a separate, opt-in action. It sends multicast queries only on the selected interface, disables IPv6, and accepts only IPv4 service addresses in the selected subnet. The scan window is five seconds (maximum ten seconds in the engine), service types are capped at 32, and results at 256. It uses ordinary UDP sockets through `mdns-sd 0.21.7`; no raw sockets or elevated capabilities are involved. The daemon shutdown is awaited with a bounded deadline. mDNS responses are unauthenticated and may be spoofed, so use this feature only on trusted local networks. TXT records are not displayed. The library is still described by its maintainers as beta software.

SSDP/UPnP is another separate, opt-in action. It sends one `M-SEARCH` UDP multicast query (`239.255.255.250:1900`) from the selected IPv4 interface with multicast TTL 1, accepts only unicast responses whose source address is in the selected subnet, and caps the listening window, datagram count, and results. It uses safe `socket2` configuration plus the standard UDP socket API; it does not use raw sockets, broadcast, elevated capabilities, or download the advertised device-description URL. `USN`, `SERVER`, and `LOCATION` values are untrusted network data; the UI displays the location only as text and never follows it.

NetBIOS name discovery is a separate, opt-in action. It queries only previously discovered device addresses, binds UDP source traffic to the selected local IPv4 address, validates response source address/port and packet bounds, and supports cancellation. Returned host/workgroup names are unverified network claims.

No TCP or ICMP response is inconclusive; it is not reported as proof that a device is offline. Conventional TCP service names (SSH, DNS, HTTP, NetBIOS, HTTPS, SMB, and RDP) are hints based only on port numbers, not verified service identities. mDNS, SSDP, and NetBIOS names are also unverified network claims.

## Current implementation status

Source currently includes:

- A GTK4/libadwaita application window with navigation to a device detail page and Settings.
- Read-only IPv4 interface enumeration and explicit interface selection.
- Read-only default IPv4 route and complete ARP-neighbour summaries from procfs.
- Bounded IPv4 subnet calculation.
- Explicit, cancellable TCP-connect discovery with validated custom port lists.
- Conservative TCP response classification and port-number-based service hints.
- Optional, cancellable datagram-only ICMP echo checks with round-trip-time reporting.
- Opt-in, cancellable, interface-scoped IPv4 mDNS/DNS-SD service discovery.
- Opt-in, cancellable SSDP/UPnP M-SEARCH discovery with selected-interface binding and bounded untrusted-response parsing.
- Opt-in, cancellable NetBIOS hostname/workgroup discovery.
- A unified device catalog merging TCP, ICMP, mDNS, SSDP, NetBIOS, and read-only MAC evidence.
- A partial device-detail page with automatic bounded common-port deep scans, progress, cancellation, and capped plain-protocol banners.
- Native Settings and Custom TCP Ports pages.
- Local versioned preferences for theme, opt-in startup scanning, custom TCP ports, and per-device custom names/icons. Device customizations are currently keyed by IPv4 address, so DHCP address changes can require reapplying them.
- A responsive, current-device-first list with numeric IPv4 ordering; it separates TCP/ICMP responders from observations with unknown reachability. A home progress bar reports TCP/ICMP completion and discovery phase states without falsely labelling missing responses as offline.
- Unit tests for CIDR calculations, procfs parsers, port-list parsing, service hints, scan limits, cancellation, loopback TCP behavior, mDNS scope/type validation, SSDP response parsing, NetBIOS packet parsing, preference persistence, device customizations, ICMP packet validation, and deep-scan banner sanitization.

**This remains a development build, not a complete or release-ready network scanner.** The source changes, CI formatting, Rust compilation, strict Clippy, controlled-network behavior, Flatpak build, and sandbox launch have not yet been verified together on the current branch. The Linux CI workflow is configured to run Rust formatting/tests/Clippy/release build, generate offline Cargo sources, validate AppStream/desktop metadata, build the Flatpak, and launch it under a virtual display. The first successful run must be inspected before any build or runtime success is claimed.

The root Flatpak manifest is `io.github.praxis1071.PraxisScanner.yml`. Its offline Cargo vendor configuration is generated in the manifest during the build; the dedicated CI workflow generates `linux/Cargo.lock` and `linux/cargo-sources.json` as build inputs. No successful Flatpak build or runtime launch has yet been confirmed.

## Build prerequisites

Install GTK4 and libadwaita development packages provided by your distribution, plus Rust 1.92 or newer.

From this directory:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --release --locked
cargo run
```

The CI workflow creates and commits the lockfile/offline source manifest only after the Rust checks pass. For a local offline Flatpak build, generate the lockfile and Cargo source manifest first, then use the root Flatpak manifest.

## Next steps

Follow the root [ROADMAP.md](../ROADMAP.md) and [Android/Linux parity matrix](../docs/linux-android-parity-matrix.md). Priority order: inspect the current Linux CI run and fix every failure; complete remaining Android screen/feature parity; verify datagram ICMP permission behavior and discovery on a controlled host network; then validate the Flatpak sandbox, runtime launch, and permissions. Do not treat the application as ready for user testing until those gates pass.
