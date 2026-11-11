# Praxis Scanner for Linux

This directory contains the native Linux implementation. The Android application remains in the repository's existing Android/Gradle project and is not replaced by this port.

## Technology

- Rust 2024
- GTK4 and libadwaita
- Flatpak as the planned distribution format

## Security boundary

The application is designed to run as an ordinary user. It does not use root, sudo, raw sockets, setuid helpers, privileged daemons, file capabilities, or elevated Linux capabilities. It reads local IPv4 interface, route, and ARP-neighbour information. Network probes start only after the user explicitly selects an eligible interface and starts a scan.

TCP discovery is restricted to private IPv4 and IPv4 link-local interfaces, at most 1024 target addresses, at most 256 unique TCP ports, at most 8192 total connection attempts per scan, at most 32 concurrent workers, and a per-connection timeout no longer than five seconds. The UI currently uses a 450 ms TCP timeout. Cancellation stops scheduling new work and is observed between in-flight connection attempts.

mDNS/DNS-SD is a separate, opt-in action. It sends multicast queries only on the selected interface, disables IPv6, and accepts only IPv4 service addresses in the selected subnet. The scan window is five seconds (maximum ten seconds in the engine), service types are capped at 32, and results at 256. It uses ordinary UDP sockets through `mdns-sd 0.21.7`; no raw sockets or elevated capabilities are involved. The daemon shutdown is awaited with a bounded deadline. mDNS responses are unauthenticated and may be spoofed, so use this feature only on trusted local networks. TXT records are not displayed. The library is still described by its maintainers as beta software.

No TCP response is inconclusive; it is not reported as proof that a device is offline. Conventional TCP service names (SSH, DNS, HTTP, NetBIOS, HTTPS, SMB, and RDP) are hints based only on port numbers, not verified service identities. mDNS service names and hostnames are also unverified network claims.

## Current implementation status

Source currently includes:

- A GTK4/libadwaita application window.
- Read-only IPv4 interface enumeration and explicit interface selection.
- Read-only default IPv4 route and complete ARP-neighbour summaries from procfs.
- Bounded IPv4 subnet calculation.
- Explicit, cancellable TCP-connect discovery with validated custom port lists.
- Conservative TCP response classification and port-number-based service hints.
- Opt-in, cancellable, interface-scoped IPv4 mDNS/DNS-SD service discovery.
- Bounded background worker threads and UI progress/result reporting.
- Unit tests for CIDR calculations, procfs parsers, port-list parsing, service hints, scan limits, cancellation, loopback TCP behavior, mDNS service-type validation, interface-name validation, and mDNS scope validation.

**This remains a development build, not a complete or release-ready network scanner.** The full CI pipeline (formatting, tests, Clippy, and release build) passed on commit `b6d808a`. Subsequent mDNS scope/metadata tests, UI wording, and daemon-shutdown lifecycle refinements are awaiting their own CI run. No controlled-network test or Flatpak runtime test has been completed. SSDP/UPnP, NetBIOS, reverse DNS, banners, richer device details, persistence/preferences, and Flatpak packaging remain outstanding.

## Build prerequisites

Install GTK4 and libadwaita development packages provided by your distribution, plus a Rust toolchain compatible with Rust 1.85 or newer.

From this directory:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
cargo run
```

A committed Cargo.lock and a verified offline Flatpak dependency source bundle are still required before reproducible packaging can be claimed.

## Next steps

Follow the root [ROADMAP.md](../ROADMAP.md). Priority order: validate the latest mDNS lifecycle changes in CI; run controlled TCP and multicast tests on the host; validate the exact Flatpak network permissions and multicast behavior; then continue SSDP/UPnP, device details, preferences, and reproducible packaging.
