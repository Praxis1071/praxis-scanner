# Praxis Scanner for Linux

This directory contains the native Linux implementation. The Android application remains in the repository's existing Android/Gradle project and is not replaced by this port.

## Technology

- Rust 2024
- GTK4 and libadwaita
- Flatpak as the planned distribution format

## Security boundary

The application is designed to run as an ordinary user. It does not use root, sudo, raw sockets, setuid helpers, privileged daemons, file capabilities, or elevated Linux capabilities. It reads local IPv4 interface, route, and ARP-neighbour information. Network probes are ordinary TCP connection attempts and start only after the user explicitly selects an eligible interface and starts a scan.

The scanner is restricted to private IPv4 and IPv4 link-local interfaces, at most 1024 target addresses, at most 256 unique TCP ports, at most 8192 total connection attempts per scan, at most 32 concurrent workers, and a per-connection timeout no longer than five seconds. The UI currently uses a 450 ms timeout. Cancellation stops scheduling new work and is observed between in-flight connection attempts.

No response is inconclusive; it is not reported as proof that a device is offline. Conventional service names (SSH, DNS, HTTP, NetBIOS, HTTPS, SMB, and RDP) are hints based only on port numbers, not verified service identities.

## Current implementation status

Source currently includes:

- A GTK4/libadwaita application window.
- Read-only IPv4 interface enumeration and explicit interface selection.
- Read-only default IPv4 route and complete ARP-neighbour summaries from procfs.
- Bounded IPv4 subnet calculation.
- Explicit, cancellable TCP-connect discovery with validated custom port lists.
- Conservative TCP response classification and port-number-based service hints.
- Background worker threads and UI progress reporting.
- Unit tests for CIDR calculations, procfs parsers, port-list parsing, service hints, scan limits, cancellation, and loopback TCP behavior.

**This is still an unverified development build, not a complete or release-ready network scanner.** The latest CI run has not yet provided a successful build/test result. The source changes must still pass formatting, compilation, tests, and Clippy. Host networking and Flatpak behavior have not been runtime-validated. mDNS, SSDP/UPnP, NetBIOS, reverse DNS, banners, richer device details, persistence/preferences, and Flatpak packaging remain outstanding.

## Build prerequisites

Install GTK4 and libadwaita development packages provided by your distribution, plus a Rust toolchain compatible with Rust 1.85 or newer.

From this directory:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run
```

A committed Cargo.lock and a verified offline Flatpak dependency source bundle are still required before reproducible packaging can be claimed.

## Next steps

Follow the root [ROADMAP.md](../ROADMAP.md). Priority order: obtain a clean CI build; review and strengthen the scanner's cancellation/resource tests; finish the device/results experience; evaluate discovery protocols against the unprivileged policy; then create and test the Flatpak manifest in a real sandbox.
