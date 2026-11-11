# Linux application architecture

> Status: initial architecture baseline, 2026-11-08. This document describes boundaries for the Linux implementation; it is not evidence of runtime validation.

## Repository layout

The Android Gradle project remains in the repository's existing root and `app/` tree. The independent Linux application lives in `linux/`:

- `linux/Cargo.toml`: Rust application manifest.
- `linux/src/main.rs`: GTK/libadwaita application entry point.
- `linux/src/ui.rs`: desktop presentation and UI event wiring.
- `linux/src/network/`: unprivileged network information and future discovery engine.

Do not move, rename, or delete Android source files as part of the Linux port. Shared behavior may be reimplemented in Rust, but Android APIs and Kotlin code are not Linux runtime dependencies.

## Layer boundaries

1. **UI layer** — GTK4/libadwaita widgets, user input, progress and result presentation. GTK objects stay on the GTK main thread.
2. **Application orchestration** — scan lifecycle, cancellation, selected interface, user preferences and conversion of engine events into UI state.
3. **Network engine** — owned Rust data types and protocol implementations. It must not depend on GTK types.
4. **Platform information** — read-only interface, address, route and neighbor-table queries.
5. **Persistence** — user preferences and device customizations, with explicit schema/version handling.

The current implementation includes the UI shell, read-only IPv4 interface enumeration, bounded IPv4 target generation, and an explicit user-triggered TCP-connect discovery path. The TCP path is source-complete at this stage but still awaits successful CI and controlled-network verification.

## Security invariants

- No root/sudo, administrator password, setuid/setgid executable, privileged daemon, file capability, or elevated capability.
- No raw sockets and no `CAP_NET_RAW` / `CAP_NET_ADMIN`.
- No route, neighbor-table, firewall, sysctl, or interface mutation.
- TCP discovery must use ordinary `connect()` sockets with explicit timeouts, bounded concurrency, cancellation and a user-confirmed scope.
- A failed unprivileged operation is reported as unavailable; there is no privileged fallback.
- Network observations must retain their source and confidence. A timeout is not proof that a host is offline.
- No telemetry or undisclosed network requests.

## Concurrency model

GTK widgets are created and mutated only on the main thread. The current TCP discovery engine uses a bounded pool of at most 32 standard-library worker threads and reports owned events over a channel. GTK widgets are updated by a GLib main-thread timeout callback; worker threads never access GTK objects. Every scan must have cancellation, a global concurrency ceiling, per-operation deadlines and deterministic cleanup. Blocking work and untrusted protocol parsing must never run in GTK signal callbacks.

## Discovery order

1. Interface/address enumeration.
2. Read-only route and neighbor information, once the chosen API passes host and Flatpak tests.
3. TCP connect discovery with a conservative, explicit scope (initial source implementation present; verification pending).
4. ICMP datagram only if the exact datagram socket is proven to work without capabilities; never use raw ICMP.
5. mDNS, SSDP and optional NetBIOS only after bounded protocol, lifecycle and Flatpak multicast tests.

## Dependency policy

Direct dependencies must be minimal and reviewed for maintenance, MSRV, license, transitive graph and security advisories. `rtnetlink` remains unapproved until its published version discrepancy is resolved. The initial implementation uses `nix` only for the read-only `getifaddrs` call; the complete resolved graph must be locked and audited before release.

## Verification policy

Each milestone needs unit tests and CI checks. A successful CI build does not replace testing on the maintainer's CachyOS host or in the exact Flatpak sandbox. Host and Flatpak outcomes are recorded separately in `docs/linux-network-feasibility-test-plan.md`.
