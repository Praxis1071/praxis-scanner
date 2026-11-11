# Praxis Scanner for Linux

This directory contains the native Linux implementation. The Android application remains in the repository's existing Android/Gradle project and is not replaced by this port.

## Technology

- Rust
- GTK4
- libadwaita
- Flatpak as the planned distribution format

## Security boundary

The Linux application is designed to run as an ordinary user. It must not use root, sudo, raw sockets, setuid helpers, privileged daemons, file capabilities, or elevated Linux capabilities. Startup reads local IPv4 interface information through `getifaddrs`; only an explicit user action starts ordinary TCP `connect()` probes against the selected private or link-local subnet.

## Current implementation status

The first foundation milestone provides:

- A native GTK4/libadwaita application window.
- Read-only IPv4 interface enumeration.
- Interface name, address, prefix, and UP/loopback state presentation.
- Unit tests for IPv4 netmask-prefix parsing.
- A bounded IPv4 subnet-range model that rejects networks above a 1024-address ceiling before allocating candidate addresses.
- An explicit common-port TCP-connect scan with a 32-worker ceiling, per-connection timeout, cancellation, and conservative response classification.
- A GTK results view that does not treat timeouts as proof that a host is offline.

This is still early development, **not a complete or verified network scanner**. TCP discovery source is now present, but CI has not yet confirmed that it builds and tests successfully. mDNS, SSDP, NetBIOS, device/service enrichment, persistence, and Flatpak packaging remain future work. No runtime test on the maintainer's CachyOS machine or inside Flatpak has been claimed.

## Build prerequisites

Install the GTK4 and libadwaita development packages provided by your distribution, plus a Rust toolchain compatible with Rust 1.85 or newer.

From this directory:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run
```

The first Cargo run will resolve dependencies and create `Cargo.lock`. Commit that lockfile after the dependency graph and license metadata have been reviewed.

## Next steps

Follow the root `ROADMAP.md`. The next implementation work is to verify the current Rust build, then add tested read-only route/interface models and a safe, cancellable, bounded TCP-connect discovery engine before any broader discovery protocols are added.
