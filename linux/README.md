# Praxis Scanner for Linux

This directory contains the native Linux implementation. The Android application remains in the repository's existing Android/Gradle project and is not replaced by this port.

## Technology

- Rust
- GTK4
- libadwaita
- Flatpak as the planned distribution format

## Security boundary

The Linux application is designed to run as an ordinary user. It must not use root, sudo, raw sockets, setuid helpers, privileged daemons, file capabilities, or elevated Linux capabilities. The current foundation only reads local IPv4 interface information through `getifaddrs`; it sends no discovery packets.

## Current implementation status

The first foundation milestone provides:

- A native GTK4/libadwaita application window.
- Read-only IPv4 interface enumeration.
- Interface name, address, prefix, and UP/loopback state presentation.
- Unit tests for IPv4 netmask-prefix parsing.

This is an initial development milestone, **not a complete network scanner**. Host discovery, TCP connection checks, protocol discovery, device details, persistence, and Flatpak packaging remain future roadmap work. No runtime test on the maintainer's CachyOS machine or inside Flatpak has been claimed.

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

Follow the root `ROADMAP.md`. The next implementation work must add tested interface/route models and a safe, bounded TCP-connect discovery engine before any broader discovery protocols are added.
