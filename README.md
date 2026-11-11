# Praxis Scanner

A Linux desktop network scanner in active development in the **Praxis Scanner** project family, built with **Rust**, **GTK4**, and **libadwaita**. It is a Linux-native companion to the Android Network Scanner codebase, not an Android build.

> **Project status: Active implementation — not yet test-ready**
>
> The Linux branch currently contains a GTK4/libadwaita shell, read-only IPv4 interface/route/ARP summaries, bounded TCP-connect discovery with custom ports and cancellation, opt-in interface-scoped mDNS/DNS-SD and SSDP/UPnP, plus an initial unified device list combining TCP, mDNS, SSDP, and MAC evidence. The latest CI run passed formatting and tests but failed strict Clippy on one needless borrow; that lint has been corrected and a fresh CI run is queued. No Flatpak build or controlled-network validation has passed yet. Host-network and Flatpak runtime behavior are not yet verified. The Android Gradle project remains present and unchanged; Linux work stays isolated on `linux/gtk4-port-planning`.

## Project goals

Create a native Linux desktop network scanner that preserves the Android application's core discovery and device-inspection workflow while adapting it to Linux desktop conventions.

The Linux application will:

- Run on Linux only.
- Use Rust for the application and scanning logic.
- Use GTK4 and libadwaita for the graphical interface.
- Be distributed exclusively as a Flatpak.
- Remain licensed under GNU GPL-3.0, while preserving applicable upstream copyright and license notices.
- Perform all supported operations without root, sudo, administrator passwords, setuid helpers, privileged services, or capabilities such as `CAP_NET_RAW`.
- Request only the minimum Flatpak permissions needed for its documented features.

## Current Linux implementation (development; runtime validation pending)

The current branch contains these source-level features:

- Read-only IPv4 interface, default-route, and complete ARP-neighbour information.
- User-selected private/link-local IPv4 subnet discovery.
- TCP connect checks with editable comma-separated ports and conservative port-number service hints.
- Opt-in mDNS/DNS-SD service discovery, restricted to the selected interface and IPv4 subnet, with a five-second default window, cancellation, and bounded results.
- Opt-in SSDP/UPnP M-SEARCH discovery with selected-interface binding, bounded response parsing, and no automatic fetching of advertised URLs.
- An initial unified device list that merges TCP, mDNS, SSDP, and read-only MAC evidence by IPv4 address; device detail pages, renaming, and persistence are not implemented.
- Limits of 1024 TCP targets, 256 unique TCP ports, 8192 total TCP connection attempts, and 32 concurrent TCP workers.
- Explicit start/cancel controls and inconclusive handling for hosts that do not respond.

The previous CI workflow only built the Android Gradle project; it did not compile or test the Linux Rust application. A Linux-specific job has now been added, but its first successful run is not yet confirmed. This does not establish correct behavior on a real network or inside Flatpak. mDNS, SSDP and NetBIOS responses are unauthenticated and can be spoofed; advertised URLs and names are treated as untrusted data.

## Planned features

The following are targets, not claims of current implementation. Each feature must be validated against Linux and the unprivileged execution requirement before it is committed to the product.

### Network discovery

- Local network host discovery using unprivileged methods.
- TCP-based reachability checks and fallback discovery.
- Read-only use of the system neighbor table where available.
- mDNS / DNS-SD service discovery (source implementation present; host and Flatpak runtime verification pending).
- SSDP / UPnP discovery (source implementation present; host and Flatpak runtime verification pending).
- NetBIOS name and workgroup discovery.
- Network interface selection where supported by the sandbox.

### Device information

- IP address and hostname.
- MAC address and vendor information when available from permitted system data.
- Device category hints based on observed services.
- Best-effort operating-system and service identification using connection-based probes and banners.
- User-defined device names and icons.

### Port and service inspection

- Configurable common-port scans.
- Optional broader TCP port scans with clear performance and network-impact warnings.
- Service and version hints from safely collected banners.
- Cancellation, timeouts, concurrency limits, and clear error reporting.

### Desktop experience

- A GTK4/libadwaita interface inspired by the Android application's information hierarchy and workflow.
- Device list, device details, scan progress, and preferences.
- Responsive layouts suitable for Linux desktop windows.
- No advertising, tracking, or unnecessary network communication.

## Non-negotiable security requirements

- No root or sudo execution.
- No administrator password prompts.
- No privileged helper daemon or setuid executable.
- No requirement for raw-socket capabilities such as `CAP_NET_RAW`.
- No broad Flatpak permissions unless a demonstrated, documented requirement makes them unavoidable; the rootless policy takes priority.
- Features that cannot be implemented reliably without elevated privileges must be redesigned around an unprivileged alternative or omitted.
- The application must clearly explain unavailable information instead of fabricating device details.

**Important:** Linux distributions differ in kernel configuration, network policy, and sandbox behavior. ICMP and ARP-related behavior must be validated experimentally. The application must not silently fall back to privileged execution.

## Technology and distribution

| Area | Decision |
| --- | --- |
| Platform | Linux only |
| Language | Rust |
| UI toolkit | GTK4 |
| GNOME integration | libadwaita |
| Packaging | Flatpak only |
| License | GNU GPL-3.0 |
| Privilege model | Unprivileged user process |

## Development principles

1. Inspect and understand the Android implementation before porting behavior.
2. Separate the UI, scan orchestration, discovery protocols, device models, and persistence.
3. Keep the scanning engine independent from GTK wherever practical.
4. Use asynchronous I/O and bounded concurrency so scans do not freeze the interface or overload the network.
5. Make scans cancellable and apply explicit timeouts.
6. Test protocol parsing and scan logic independently, then validate against real devices on a controlled local network.
7. Test the Flatpak sandbox and permissions early, not only at release time.
8. Avoid unnecessary dependencies and avoid collecting or transmitting user network data.
9. Update `ROADMAP.md` as work is completed; only mark an item complete after verification.
10. Preserve the Android implementation on `main` until the Linux port is deliberately separated or merged according to the maintainer's decision.

## Project roadmap

See [ROADMAP.md](ROADMAP.md) for the phased research, architecture, implementation, testing, and release plan. The current Android source analysis and preliminary Linux feature-parity decisions are documented in [docs/linux-port-audit.md](docs/linux-port-audit.md).

## License

This project is intended to remain under the [GNU General Public License v3.0](LICENSE). The Android project and its upstream contributors retain their applicable copyright. Preserve existing notices and clearly document the origin of adapted code. See the license text for the full terms.
