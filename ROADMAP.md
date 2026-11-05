# Praxis Scanner — Linux Port Roadmap

> **Status:** Planning  
> **Implementation status:** Not started  
> **Target:** Linux only · Rust · GTK4 · libadwaita · Flatpak · GPL-3.0

This roadmap is the source of truth for the Linux port. Update the checkboxes only after the corresponding work has been completed and verified. Do not begin implementation until the maintainer explicitly approves it.

## 0. Project constraints and decisions

- [x] Target Linux desktop only; no Android build target for this port.
- [x] Use Rust for application and scanning logic.
- [x] Use GTK4 for the interface.
- [x] Use libadwaita for desktop-native widgets and behavior.
- [x] Use Flatpak as the only supported packaging and distribution format.
- [x] Continue under GNU GPL-3.0 and preserve applicable upstream copyright and license notices.
- [x] Require no root, sudo, administrator password, setuid helper, privileged daemon, or elevated capability.
- [x] Treat unprivileged operation as a hard requirement, even if that means omitting a feature.
- [x] Keep the Android implementation on the existing `main` branch untouched while planning and porting on a dedicated branch.
- [x] Do not start coding until the maintainer explicitly says to begin.
- [x] Confirm the repository and product name as **Praxis Scanner** (`praxis-scanner`). The long-term branch-versus-standalone-repository decision remains open.

## 1. Source-project audit

- [x] Inspect the Android repository tree and identify the responsibilities of each module. (See [Linux port audit](docs/linux-port-audit.md).)
- [x] Trace the full scan lifecycle from UI action to discovery, enrichment, and result presentation.
- [x] Document the existing discovery algorithms, timeouts, concurrency model, and fallback behavior.
- [x] Inspect ICMP/TCP reachability checks and determine which parts can be reproduced without raw sockets or capabilities.
- [x] Inspect Android ARP/MAC acquisition and identify the Linux read-only neighbor-table candidate; runtime permissions remain unverified.
- [x] Inspect mDNS, SSDP/UPnP, and NetBIOS implementations and their protocol details.
- [x] Inspect port scanning, banner collection, service identification, and OS/device fingerprint heuristics.
- [ ] Inspect vendor/OUI data source and update strategy. **Licensing/redistribution review remains open; do not bundle the current database yet.**
- [x] Inspect device naming, icon assignment, network-interface selection, and preferences persistence.
- [ ] Review Android screenshot images visually and approve desktop wireframes. Source-level screen/interaction mapping is documented; visual review remains open.
- [x] Record reusable behavior, platform-specific code that must be replaced, and code that must not be ported.
- [x] Produce the preliminary feature parity matrix. Runtime and Flatpak verification remain open.

## 2. Linux feasibility and unprivileged networking research

 > Initial kernel, Flatpak and Rust-crate research notes are in [the Linux port audit](docs/linux-port-audit.md). Items below remain unchecked until experimentally verified on Linux and in Flatpak.

- [ ] Verify Linux unprivileged ICMP options across target distributions and Flatpak runtime constraints.
- [ ] Verify whether the required ping socket behavior is available without `CAP_NET_RAW`; do not assume it is enabled.
- [ ] Verify access to the kernel neighbor table through supported unprivileged interfaces.
- [ ] Determine which network interface and local-subnet details are available to a sandboxed application.
- [ ] Validate TCP connect scanning without elevated privileges.
- [ ] Validate UDP discovery using ordinary datagram sockets and document protocol-specific limitations.
- [ ] Validate multicast and broadcast behavior for mDNS, SSDP, and NetBIOS inside Flatpak.
- [ ] Determine the minimum Flatpak permissions required for each protocol.
- [ ] Confirm that no proposed permission or helper violates the no-root/no-capability policy.
- [ ] Build a capability matrix for common Linux environments and document degraded behavior.
- [ ] Decide which Android features must be adapted, simplified, or omitted based on verified feasibility.

### Security acceptance criteria

- [ ] The application never requests root, sudo, or an administrator password.
- [ ] The application does not depend on setuid binaries, privileged services, or file capabilities.
- [ ] The application does not require `CAP_NET_RAW` or another elevated capability.
- [ ] Flatpak permissions are limited to the minimum required and documented.
- [ ] Unsupported operations fail clearly and safely; there is no privileged fallback.
- [ ] The UI distinguishes confirmed facts from heuristic guesses and unavailable information.

## 3. Product and UX specification

- [ ] Define the main window layout using the Android app's information hierarchy as a reference.
- [ ] Define navigation and responsive behavior for Linux desktop window sizes.
- [ ] Specify the scan start/stop flow, progress reporting, and empty/error states.
- [ ] Specify the device list, sorting, filtering, and device detail presentation.
- [ ] Specify port and service detail presentation.
- [ ] Specify device rename and icon customization.
- [ ] Specify network-interface selection and explain interface limitations.
- [ ] Specify preferences, scan profiles, and configurable ports.
- [ ] Define keyboard navigation, accessibility, and localization expectations.
- [ ] Create screen-by-screen wireframes or design references before implementing the UI.
- [ ] Review the proposed UX and obtain maintainer approval.

## 4. Architecture and dependency design

- [ ] Define module boundaries for application, UI, scan orchestration, protocols, network data, models, and persistence.
- [ ] Keep GTK types out of the core scanning engine.
- [ ] Choose an asynchronous runtime and networking libraries based on the audited requirements.
- [ ] Define bounded concurrency, per-probe timeouts, retry policy, and cancellation semantics.
- [ ] Define typed scan results and structured error categories.
- [ ] Define how partial results are surfaced when some discovery methods are unavailable.
- [ ] Define persistence format and schema migration strategy for user preferences and device customizations.
- [ ] Define vendor/OUI data packaging and update policy, including source licensing.
- [ ] Review dependencies for maintenance, license compatibility, security posture, and unnecessary overlap.
- [ ] Document the final architecture and dependency decisions before implementation.

## 5. Implementation phases (only after explicit approval)

- [ ] Establish the Rust project, formatting/linting rules, and reproducible development environment.
- [ ] Build the GTK4/libadwaita application shell and navigation.
- [ ] Implement core data models and scan lifecycle abstractions.
- [ ] Implement network-interface and local-network information using unprivileged APIs.
- [ ] Implement TCP reachability and host discovery.
- [ ] Implement unprivileged ICMP where verified feasible, with a documented fallback.
- [ ] Implement read-only neighbor-table enrichment where available.
- [ ] Implement mDNS discovery.
- [ ] Implement SSDP/UPnP discovery.
- [ ] Implement NetBIOS discovery.
- [ ] Implement configurable TCP port scanning with bounded concurrency.
- [ ] Implement banner collection and conservative service/version hints.
- [ ] Implement device classification and best-effort OS fingerprinting.
- [ ] Implement vendor lookup and randomized-MAC caveats where data is available.
- [ ] Implement device naming, icon customization, and preferences.
- [ ] Integrate scan results into the UI without blocking the main thread.
- [ ] Add clear permission, capability, timeout, and partial-result explanations.
- [ ] Review the implementation against the feature parity matrix and remove unsupported promises.

## 6. Quality assurance and security validation

- [ ] Add unit tests for parsers, protocol handling, models, and classification logic.
- [ ] Add tests for cancellation, timeouts, concurrency limits, and partial failures.
- [ ] Add integration tests for each supported discovery protocol.
- [ ] Test against a controlled local network with multiple operating systems and device types.
- [ ] Verify that normal application startup and all supported scans work as a regular user.
- [ ] Verify that no code path invokes sudo, requests root, or relies on elevated capabilities.
- [ ] Inspect the built Flatpak manifest and effective permissions.
- [ ] Test in a clean Flatpak sandbox and on more than one Linux distribution.
- [ ] Test offline behavior and confirm there is no undisclosed telemetry or external contact.
- [ ] Run formatting, linting, dependency/license checks, and the complete test suite.
- [ ] Fix regressions before proceeding; do not mark a phase complete based only on compilation.

## 7. Flatpak packaging and release

- [ ] Select and pin a suitable Freedesktop runtime and SDK version.
- [ ] Create a minimal Flatpak manifest with auditable permissions.
- [ ] Ensure the app ID, desktop entry, icon, metainfo, and application name are consistent.
- [ ] Build and install the Flatpak locally for clean-environment testing.
- [ ] Verify updates and data migration behavior.
- [ ] Prepare release notes, screenshots, installation instructions, and source links.
- [ ] Verify GPL-3.0 notices and corresponding source availability for every release.
- [ ] Decide whether to publish on Flathub after the project is mature and meets its submission requirements.
- [ ] Publish a release only after maintainer testing and approval.

## 8. Documentation and maintenance

- [ ] Keep README feature claims aligned with implemented and tested behavior.
- [ ] Document Flatpak permissions and why each one is needed.
- [ ] Document known limitations, protocol coverage, and distribution-specific behavior.
- [ ] Document build, test, and release procedures.
- [ ] Keep this roadmap updated with verified checkmarks and clear deferred items.
- [ ] Review dependencies and security reports periodically.

## Definition of done

The Linux port is ready for its first stable release only when:

1. It works as a normal unprivileged user without root, sudo, privileged helpers, or elevated capabilities.
2. Its advertised discovery and inspection features have been tested in the Flatpak sandbox.
3. Unsupported features and environmental limitations are clearly disclosed.
4. The UI is stable, responsive, and usable on supported Linux desktops.
5. Tests, packaging checks, license review, and maintainer acceptance are complete.
6. The Flatpak is reproducible and the corresponding GPL-3.0 source is available.

---

**Current state:** Planning documentation only. No Linux implementation has been started.
