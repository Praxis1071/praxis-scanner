# Praxis Scanner — Linux Port Roadmap

> **Status:** Planning  
> **Implementation status:** Not started  
> **Target:** Linux desktop · Rust · GTK4 · libadwaita · Flatpak · GPL-3.0  
> **Development branch:** `linux/gtk4-port-planning`

This roadmap is the source of truth for the Linux edition. Its final objective is a stable, secure, documented, tested, and distributable Linux desktop network scanner that delivers the feasible core experience of the Android application while respecting the strict unprivileged-operation policy below. Every phase contributes to that final objective; the roadmap is not considered complete merely because the application compiles.

Update checkboxes only after the corresponding work has been completed and verified. Planning and research are not implementation. Do not begin application implementation until the maintainer explicitly approves it.

## Ultimate project objective

Deliver **Praxis Scanner for Linux** as a polished native desktop application that:

- Discovers devices on the user's local network and presents useful, understandable results.
- Provides reliable TCP reachability checks, configurable port inspection, and best-effort service/device identification.
- Uses additional discovery protocols (ICMP datagram ping, neighbor-table data, mDNS, SSDP/UPnP, NetBIOS, and reverse DNS) only where their behavior is proven safe and available without elevated privileges.
- Offers a modern GTK4/libadwaita interface with scan progress and cancellation, device details, port/service details, device naming and icon customization, and clear settings.
- Runs as an ordinary user and is distributed as a Flatpak with the minimum justified permissions.
- Is modular, maintainable, tested, reproducible, accessible, and documented.
- Preserves GPL-3.0 obligations and all applicable upstream copyright/license notices.
- Makes no unsupported claims: unavailable data and heuristic guesses are clearly identified.

The Linux edition is a separate platform implementation, not a Kotlin-to-Rust line-by-line translation. Android-only functionality (including Shizuku, root-based access, Android permissions, and Android lifecycle/UI APIs) is not part of the Linux target.

## 0. Project constraints and decisions

- [x] Keep the existing Android application and its source code on `main`; Linux planning and implementation take place on a dedicated branch in the same repository.
- [x] Use the existing repository; a separate repository is not required for the Linux port.
- [x] Use **Praxis Scanner** as the product name and `praxis-scanner` as the repository name.
- [x] Target Linux desktop only for this port; do not replace or remove the Android application.
- [x] Use Rust for application and scanning logic.
- [x] Use GTK4 for the interface.
- [x] Use libadwaita for desktop-native widgets and behavior.
- [x] Use Flatpak as the planned supported packaging and distribution format.
- [x] Continue under GNU GPL-3.0 and preserve applicable upstream copyright and license notices.
- [x] Require no root, sudo, administrator password, setuid helper, privileged daemon, or elevated capability.
- [x] Treat unprivileged operation as a hard requirement, even if that means omitting a feature.
- [x] Keep Android source files unchanged during Linux planning and porting.
- [x] Do not start implementation until the maintainer explicitly approves it.
- [ ] Keep all Linux work isolated on the dedicated branch until the maintainer has tested and approved it; merge into `main` only after explicit approval.

### Non-negotiable security rules

- Never request or invoke root, sudo, or an administrator password.
- Never install or rely on setuid/setgid helpers, privileged daemons, file capabilities, or elevated capabilities.
- Never require `CAP_NET_RAW`, `CAP_NET_ADMIN`, or raw sockets.
- Do not weaken host sysctls or firewall settings to make a feature work.
- Do not silently fall back to a privileged method when an unprivileged method fails.
- Request only the Flatpak permissions proven necessary for advertised features.
- Do not add telemetry or undisclosed external network requests.

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

> Initial kernel, Flatpak and Rust-crate research notes are in [the Linux port audit](docs/linux-port-audit.md). Items below remain unchecked until experimentally verified on the host and in Flatpak.

- [ ] Record the target development system details (distribution, kernel, user/group context, network interfaces, routes, neighbor table, Flatpak availability, and ping-group range).
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
- [ ] Decide which Android features must be adapted, simplified, deferred, or omitted based on verified feasibility.
- [ ] Record evidence and exact test conditions; distinguish host results from Flatpak results.

> Execution checklist and safe host/Flatpak test commands: [Linux network feasibility test plan](docs/linux-network-feasibility-test-plan.md). Fill its matrix with observed results. A proposed library, source-code inspection, or documentation statement alone does not count as a runtime pass.

### Security acceptance criteria

- [ ] The application never requests root, sudo, or an administrator password.
- [ ] The application does not depend on setuid binaries, privileged services, or file capabilities.
- [ ] The application does not require `CAP_NET_RAW` or another elevated capability.
- [ ] Flatpak permissions are limited to the minimum required and documented.
- [ ] Unsupported operations fail clearly and safely; there is no privileged fallback.
- [ ] The UI distinguishes confirmed facts from heuristic guesses and unavailable information.

## 3. Product and UX specification

- [ ] Define the product's first-release scope from the verified feasibility matrix; do not promise unverified Android parity.
- [ ] Define the main window layout using the Android app's information hierarchy as a reference, adapted to desktop workflows.
- [ ] Define navigation and responsive behavior for Linux desktop window sizes.
- [ ] Specify the scan start/stop flow, progress reporting, cancellation, and empty/error states.
- [ ] Specify the device list, sorting, filtering, and device detail presentation.
- [ ] Specify port and service detail presentation.
- [ ] Specify device rename and icon customization.
- [ ] Specify network-interface selection and explain interface limitations.
- [ ] Specify preferences, scan profiles, and configurable ports.
- [ ] Define safe defaults, scan scope confirmation, and clear warnings for exhaustive port scans.
- [ ] Define keyboard navigation, accessibility, and localization expectations.
- [ ] Create screen-by-screen wireframes or design references before implementing the UI.
- [ ] Review the proposed UX and obtain maintainer approval.

## 4. Architecture and dependency design

- [ ] Define module boundaries for application, UI, scan orchestration, protocols, network data, models, and persistence.
- [ ] Keep GTK types out of the core scanning engine.
- [ ] Keep network operations off the GTK main thread and define safe communication back to the UI.
- [ ] Choose an asynchronous runtime and networking libraries based on the audited requirements.
- [ ] Define bounded concurrency, per-probe timeouts, retry policy, rate limits, and cancellation semantics.
- [ ] Define typed scan results and structured error categories.
- [ ] Define how partial results are surfaced when some discovery methods are unavailable.
- [ ] Define persistence format and schema migration strategy for user preferences and device customizations.
- [ ] Define vendor/OUI data packaging and update policy, including source licensing.
- [ ] Review dependencies for maintenance, license compatibility, security posture, and unnecessary overlap.
- [ ] Define logging that is useful for diagnosis without exposing unnecessary network/user information.
- [ ] Document the final architecture, dependency decisions, and threat model before implementation.

## 5. Implementation phases (only after explicit approval)

Implementation must proceed incrementally. Each item needs tests and review before dependent work is considered complete.

### 5.1 Foundation and application shell

- [ ] Establish the Rust project, formatting/linting rules, and reproducible development environment.
- [ ] Add the GTK4/libadwaita application shell and navigation.
- [ ] Establish core data models, structured errors, and scan lifecycle abstractions.
- [ ] Establish UI/engine messaging, background task handling, and cancellation.

### 5.2 Network foundation and core discovery

- [ ] Implement network-interface and local-network information using unprivileged APIs.
- [ ] Implement TCP reachability and host discovery.
- [ ] Implement unprivileged ICMP only where verified feasible, with a documented fallback.
- [ ] Implement read-only neighbor-table enrichment where available.
- [ ] Present partial discovery results and explain unavailable sources.

### 5.3 Protocol discovery and inspection

- [ ] Implement mDNS discovery.
- [ ] Implement SSDP/UPnP discovery with bounded, safe device-description retrieval.
- [ ] Implement NetBIOS discovery where justified by feasibility results.
- [ ] Implement reverse DNS lookup with timeouts and cancellation.
- [ ] Implement configurable TCP port scanning with bounded concurrency and conservative defaults.
- [ ] Implement banner collection with strict size/time limits and safe parsing.
- [ ] Implement conservative service/version hints.
- [ ] Implement device classification and best-effort OS fingerprinting, clearly labeled as heuristic.
- [ ] Implement vendor lookup only if data licensing and redistribution are approved; explain randomized-MAC uncertainty.
- [ ] Add scan profiles and custom-port configuration only after the core scan behavior is stable.

### 5.4 User experience and persistence

- [ ] Implement the device list, device details, port/service details, and scan progress views.
- [ ] Implement start, stop, cancellation, empty, partial-result, and error states.
- [ ] Implement device naming, icon customization, and preferences.
- [ ] Integrate scan results into the UI without blocking the main thread.
- [ ] Add accessible labels, keyboard operation, responsive layouts, and localization support.
- [ ] Review the implementation against the feature parity matrix and remove unsupported promises.

## 6. Quality assurance and security validation

- [ ] Add unit tests for parsers, protocol handling, models, and classification logic.
- [ ] Add tests for cancellation, timeouts, rate limits, concurrency limits, and partial failures.
- [ ] Add integration tests for each supported discovery protocol.
- [ ] Test against a controlled local network with multiple operating systems and device types.
- [ ] Verify that normal application startup and all supported scans work as a regular user.
- [ ] Verify that no code path invokes sudo, requests root, or relies on elevated capabilities.
- [ ] Inspect the built Flatpak manifest and effective permissions.
- [ ] Test in a clean Flatpak sandbox and on more than one Linux distribution.
- [ ] Test offline behavior and confirm there is no undisclosed telemetry or external contact.
- [ ] Test malformed, oversized, and unexpected protocol responses.
- [ ] Test long-running scans, repeated scans, resource use, and UI responsiveness.
- [ ] Run formatting, linting, dependency/license checks, and the complete test suite.
- [ ] Fix regressions before proceeding; do not mark a phase complete based only on compilation.
- [ ] Publish a test report with environment, commands, results, known limitations, and unresolved issues.

## 7. Flatpak packaging and release engineering

- [ ] Select and pin a suitable Freedesktop runtime and SDK version.
- [ ] Create a minimal Flatpak manifest with auditable permissions.
- [ ] Ensure the app ID, desktop entry, icon, metainfo, and application name are consistent.
- [ ] Build and install the Flatpak locally for clean-environment testing.
- [ ] Verify updates and data migration behavior.
- [ ] Verify that the application works with only the permissions declared in the manifest.
- [ ] Prepare release notes, screenshots, installation instructions, and source links.
- [ ] Verify GPL-3.0 notices and corresponding source availability for every release.
- [ ] Decide whether to publish on Flathub after the project is mature and meets its submission requirements.
- [ ] Publish a release only after maintainer testing and approval.

## 8. Documentation and long-term maintenance

- [ ] Keep README feature claims aligned with implemented and tested behavior.
- [ ] Document Flatpak permissions and why each one is needed.
- [ ] Document known limitations, protocol coverage, and distribution-specific behavior.
- [ ] Document build, test, troubleshooting, and release procedures.
- [ ] Keep this roadmap updated with verified checkmarks and clearly identified deferred items.
- [ ] Keep third-party license notices and attribution complete.
- [ ] Review dependencies, security advisories, and supported runtime versions periodically.
- [ ] Establish a process for handling bug reports, security reports, and compatibility regressions.

## 9. Maintainer acceptance and completion of the Linux port

- [ ] Produce a release-candidate Flatpak and provide installation/testing instructions to the maintainer.
- [ ] Maintainer tests the release candidate on the target CachyOS system.
- [ ] Maintainer verifies the advertised features, permission behavior, usability, and known limitations.
- [ ] Resolve blocking bugs and repeat affected regression tests.
- [ ] Obtain explicit maintainer approval for the completed Linux port.
- [ ] Review the complete branch diff and confirm Android source files and Android behavior remain untouched.
- [ ] Merge the Linux work into `main` only after explicit approval.
- [ ] Tag the first stable Linux release and publish the corresponding source and release artifacts.

## Definition of done — the final objective

The roadmap reaches its final objective only when all applicable requirements below are satisfied:

1. **A complete Linux desktop application exists:** Praxis Scanner has a functional Rust core and a polished GTK4/libadwaita interface, not merely a prototype or proof of concept.
2. **The core purpose works:** it can discover local-network devices and present useful device, reachability, port, and service information using the features verified for the supported environments.
3. **The security policy is met:** it works as a normal unprivileged user without root, sudo, privileged helpers, raw sockets, or elevated capabilities.
4. **Sandboxing is verified:** the distributed Flatpak has only justified permissions, and its advertised network features have been tested inside the sandbox.
5. **Quality is demonstrated:** automated tests, controlled-network integration tests, malformed-input tests, cancellation/resource tests, and real maintainer testing pass.
6. **The experience is complete:** errors, partial results, unsupported features, and heuristic information are communicated clearly; the UI is responsive and accessible.
7. **The project is distributable and maintainable:** reproducible packaging, GPL-3.0 compliance, complete documentation, source availability, and a release process are in place.
8. **The maintainer accepts the result:** the user has tested and explicitly approved the branch before it is merged into `main`.

If a feature cannot satisfy the security policy or cannot be reliably tested, it must be documented as unsupported or deferred rather than weakening the project's constraints.

---

**Current state:** Planning documentation only. The Android source audit and initial research documents are complete. Host and Flatpak feasibility tests have not yet been run. No Linux application implementation has started.
