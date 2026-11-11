# Praxis Scanner — Linux Port Roadmap

> **Status:** Implementation in progress  
> **Implementation status:** GTK4/libadwaita shell, bounded configurable TCP discovery, read-only route/ARP summaries, opt-in interface-scoped mDNS/DNS-SD, bounded SSDP/UPnP discovery, and an initial unified device summary list are present in source. The latest CI run passed formatting and tests but failed strict Clippy on one needless borrow; commit `141e45c` fixes it and a fresh run is queued. Host and Flatpak runtime verification remain pending  
> **Target:** Linux desktop · Rust · GTK4 · libadwaita · Flatpak · GPL-3.0  
> **Development branch:** `linux/gtk4-port-planning`

This roadmap is the source of truth for the Linux edition and the governing execution plan. The primary objective is to reproduce the Android Praxis Scanner application's appearance, information hierarchy, screen flows, interactions, and user-visible functionality as completely and faithfully as Linux desktop conventions allow. This is a port/clone of the product experience, not merely a new scanner with similar features. Kotlin source may remain in the repository unchanged; Linux is an additional native implementation. The roadmap is not complete merely because the application compiles, launches, or passes a small subset of tests.

Update checkboxes only after the corresponding work has been completed and verified. Planning and research are not implementation. The maintainer explicitly authorized implementation on 2026-11-08; continue only within the documented security and scope constraints.

## Governing objective and execution method (maintainer clarification — 2026-11-11)

The maintainer has explicitly clarified that **full Android-to-Linux product parity is the central goal**. Keep the Android implementation and Kotlin files; do not treat their presence or GitHub's language statistics as a problem. Build the Linux implementation alongside them.

### What “clone the Android application” means
The active implementation checklist is [Android → Linux Feature-Parity Matrix](docs/linux-android-parity-matrix.md). Update it whenever a feature is inspected, implemented, verified, or found to differ; do not treat the initial audit as complete.


- Reproduce every user-visible Android screen, major component, information hierarchy, interaction, workflow, and setting in a native GTK4/libadwaita desktop experience.
- Reproduce the application's advertised and actually implemented functionality, not just the easiest subset. Map every Android feature to its Linux equivalent and track it in a feature-parity matrix.
- Preserve familiar terminology, result semantics, scan behavior, defaults, and user expectations wherever the underlying platform permits.
- Adapt Android-specific patterns to desktop conventions without losing the underlying capability: keyboard/mouse operation, resizable layouts, desktop navigation, dialogs, tables/lists, and native preferences.
- Keep Android-only APIs and mechanisms out of Linux code. For every platform-specific dependency, identify the user-visible behavior it provides and implement the closest safe Linux-native equivalent.
- Do not silently drop, hide, or downgrade a feature because it is difficult. Investigate it, document the blocker, test alternatives, and continue repair work. Any genuinely impossible or security-incompatible exception must be explained with evidence and brought back to the maintainer rather than quietly treated as parity.
- Maintain visual references and a screen-by-screen comparison record. “Looks similar” is not enough: compare layout, hierarchy, states, labels, icons, feedback, and interaction behavior against the Android reference.
- Preserve the original Android project. Linux work remains isolated on `linux/gtk4-port-planning` until explicit approval.

### Required work loop: control → error detection → repair → re-control

Every work session and every meaningful milestone follows this loop:

1. **Control / inspect:** compare the Android source, behavior, screenshots, existing Linux implementation, roadmap, and current CI state. Identify what exists, what is missing, and what is only partially implemented.
2. **Error detection:** inspect code paths and UI behavior; run formatting, static analysis, unit/integration tests, packaging checks, and controlled runtime checks appropriate to the change. Record concrete failures and parity gaps.
3. **Repair:** fix the root cause, not just the visible symptom. Implement missing behavior and UI, strengthen tests, update packaging/docs, and preserve the project's security constraints.
4. **Re-control:** repeat the relevant checks after repair, inspect regressions, and compare the result against the Android reference again. Do not mark an item complete until the evidence supports it.
5. **Continue:** select the next highest-impact parity gap or defect and repeat. A passing build is a checkpoint, never the definition of completion.

For each feature, record its Android reference, expected behavior, Linux implementation, verification method, observed result, remaining difference, and status. Keep separate statuses for **implemented**, **automated-test verified**, **host verified**, **Flatpak verified**, and **Android parity reviewed**. Never collapse these into one “done” checkbox.

### Completion commitment

The Linux clone remains an active project until the feature-parity review, visual review, functionality checks, security checks, host validation, Flatpak validation, regression suite, and maintainer acceptance criteria in this roadmap are satisfied. Do not stop at a prototype, MVP, successful compile, or the first working Flatpak. Do not ask the maintainer to perform acceptance testing while known major parity gaps or blocking defects remain. Once the work is genuinely ready, provide a clear release-candidate handoff and request the maintainer's final review. Do not merge to `main` without explicit approval.

## Ultimate project objective

Deliver **Praxis Scanner for Linux** as a polished native desktop application that:

- Reproduces the Android app's device discovery and result experience as closely as possible, including the full supported feature set and clear, understandable results.
- Provides reliable TCP reachability checks, configurable port inspection, and best-effort service/device identification.
- Uses additional discovery protocols (ICMP datagram ping, neighbor-table data, mDNS, SSDP/UPnP, NetBIOS, and reverse DNS) only where their behavior is proven safe and available without elevated privileges.
- Recreates the Android app's complete screen set and interaction flows in a modern GTK4/libadwaita desktop interface, including scan progress/cancellation, device and port/service details, naming/icons, and settings.
- Runs as an ordinary user and is distributed as a Flatpak with the minimum justified permissions.
- Is modular, maintainable, tested, reproducible, accessible, and documented.
- Preserves GPL-3.0 obligations and all applicable upstream copyright/license notices.
- Makes no unsupported claims: unavailable data and heuristic guesses are clearly identified.

The Linux edition is a separate native platform implementation, not a Kotlin-to-Rust line-by-line translation. Android-only APIs (including Shizuku, Android permissions, and Android lifecycle/UI APIs) are not copied literally; their user-visible purpose must be assessed and, where possible, reproduced through safe Linux-native equivalents.

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
- [x] Obtain maintainer approval before beginning implementation (explicit approval received 2026-11-08).
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
- [x] Produce the initial source-backed Android → Linux feature-parity matrix in [docs/linux-android-parity-matrix.md](docs/linux-android-parity-matrix.md). The audit is intentionally incomplete and remains a living checklist; visual review, deeper source tracing, implementation, and runtime verification remain open.

## 2. Linux feasibility and unprivileged networking research

> Initial kernel, Flatpak and Rust-crate research notes are in [the Linux port audit](docs/linux-port-audit.md). Items below remain unchecked until experimentally verified on the host and in Flatpak.

- [x] Refresh current Linux kernel, Flatpak, rtnetlink, ICMP, GTK4 and libadwaita documentation; record newly identified security caveats in the audit. Cross-check Flatpak runtime lifecycle and flag the rtnetlink docs.rs/upstream-release version discrepancy. (Documentation research only; runtime behavior remains unverified.)
- [x] Add a safe, read-only first-pass host baseline command set to the feasibility test plan.
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

## 5. Implementation phases (maintainer approval received 2026-11-08)

Implementation is authorized and active on this branch. Source includes the GTK4/libadwaita shell, read-only IPv4 interface/route/ARP summaries, bounded subnet calculation, explicit configurable TCP-connect discovery, conservative service hints, cancellation, opt-in interface-scoped IPv4 mDNS/DNS-SD, and bounded SSDP/UPnP discovery. The complete CI pipeline (formatting, tests, Clippy, and release build) passed on commit `09320a1`. The SSDP engine and its UI integration are awaiting their own CI run. No host-network or Flatpak runtime behavior has been verified, so no feature is considered release-complete.

**Current milestone:** establish a complete screen/feature parity inventory against Android, then use the mandatory control → error detection → repair → re-control loop to close implementation and verification gaps. Continue through the full clone objective; do not stop after the current device-list milestone. No user-side acceptance testing is requested until the application is feature-complete and the major parity/quality gates are closed.

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

- [ ] Implement mDNS discovery. (A bounded, interface-scoped source implementation exists; runtime and Flatpak verification remain pending.)
- [ ] Implement SSDP/UPnP discovery with bounded response parsing. (One M-SEARCH query and untrusted LOCATION text are supported; device-description URLs are deliberately never fetched.)
- [ ] Implement NetBIOS discovery where justified by feasibility results.
- [ ] Implement reverse DNS lookup with timeouts and cancellation.
- [ ] Implement configurable TCP port scanning with bounded concurrency and conservative defaults.
- [ ] Implement banner collection with strict size/time limits and safe parsing.
- [ ] Implement conservative service/version hints.
- [ ] Implement device classification and best-effort OS fingerprinting, clearly labeled as heuristic.
- [ ] Implement vendor lookup only if data licensing and redistribution are approved; explain randomized-MAC uncertainty.
- [ ] Add scan profiles and custom-port configuration only after the core scan behavior is stable.

### 5.4 User experience and persistence

- [ ] Integrate the new protocol-neutral device-evidence catalog into a unified device list, device details, port/service details, and scan progress views.
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

### Full-clone parity gate (required in addition to the quality gates below)

- [ ] Complete a source-backed inventory of every Android screen, user action, setting, scan/discovery feature, result field, and error/empty/loading state.
- [ ] Maintain a traceable Android → Linux parity matrix; every row has a reference and a verification procedure.
- [ ] Recreate all applicable screens and workflows in GTK4/libadwaita and complete a visual comparison against Android references.
- [ ] Reproduce all applicable user-visible behavior and scan semantics; document and resolve every known discrepancy.
- [ ] Verify normal, boundary, failure, cancellation, partial-result, and unavailable-feature states for every major workflow.
- [ ] Review every difference that cannot be reproduced literally on Linux and implement the closest safe native equivalent or obtain an explicit maintainer decision.
- [ ] Complete the repeated control → error detection → repair → re-control cycle with no known blocking defects or unexplained parity gaps.

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

**Current state (2026-11-11):** Linux implementation is active on `linux/gtk4-port-planning`; the latest branch comparison reports 141 commits ahead of `main` and 0 behind. The Android project remains present; the branch diff adds Linux source/docs and adjusts root documentation, not Android implementation files. Linux source includes the GTK4/libadwaita shell, read-only IPv4 interface/route/ARP summaries, bounded subnet calculation, explicit TCP-connect scanning, configurable comma-separated TCP ports, conservative port-number service hints, cancellation, progress, mDNS, SSDP, and a basic unified device summary list with an initial navigable device-detail page (IP, MAC, TCP evidence/open ports, mDNS and SSDP evidence only). This is an early partial implementation, not Android detail-screen parity. TCP scan bounds are 1024 target addresses, 256 unique ports, 8192 connection attempts, and 32 workers; UI TCP timeout is 450 ms. The latest UI/navigation change is commit `6bcf9fa`; CI run `43092906677` is pending, so compilation, tests, Clippy, and Flatpak status for this change are not yet verified. The Flatpak manifest exists, but its build job has not succeeded. Host and Flatpak runtime tests, device detail screens, sorting/filtering, rename/icon customization, NetBIOS, reverse DNS, banners, and persistent preferences remain incomplete. The application is not ready for maintainer testing.


## Latest parity implementation update (2026-11-11)

- Added a bounded, parallel single-device TCP deep-scan engine using the Android app's standard common-port list, with per-port progress, cancellation, and conservative service labels.
- Added safe service-banner collection for plain TCP services: one bounded 512-byte read, a short read timeout, no plaintext probing of TLS ports, and only an HTTP HEAD request for plain HTTP endpoints.
- Added a bounded UDP NetBIOS NBSTAT implementation with strict response parsing, source validation, cancellation, and hostname/workgroup evidence integration.
- These changes are **source implemented, not yet CI/host/Flatpak verified**. The Android app's full 1–65535 scan, ICMP latency/TTL, OS detection, persistent settings/customizations, and remaining screens are still open parity work.
