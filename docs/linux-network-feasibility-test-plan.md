# Linux Network Feasibility Test Plan

> **Purpose:** Validate the Linux networking capabilities needed by Praxis Scanner before implementation.
>
> **Status:** Test plan only. No tests have been executed against the maintainer's machine or network.
>
> **Safety:** All commands are read-only or send a small number of ordinary discovery packets. Run them only on a network you own or are authorized to assess. Do not use sudo, root, setuid helpers, file capabilities, or elevated privileges.

## 1. Test environment record

Record these details with every test run:

- Distribution and version
- Kernel version
- Desktop session
- Network type (Wi-Fi, Ethernet, VPN)
- Selected interface name
- IPv4 address and prefix
- Default gateway
- Flatpak version and runtime version, when testing the packaged sandbox
- Whether the test was run on the host or inside Flatpak

Suggested read-only environment commands:

```sh
cat /etc/os-release
uname -r
ip -brief link
ip -brief address
ip route
flatpak --version
```

Do not include public IP addresses, SSIDs, MAC addresses or other identifying network details in public issue reports unless intentionally disclosed.

## 2. Host interface and route inspection

Run as the ordinary desktop user:

```sh
ip -brief link
ip -brief address
ip route
```

**Pass criteria**

- The selected interface can be identified.
- Its IPv4 address and prefix can be read.
- The default route/gateway can be identified where one exists.
- Multiple interfaces and VPN interfaces are not silently merged into one network.
- Missing IPv4, disconnected interfaces and point-to-point routes are represented as unavailable states, not fatal errors.

**Record:** interface name, address family, prefix, route and whether the information is available without elevated privileges. Redact values before sharing.

## 3. Neighbor-table visibility

Run:

```sh
ip neigh show
```

This is a baseline observation, not proof that every LAN host is discoverable. The neighbor cache only contains entries the kernel currently knows about and may be empty or incomplete.

**Pass criteria**

- The ordinary user can read the current neighbor table.
- Entries can be associated with the correct interface.
- Incomplete, failed, stale, reachable and permanent states are not misreported as confirmed live devices.
- No command modifies the table.

**Implementation gate:** a small Rust proof of concept should use a read-only rtnetlink neighbor dump. Do not shell out to `ip` in the final application. Verify ordinary-user access and the same operation in Flatpak.

## 4. ICMP ping-socket policy

Inspect the host setting:

```sh
cat /proc/sys/net/ipv4/ping_group_range
id
```

Optionally, test a normal ping to a known host on your own network:

```sh
ping -c 1 -W 1 192.168.1.1
```

Replace the example address with your own gateway. This command is only a basic diagnostic; the system `ping` utility may use different socket mechanisms and does not by itself prove that the application's intended ICMP datagram socket will work.

**Pass criteria**

- Record the configured group range and the user's numeric group IDs.
- A dedicated Rust proof of concept must create an ICMP datagram/ping socket without capabilities.
- The test must fail gracefully when policy denies the socket.
- No sysctl is changed to make the test pass.

**Hard rule:** never add `CAP_NET_RAW`, raw ICMP sockets, setuid, sudo, or a privileged helper. ICMP is optional; TCP connect fallback must remain available.

## 5. TCP connect behavior

Use only a known host on a network you own or are authorized to test. A normal TCP client connection does not require raw sockets or elevated capabilities.

**Proof-of-concept requirements**

- Connect to one explicitly selected address and port.
- Use a short configurable timeout.
- Distinguish connected, refused, timed out, unreachable and local socket errors.
- Close sockets on completion and cancellation.
- Do not infer that a host is offline merely because a port did not accept a connection.

**Pass criteria:** successful and refused connections are distinguishable; timeout and cancellation do not hang; the test uses ordinary user permissions.

Do not begin broad subnet or full-port scans as part of this feasibility check.

## 6. UDP multicast and broadcast

The protocols to validate separately are:

| Protocol | Typical destination | Purpose |
| --- | --- | --- |
| mDNS | UDP 5353, 224.0.0.251 | DNS-SD service discovery |
| SSDP | UDP 1900, 239.255.255.250 | UPnP device discovery |
| NetBIOS Name Service | UDP 137, broadcast or directed query | Optional host/workgroup naming |

**Host test requirements**

- Bind to the intended interface/address where supported.
- Join the relevant multicast group for the selected interface.
- Send only a standards-compliant, bounded discovery request.
- Use a short receive deadline and bounded response size.
- Handle no response as a normal outcome.
- Leave multicast groups and close sockets on cancellation.
- Do not assume a VPN, guest Wi-Fi or access-point client-isolation network permits peer discovery.

**Pass criteria:** socket creation, group membership, packet send and bounded receive all work as an ordinary user on the test network. A protocol is considered supported only when a known compatible device or test responder produces a valid response.

## 7. Flatpak sandbox validation

Flatpak denies network access by default. A network-scanning application needs network sharing, normally declared as:

```yaml
finish-args:
  - --share=network
```

This is a broad network permission. Explain it to users and request no unrelated permissions.

**Test sequence**

1. Build a minimal test application with only the intended network permission.
2. Verify interface/address discovery from inside the sandbox.
3. Verify TCP connect.
4. Verify ICMP datagram socket behavior independently.
5. Verify neighbor-table visibility independently.
6. Verify mDNS multicast send/receive.
7. Verify SSDP multicast send/receive.
8. Verify NetBIOS broadcast behavior only if that optional feature remains in scope.
9. Repeat with the exact Flatpak runtime and manifest planned for release.

**Pass criteria**

- The application works with the minimum declared permissions.
- No host filesystem, system D-Bus, device access, session-bus ownership, or elevated capability is added merely to make scanning work.
- If a protocol cannot work in the sandbox, the UI reports it as unavailable and other discovery methods continue.
- Host success must not be assumed to imply Flatpak success.

## 8. Rust proof-of-concept gates

Before selecting final dependencies, create isolated, disposable proof-of-concept experiments (not production application code) for:

- Interface/address/route enumeration.
- Read-only rtnetlink neighbor dump.
- ICMP datagram socket.
- TCP connect with timeout and cancellation.
- mDNS browse and shutdown.
- SSDP discovery and bounded device-description retrieval.
- NetBIOS NBSTAT query and parser, if retained.

For each experiment record:

- Exact crate versions and complete transitive dependency tree.
- License metadata for direct and transitive dependencies.
- Build result against the intended Flatpak runtime.
- Host result and Flatpak result.
- Ordinary-user result.
- Timeout, cancellation and malformed-response behavior.
- Memory and concurrency bounds.

Do not add experimental crates to the production manifest until reviewed and approved.

## 9. Result matrix

Fill this table only with observed results. Use **Not tested**, **Pass**, **Fail**, or **Conditional**; never infer a pass from documentation alone.

| Capability | Host ordinary user | Flatpak | Notes / evidence |
| --- | --- | --- | --- |
| Interface and address enumeration | Not tested | Not tested | |
| Default route/gateway | Not tested | Not tested | |
| Neighbor-table dump | Not tested | Not tested | |
| ICMP datagram socket | Not tested | Not tested | |
| TCP connect | Not tested | Not tested | |
| mDNS multicast | Not tested | Not tested | |
| SSDP multicast | Not tested | Not tested | |
| NetBIOS broadcast | Not tested | Not tested | |

## 10. Exit criteria

The feasibility phase is complete only when:

- Every required capability has host and Flatpak evidence.
- Conditional and unavailable capabilities have documented fallback behavior.
- The final permission set is minimal and justified.
- No test or proposed implementation requires root, sudo, raw sockets, setuid, privileged helpers or elevated capabilities.
- The supported feature set and limitations are reflected in the README and UX specification.

Until these criteria are met, do not mark the feasibility phase complete and do not begin production implementation.
