//! Bounded TCP-connect discovery using ordinary unprivileged sockets.
//!
//! A timeout is deliberately not treated as proof that a host is offline.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const MAX_SCAN_TARGETS: usize = 1024;
pub const MAX_CONCURRENT_WORKERS: usize = 32;
pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_millis(450);
pub const DEFAULT_TCP_PORTS: [u16; 7] = [22, 53, 80, 139, 443, 445, 3389];
/// The Android app's standard per-device deep-scan port set, kept in sync for parity.
pub const DEEP_SCAN_TCP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2121, 3306, 3389,
    3690, 4443, 5000, 5060, 5432, 5631, 5632, 5900, 5901, 5902, 6000, 6379, 6443,
    6666, 6667, 7001, 7002, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9418, 10000, 11211, 27017, 27018, 28017, 49152, 49153, 49154, 49155, 49156,
    49157,
];
pub const MAX_TCP_PORTS: usize = 256;
pub const MAX_SCAN_PROBES: usize = 8_192;

/// Return a conventional service label for a TCP port, not a verified service identity.
pub fn service_name(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 | 2121 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 | 465 | 587 => Some("SMTP"),
        53 => Some("DNS"),
        80 | 8000 | 8008 | 8080 | 8081 | 8888 => Some("HTTP"),
        110 => Some("POP3"),
        111 => Some("RPC"),
        135 => Some("MSRPC"),
        139 => Some("NetBIOS"),
        143 => Some("IMAP"),
        443 | 8443 => Some("HTTPS"),
        445 => Some("SMB"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1080 => Some("SOCKS"),
        1433 | 1434 => Some("MSSQL"),
        1521 => Some("Oracle"),
        1723 => Some("PPTP"),
        2049 => Some("NFS"),
        2082 | 2086 => Some("cPanel/WHM"),
        2083 | 2087 => Some("cPanel/WHM TLS"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        3690 => Some("SVN"),
        4443 => Some("HTTPS Alt"),
        5000 => Some("UPnP / HTTP Alt"),
        5060 => Some("SIP"),
        5432 => Some("PostgreSQL"),
        5631 | 5632 => Some("pcAnywhere"),
        5900..=5902 => Some("VNC"),
        6000 => Some("X11"),
        6379 => Some("Redis"),
        6443 => Some("Kubernetes API"),
        6666 | 6667 => Some("IRC"),
        7001 | 7002 => Some("WebLogic"),
        9000 => Some("HTTP Alt"),
        9090 => Some("HTTP Alt"),
        9200 => Some("Elasticsearch"),
        9418 => Some("Git"),
        10000 => Some("Webmin"),
        11211 => Some("Memcached"),
        27017 | 27018 => Some("MongoDB"),
        28017 => Some("MongoDB HTTP"),
        _ => None,
    }
}

const MAX_TCP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostScanResult {
    pub address: Ipv4Addr,
    pub open_ports: Vec<u16>,
    /// True only when a TCP connection succeeded or the peer refused it.
    pub tcp_responded: bool,
}

#[derive(Debug)]
pub enum ScanEvent {
    HostCompleted(HostScanResult),
    Finished {
        total: usize,
        completed: usize,
        cancelled: bool,
    },
}

/// Per-port progress emitted by the single-device deep scanner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeepScanEvent {
    PortCompleted {
        port: u16,
        open: bool,
        tcp_responded: bool,
        banner: Option<String>,
    },
    Finished {
        total: usize,
        completed: usize,
        cancelled: bool,
    },
}

/// Start a bounded, parallel TCP port scan against one explicitly selected device.
pub fn start_device_deep_scan(
    address: Ipv4Addr,
    mut ports: Vec<u16>,
    timeout: Duration,
) -> Result<(ScanHandle, mpsc::Receiver<DeepScanEvent>), ScanStartError> {
    if timeout.is_zero() || timeout > MAX_TCP_TIMEOUT {
        return Err(ScanStartError::InvalidTimeout);
    }
    if ports.is_empty() {
        return Err(ScanStartError::EmptyPortList);
    }
    if ports.len() > MAX_TCP_PORTS {
        return Err(ScanStartError::TooManyPorts {
            requested: ports.len(),
            limit: MAX_TCP_PORTS,
        });
    }
    if let Some(port) = ports.iter().find(|port| **port == 0) {
        return Err(ScanStartError::InvalidPort(*port));
    }

    ports.sort_unstable();
    ports.dedup();
    if ports.len() > MAX_SCAN_PROBES {
        return Err(ScanStartError::TooManyProbes {
            requested: ports.len(),
            limit: MAX_SCAN_PROBES,
        });
    }

    let total = ports.len();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (event_sender, event_receiver) = mpsc::channel();

    thread::spawn(move || {
        let (job_sender, job_receiver) = mpsc::channel();
        let shared_receiver = Arc::new(Mutex::new(job_receiver));
        let completed = Arc::new(AtomicUsize::new(0));
        let worker_count = total.min(MAX_CONCURRENT_WORKERS);
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let receiver = Arc::clone(&shared_receiver);
            let sender = event_sender.clone();
            let worker_cancelled = Arc::clone(&worker_cancelled);
            let worker_completed = Arc::clone(&completed);

            workers.push(thread::spawn(move || loop {
                let next_port = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv();
                let Ok(port) = next_port else {
                    break;
                };

                if worker_cancelled.load(Ordering::Relaxed) {
                    continue;
                }

                let socket = SocketAddr::V4(SocketAddrV4::new(address, port));
                let (open, tcp_responded, banner) =
                    match TcpStream::connect_timeout(&socket, timeout) {
                        Ok(mut stream) => {
                            let banner = collect_service_banner(address, port, &mut stream);
                            (true, true, banner)
                        }
                        Err(error) if is_connection_refused(&error) => (false, true, None),
                        Err(_) => (false, false, None),
                    };
                worker_completed.fetch_add(1, Ordering::Relaxed);

                if sender
                    .send(DeepScanEvent::PortCompleted {
                        port,
                        open,
                        tcp_responded,
                        banner,
                    })
                    .is_err()
                {
                    worker_cancelled.store(true, Ordering::Relaxed);
                    break;
                }
            }));
        }

        for port in ports {
            if worker_cancelled.load(Ordering::Relaxed) || job_sender.send(port).is_err() {
                break;
            }
        }
        drop(job_sender);

        for worker in workers {
            let _ = worker.join();
        }

        let _ = event_sender.send(DeepScanEvent::Finished {
            total,
            completed: completed.load(Ordering::Relaxed),
            cancelled: worker_cancelled.load(Ordering::Relaxed),
        });
    });

    Ok((ScanHandle { cancelled }, event_receiver))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanStartError {
    TooManyTargets { requested: usize, limit: usize },
    InvalidTimeout,
    EmptyPortList,
    TooManyPorts { requested: usize, limit: usize },
    TooManyProbes { requested: usize, limit: usize },
    InvalidPort(u16),
}

impl std::fmt::Display for ScanStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyTargets { requested, limit } => write!(
                formatter,
                "scan contains {requested} targets; the configured limit is {limit}"
            ),
            Self::InvalidTimeout => formatter.write_str(
                "TCP timeout must be greater than zero and no longer than five seconds",
            ),
            Self::EmptyPortList => formatter.write_str("at least one TCP port must be selected"),
            Self::TooManyPorts { requested, limit } => write!(
                formatter,
                "port list contains {requested} ports; the configured limit is {limit}"
            ),
            Self::TooManyProbes { requested, limit } => write!(
                formatter,
                "scan would perform {requested} TCP connection attempts; the configured limit is {limit}"
            ),
            Self::InvalidPort(port) => write!(formatter, "TCP port {port} is invalid; port zero is not allowed"),
        }
    }
}

impl std::error::Error for ScanStartError {}


/// Parse a comma-separated list of TCP ports. Duplicate values are removed.
pub fn parse_tcp_ports(input: &str) -> Result<Vec<u16>, PortListError> {
    if input.trim().is_empty() {
        return Err(PortListError::Empty);
    }

    let mut ports = Vec::new();
    for item in input.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(PortListError::EmptyItem);
        }
        let port = item
            .parse::<u16>()
            .map_err(|_| PortListError::InvalidNumber(item.to_owned()))?;
        if port == 0 {
            return Err(PortListError::PortZero);
        }
        if !ports.contains(&port) {
            if ports.len() == MAX_TCP_PORTS {
                return Err(PortListError::TooMany {
                    limit: MAX_TCP_PORTS,
                });
            }
            ports.push(port);
        }
    }
    Ok(ports)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortListError {
    Empty,
    EmptyItem,
    InvalidNumber(String),
    PortZero,
    TooMany { limit: usize },
}

impl std::fmt::Display for PortListError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("enter at least one TCP port"),
            Self::EmptyItem => formatter.write_str("remove empty entries from the port list"),
            Self::InvalidNumber(value) => write!(formatter, "‘{value}’ is not a valid TCP port"),
            Self::PortZero => formatter.write_str("TCP port 0 cannot be scanned"),
            Self::TooMany { limit } => write!(formatter, "use no more than {limit} unique TCP ports"),
        }
    }
}

impl std::error::Error for PortListError {}

#[derive(Clone)]
pub struct ScanHandle {
    cancelled: Arc<AtomicBool>,
}

impl ScanHandle {
    /// Whether two handles refer to the same underlying scan operation.
    pub fn refers_to_same_scan(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cancelled, &other.cancelled)
    }

    /// Request cancellation. In-flight connect calls finish within their timeout.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Start a bounded TCP-connect scan using a caller-supplied port list.
/// Start a bounded TCP-connect scan using a caller-supplied port list.
pub fn start_tcp_discovery_with_ports(
    hosts: Vec<Ipv4Addr>,
    mut ports: Vec<u16>,
    timeout: Duration,
) -> Result<(ScanHandle, mpsc::Receiver<ScanEvent>), ScanStartError> {
    if hosts.len() > MAX_SCAN_TARGETS {
        return Err(ScanStartError::TooManyTargets {
            requested: hosts.len(),
            limit: MAX_SCAN_TARGETS,
        });
    }
    if timeout.is_zero() || timeout > MAX_TCP_TIMEOUT {
        return Err(ScanStartError::InvalidTimeout);
    }
    if ports.is_empty() {
        return Err(ScanStartError::EmptyPortList);
    }
    if ports.len() > MAX_TCP_PORTS {
        return Err(ScanStartError::TooManyPorts {
            requested: ports.len(),
            limit: MAX_TCP_PORTS,
        });
    }
    if let Some(port) = ports.iter().find(|port| **port == 0) {
        return Err(ScanStartError::InvalidPort(*port));
    }
    ports.sort_unstable();
    ports.dedup();
    let requested_probes = hosts.len().saturating_mul(ports.len());
    if requested_probes > MAX_SCAN_PROBES {
        return Err(ScanStartError::TooManyProbes {
            requested: requested_probes,
            limit: MAX_SCAN_PROBES,
        });
    }

    let ports = Arc::new(ports);
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (event_sender, event_receiver) = mpsc::channel();

    let _coordinator = thread::spawn(move || {
        let total = hosts.len();
        if total == 0 {
            let _ = event_sender.send(ScanEvent::Finished {
                total: 0,
                completed: 0,
                cancelled: false,
            });
            return;
        }

        let (job_sender, job_receiver) = mpsc::channel();
        let shared_receiver = Arc::new(Mutex::new(job_receiver));
        let completed = Arc::new(AtomicUsize::new(0));
        let worker_count = total.min(MAX_CONCURRENT_WORKERS);
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let receiver = Arc::clone(&shared_receiver);
            let sender = event_sender.clone();
            let worker_cancelled = Arc::clone(&worker_cancelled);
            let worker_completed = Arc::clone(&completed);
            let worker_ports = Arc::clone(&ports);

            workers.push(thread::spawn(move || loop {
                let next_host = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv();
                let Ok(address) = next_host else {
                    break;
                };

                if worker_cancelled.load(Ordering::Relaxed) {
                    continue;
                }

                let result = scan_host(address, timeout, &worker_ports, &worker_cancelled);
                worker_completed.fetch_add(1, Ordering::Relaxed);
                if sender.send(ScanEvent::HostCompleted(result)).is_err() {
                    worker_cancelled.store(true, Ordering::Relaxed);
                    break;
                }
            }));
        }

        for address in hosts {
            if worker_cancelled.load(Ordering::Relaxed) {
                break;
            }
            if job_sender.send(address).is_err() {
                break;
            }
        }
        drop(job_sender);

        for worker in workers {
            let _ = worker.join();
        }

        let _ = event_sender.send(ScanEvent::Finished {
            total,
            completed: completed.load(Ordering::Relaxed),
            cancelled: worker_cancelled.load(Ordering::Relaxed),
        });
    });

    Ok((ScanHandle { cancelled }, event_receiver))
}

fn scan_host(
    address: Ipv4Addr,
    timeout: Duration,
    ports: &[u16],
    cancelled: &AtomicBool,
) -> HostScanResult {
    let (open_ports, tcp_responded) = probe_ports(address, timeout, ports, cancelled);

    HostScanResult {
        address,
        open_ports,
        tcp_responded,
    }
}

fn probe_ports(
    address: Ipv4Addr,
    timeout: Duration,
    ports: &[u16],
    cancelled: &AtomicBool,
) -> (Vec<u16>, bool) {
    let mut open_ports = Vec::new();
    let mut tcp_responded = false;

    for port in ports {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }

        let socket = SocketAddr::V4(SocketAddrV4::new(address, *port));
        match TcpStream::connect_timeout(&socket, timeout) {
            Ok(stream) => {
                tcp_responded = true;
                open_ports.push(*port);
                drop(stream);
            }
            Err(error) if is_connection_refused(&error) => {
                tcp_responded = true;
            }
            Err(_) => {}
        }
    }

    (open_ports, tcp_responded)
}

fn collect_service_banner(
    address: Ipv4Addr,
    port: u16,
    stream: &mut TcpStream,
) -> Option<String> {
    // Never speak plaintext to TLS services. For plain HTTP, issue only a harmless
    // HEAD request; other services are inspected passively for their initial greeting.
    if matches!(port, 443 | 465 | 993 | 995 | 8443) {
        return None;
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(350)))
        .ok()?;

    if matches!(port, 80 | 8000 | 8008 | 8080 | 8081 | 8888) {
        let request = format!(
            "HEAD / HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).ok()?;
    }

    let mut buffer = [0_u8; 512];
    let read = stream.read(&mut buffer).ok()?;
    if read == 0 {
        return None;
    }
    sanitize_service_banner(&buffer[..read])
}

fn sanitize_service_banner(bytes: &[u8]) -> Option<String> {
    let decoded = String::from_utf8_lossy(bytes);
    let first_line = decoded.lines().find(|line| !line.trim().is_empty())?;
    let sanitized = first_line
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let banner = sanitized.chars().take(240).collect::<String>();
    (!banner.is_empty()).then_some(banner)
}

fn is_connection_refused(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionRefused
}

#[cfg(test)]
mod tests {
    use super::{
        is_connection_refused, probe_ports, start_tcp_discovery_with_ports, ScanEvent,
        ScanStartError, DEFAULT_TCP_PORTS, MAX_SCAN_TARGETS, MAX_TCP_PORTS,
    };
    use std::io;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    #[test]
    fn single_device_deep_scan_reports_open_ports_and_progress() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind an ephemeral loopback port");
        let open_port = listener.local_addr().expect("read listener address").port();
        let (_handle, events) = super::start_device_deep_scan(
            Ipv4Addr::LOCALHOST,
            vec![open_port, open_port],
            Duration::from_millis(500),
        )
        .expect("start bounded device deep scan");

        let mut open_seen = false;
        let mut finished_seen = false;
        while let Ok(event) = events.recv_timeout(Duration::from_secs(2)) {
            match event {
                super::DeepScanEvent::PortCompleted { port, open, .. } => {
                    assert_eq!(port, open_port);
                    open_seen |= open;
                }
                super::DeepScanEvent::Finished {
                    total,
                    completed,
                    cancelled,
                } => {
                    assert_eq!(total, 1);
                    assert_eq!(completed, 1);
                    assert!(!cancelled);
                    finished_seen = true;
                    break;
                }
            }
        }
        assert!(open_seen);
        assert!(finished_seen);
    }

    #[test]
    fn single_device_deep_scan_rejects_unbounded_or_invalid_port_sets() {
        assert!(matches!(
            super::start_device_deep_scan(
                Ipv4Addr::LOCALHOST,
                vec![0],
                Duration::from_millis(100)
            ),
            Err(ScanStartError::InvalidPort(0))
        ));
        assert!(matches!(
            super::start_device_deep_scan(
                Ipv4Addr::LOCALHOST,
                (1..=MAX_TCP_PORTS + 1).map(|port| port as u16).collect(),
                Duration::from_millis(100)
            ),
            Err(ScanStartError::TooManyPorts { .. })
        ));
    }

    #[test]
    fn android_deep_scan_port_set_is_unique_and_within_linux_safety_limits() {
        let ports = super::DEEP_SCAN_TCP_PORTS;
        let unique = ports.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), ports.len());
        assert!(ports.len() <= MAX_TCP_PORTS);
        assert!(ports.iter().all(|port| *port != 0));
        assert!(ports.contains(&49157));
    }

    #[test]
    fn service_names_are_conservative_port_number_hints() {
        assert_eq!(super::service_name(22), Some("SSH"));
        assert_eq!(super::service_name(445), Some("SMB"));
        assert_eq!(super::service_name(12345), None);
    }

    #[test]
    fn parses_port_lists_and_removes_duplicates() {
        assert_eq!(
            super::parse_tcp_ports("22, 80,443,22").expect("valid ports"),
            vec![22, 80, 443]
        );
    }

    #[test]
    fn rejects_invalid_port_list_values() {
        assert!(super::parse_tcp_ports("").is_err());
        assert!(super::parse_tcp_ports("22,,80").is_err());
        assert!(super::parse_tcp_ports("0,80").is_err());
        assert!(super::parse_tcp_ports("abc").is_err());
        assert!(super::parse_tcp_ports("65536").is_err());
    }

    #[test]
    fn rejects_port_lists_above_the_configured_limit() {
        let input = (1..=super::MAX_TCP_PORTS + 1)
            .map(|port| port.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(matches!(
            super::parse_tcp_ports(&input),
            Err(super::PortListError::TooMany { .. })
        ));
    }

    #[test]
    fn service_banner_sanitizer_keeps_one_bounded_printable_line() {
        let banner = super::sanitize_service_banner(
            b"SSH-2.0-OpenSSH_9.8\r\nignored second line\n",
        )
        .expect("valid banner");
        assert_eq!(banner, "SSH-2.0-OpenSSH_9.8");
        assert!(super::sanitize_service_banner(b"\0\r\n").is_none());
    }

    #[test]
    fn connection_refused_is_still_evidence_of_a_tcp_response() {
        let error = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert!(is_connection_refused(&error));
    }

    #[test]
    fn timeout_is_not_classified_as_a_tcp_response() {
        let error = io::Error::from(io::ErrorKind::TimedOut);
        assert!(!is_connection_refused(&error));
    }

    #[test]
    fn detects_an_open_loopback_tcp_port() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind an ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("read the loopback listener address")
            .port();
        let cancelled = AtomicBool::new(false);

        let (open_ports, responded) = probe_ports(
            Ipv4Addr::LOCALHOST,
            Duration::from_millis(500),
            &[port],
            &cancelled,
        );

        assert_eq!(open_ports, vec![port]);
        assert!(responded);
    }

    #[test]
    fn cancelled_probe_does_not_open_connections() {
        let cancelled = AtomicBool::new(true);
        let (open_ports, responded) = probe_ports(
            Ipv4Addr::LOCALHOST,
            Duration::from_millis(100),
            &[80],
            &cancelled,
        );

        assert!(open_ports.is_empty());
        assert!(!responded);
    }

    #[test]
    fn rejects_scan_combinations_above_the_probe_budget() {
        let hosts = vec![Ipv4Addr::LOCALHOST; 33];
        let ports = (1..=MAX_SCAN_TARGETS.min(super::MAX_TCP_PORTS))
            .map(|port| port as u16)
            .collect::<Vec<_>>();
        assert!(matches!(
            super::start_tcp_discovery_with_ports(hosts, ports, Duration::from_millis(100)),
            Err(ScanStartError::TooManyProbes { .. })
        ));
    }

    #[test]
    fn rejects_target_lists_above_the_safety_limit() {
        let hosts = vec![Ipv4Addr::LOCALHOST; MAX_SCAN_TARGETS + 1];
        assert_eq!(
            start_tcp_discovery_with_ports(hosts, DEFAULT_TCP_PORTS.to_vec(), Duration::from_millis(100)).err(),
            Some(ScanStartError::TooManyTargets {
                requested: MAX_SCAN_TARGETS + 1,
                limit: MAX_SCAN_TARGETS,
            })
        );
    }

    #[test]
    fn full_custom_port_scan_reports_an_open_loopback_listener() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind an ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("read the loopback listener address")
            .port();

        let (_handle, events) = start_tcp_discovery_with_ports(
            vec![Ipv4Addr::LOCALHOST],
            vec![port],
            Duration::from_millis(500),
        )
        .expect("start a valid custom-port scan");

        match events.recv_timeout(Duration::from_secs(2)) {
            Ok(ScanEvent::HostCompleted(result)) => {
                assert_eq!(result.address, Ipv4Addr::LOCALHOST);
                assert_eq!(result.open_ports, vec![port]);
                assert!(result.tcp_responded);
            }
            event => panic!("expected host result, received {event:?}"),
        }

        assert!(matches!(
            events.recv_timeout(Duration::from_secs(2)),
            Ok(ScanEvent::Finished {
                total: 1,
                completed: 1,
                cancelled: false,
            })
        ));
    }

    #[test]
    fn rejects_empty_and_zero_port_lists() {
        assert_eq!(
            start_tcp_discovery_with_ports(
                vec![Ipv4Addr::LOCALHOST],
                Vec::new(),
                Duration::from_millis(100),
            )
            .err(),
            Some(ScanStartError::EmptyPortList)
        );
        assert_eq!(
            start_tcp_discovery_with_ports(
                vec![Ipv4Addr::LOCALHOST],
                vec![0],
                Duration::from_millis(100),
            )
            .err(),
            Some(ScanStartError::InvalidPort(0))
        );
    }

    #[test]
    fn rejects_custom_port_lists_above_the_limit() {
        let ports = (1..=MAX_TCP_PORTS + 1)
            .map(|port| port as u16)
            .collect();
        assert!(matches!(
            start_tcp_discovery_with_ports(
                vec![Ipv4Addr::LOCALHOST],
                ports,
                Duration::from_millis(100),
            ),
            Err(ScanStartError::TooManyPorts { .. })
        ));
    }

    #[test]
    fn rejects_zero_timeout() {
        assert_eq!(
            start_tcp_discovery_with_ports(vec![Ipv4Addr::LOCALHOST], DEFAULT_TCP_PORTS.to_vec(), Duration::ZERO).err(),
            Some(ScanStartError::InvalidTimeout)
        );
    }

    #[test]
    fn empty_scan_finishes_without_network_activity() {
        let (_handle, events) = start_tcp_discovery_with_ports(Vec::new(), DEFAULT_TCP_PORTS.to_vec(), Duration::from_millis(100))
            .expect("an empty scan is valid");
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)),
            Ok(ScanEvent::Finished {
                total: 0,
                completed: 0,
                cancelled: false,
            })
        ));
    }
}
