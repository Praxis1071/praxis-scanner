//! Bounded TCP-connect discovery using ordinary unprivileged sockets.
//!
//! A timeout is deliberately not treated as proof that a host is offline.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const MAX_SCAN_TARGETS: usize = 1024;
pub const MAX_CONCURRENT_WORKERS: usize = 32;
pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_millis(450);
pub const DEFAULT_TCP_PORTS: [u16; 7] = [22, 53, 80, 139, 443, 445, 3389];
pub const MAX_TCP_PORTS: usize = 256;
pub const MAX_SCAN_PROBES: usize = 8_192;

/// Return a conventional service label for a TCP port, not a verified service identity.
pub fn service_name(port: u16) -> Option<&'static str> {
    match port {
        22 => Some("SSH"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        139 => Some("NetBIOS"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        3389 => Some("RDP"),
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

pub struct ScanHandle {
    cancelled: Arc<AtomicBool>,
}

impl ScanHandle {
    /// Request cancellation. In-flight connect calls finish within their timeout.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Start a bounded scan of the supplied IPv4 addresses.
///
/// This function never opens raw sockets or requests elevated capabilities.
/// The default entry point probes common TCP ports; custom scans are separately bounded.
/// All scans run at most 32 workers and enforce a total probe budget.
pub fn start_tcp_discovery(
    hosts: Vec<Ipv4Addr>,
    timeout: Duration,
) -> Result<(ScanHandle, mpsc::Receiver<ScanEvent>), ScanStartError> {
    start_tcp_discovery_with_ports(hosts, DEFAULT_TCP_PORTS.to_vec(), timeout)
}

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

fn is_connection_refused(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionRefused
}

#[cfg(test)]
mod tests {
    use super::{
        is_connection_refused, probe_ports, start_tcp_discovery, start_tcp_discovery_with_ports,
        ScanEvent, ScanStartError, MAX_SCAN_TARGETS, MAX_TCP_PORTS,
    };
    use std::io;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

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
            start_tcp_discovery(hosts, Duration::from_millis(100)).err(),
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
            start_tcp_discovery(vec![Ipv4Addr::LOCALHOST], Duration::ZERO).err(),
            Some(ScanStartError::InvalidTimeout)
        );
    }

    #[test]
    fn empty_scan_finishes_without_network_activity() {
        let (_handle, events) = start_tcp_discovery(Vec::new(), Duration::from_millis(100))
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
