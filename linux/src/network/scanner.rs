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
const COMMON_TCP_PORTS: [u16; 7] = [22, 53, 80, 139, 443, 445, 3389];
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
        }
    }
}

impl std::error::Error for ScanStartError {}

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
/// It probes a small fixed set of common TCP ports and runs at most 32 workers.
pub fn start_tcp_discovery(
    hosts: Vec<Ipv4Addr>,
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

                let result = scan_host(address, timeout, &worker_cancelled);
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
    cancelled: &AtomicBool,
) -> HostScanResult {
    let (open_ports, tcp_responded) =
        probe_ports(address, timeout, &COMMON_TCP_PORTS, cancelled);

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
        is_connection_refused, probe_ports, start_tcp_discovery, ScanEvent, ScanStartError,
        MAX_SCAN_TARGETS,
    };
    use std::io;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

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
