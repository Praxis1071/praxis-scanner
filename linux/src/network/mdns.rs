//! Bounded, interface-scoped DNS-SD discovery over multicast DNS.
//!
//! Discovery is opt-in, uses ordinary UDP sockets through mdns-sd, and never
//! opens raw sockets or requests elevated capabilities. Results are restricted
//! to IPv4 addresses in the selected interface's candidate subnet.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use mdns_sd::{DaemonEvent, IfKind, ServiceDaemon, ServiceEvent};

pub const DEFAULT_MDNS_WINDOW: Duration = Duration::from_secs(5);
pub const MAX_MDNS_WINDOW: Duration = Duration::from_secs(10);
pub const MAX_MDNS_SERVICE_TYPES: usize = 32;
pub const MAX_MDNS_RESULTS: usize = 256;

const ENUMERATION_TYPE: &str = "_services._dns-sd._udp.local.";
const COMMON_SERVICE_TYPES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_smb._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_ftp._tcp.local.",
];

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MdnsService {
    pub address: Ipv4Addr,
    pub fullname: String,
    pub hostname: String,
    pub service_type: String,
    pub port: u16,
}

#[derive(Debug)]
pub enum MdnsEvent {
    ServiceFound(MdnsService),
    Finished {
        services: usize,
        cancelled: bool,
    },
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MdnsStartError {
    InvalidInterfaceName,
    EmptyAddressScope,
    TooManyAddresses { requested: usize, limit: usize },
    InvalidDuration,
    ThreadSpawn(String),
}

impl std::fmt::Display for MdnsStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInterfaceName => formatter.write_str("the selected network interface name is invalid"),
            Self::EmptyAddressScope => formatter.write_str("mDNS discovery requires a non-empty selected subnet"),
            Self::TooManyAddresses { requested, limit } => write!(
                formatter,
                "mDNS scope contains {requested} addresses; the configured limit is {limit}"
            ),
            Self::InvalidDuration => formatter.write_str("mDNS discovery duration must be greater than zero and no longer than ten seconds"),
            Self::ThreadSpawn(error) => write!(formatter, "could not start the mDNS worker thread: {error}"),
        }
    }
}

impl std::error::Error for MdnsStartError {}

pub struct MdnsHandle {
    cancelled: Arc<AtomicBool>,
}

impl MdnsHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

impl Drop for MdnsHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Start opt-in mDNS/DNS-SD discovery on exactly one selected interface.
pub fn start_mdns_discovery(
    interface_name: String,
    allowed_addresses: Vec<Ipv4Addr>,
    duration: Duration,
) -> Result<(MdnsHandle, mpsc::Receiver<MdnsEvent>), MdnsStartError> {
    if !is_valid_interface_name(&interface_name) {
        return Err(MdnsStartError::InvalidInterfaceName);
    }
    if allowed_addresses.is_empty() {
        return Err(MdnsStartError::EmptyAddressScope);
    }
    if allowed_addresses
        .iter()
        .any(|address| {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (!address.is_private() && !address.is_link_local())
        })
    {
        return Err(MdnsStartError::EmptyAddressScope);
    }
    if allowed_addresses.len() > 1024 {
        return Err(MdnsStartError::TooManyAddresses {
            requested: allowed_addresses.len(),
            limit: 1024,
        });
    }
    if duration.is_zero() || duration > MAX_MDNS_WINDOW {
        return Err(MdnsStartError::InvalidDuration);
    }

    let allowed_addresses = allowed_addresses.into_iter().collect::<HashSet<_>>();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (sender, receiver) = mpsc::channel();

    thread::Builder::new()
        .name("praxis-mdns-discovery".to_owned())
        .spawn(move || {
            let result = run_discovery(
                &interface_name,
                &allowed_addresses,
                duration,
                &worker_cancelled,
                &sender,
            );
            if let Err(error) = result {
                let _ = sender.send(MdnsEvent::Failed(error));
            }
        })
        .map_err(|error| MdnsStartError::ThreadSpawn(error.to_string()))?;

    Ok((MdnsHandle { cancelled }, receiver))
}

fn run_discovery(
    interface_name: &str,
    allowed_addresses: &HashSet<Ipv4Addr>,
    duration: Duration,
    cancelled: &AtomicBool,
    sender: &mpsc::Sender<MdnsEvent>,
) -> Result<(), String> {
    let daemon = ServiceDaemon::new().map_err(|error| format!("could not start mDNS daemon: {error}"))?;
    let result = browse_on_selected_interface(
        &daemon,
        interface_name,
        allowed_addresses,
        duration,
        cancelled,
        sender,
    );

    let _ = daemon.stop_browse(ENUMERATION_TYPE);
    for service_type in COMMON_SERVICE_TYPES {
        let _ = daemon.stop_browse(service_type);
    }
    let _ = daemon.shutdown();

    result
}

fn browse_on_selected_interface(
    daemon: &ServiceDaemon,
    interface_name: &str,
    allowed_addresses: &HashSet<Ipv4Addr>,
    duration: Duration,
    cancelled: &AtomicBool,
    sender: &mpsc::Sender<MdnsEvent>,
) -> Result<(), String> {
    let monitor = daemon
        .monitor()
        .map_err(|error| format!("could not monitor mDNS daemon: {error}"))?;

    daemon
        .disable_interface(IfKind::All)
        .map_err(|error| format!("could not restrict mDNS to the selected interface: {error}"))?;
    daemon
        .enable_interface(IfKind::Name(interface_name.to_owned()))
        .map_err(|error| format!("could not enable mDNS on {interface_name}: {error}"))?;
    daemon
        .disable_interface(IfKind::IPv6)
        .map_err(|error| format!("could not restrict mDNS to IPv4 on {interface_name}: {error}"))?;

    let mut subscriptions = Vec::new();
    let mut service_types = HashSet::new();
    let mut pending_types = Vec::new();

    subscribe(
        daemon,
        ENUMERATION_TYPE,
        &mut service_types,
        &mut subscriptions,
    )?;
    for service_type in COMMON_SERVICE_TYPES {
        subscribe(
            daemon,
            service_type,
            &mut service_types,
            &mut subscriptions,
        )?;
    }

    let deadline = Instant::now() + duration;
    let mut results = HashSet::new();
    let mut failed = None;

    while Instant::now() < deadline && !cancelled.load(Ordering::Relaxed) {
        while let Ok(event) = monitor.try_recv() {
            if let DaemonEvent::Error(error) = event {
                failed = Some(format!("mDNS daemon error: {error}"));
                break;
            }
        }
        if failed.is_some() {
            break;
        }

        for (subscription_type, events) in &subscriptions {
            while let Ok(event) = events.try_recv() {
                match event {
                    ServiceEvent::ServiceFound(_, fullname)
                        if subscription_type == ENUMERATION_TYPE =>
                    {
                        if is_valid_service_type(&fullname)
                            && !service_types.contains(&fullname)
                            && !pending_types.contains(&fullname)
                            && service_types.len() + pending_types.len() < MAX_MDNS_SERVICE_TYPES
                        {
                            pending_types.push(fullname);
                        }
                    }
                    ServiceEvent::ServiceResolved(resolved)
                        if subscription_type != ENUMERATION_TYPE =>
                    {
                        if !resolved.is_valid()
                            || !is_safe_dns_text(&resolved.fullname)
                            || !is_safe_dns_text(&resolved.host)
                            || !is_valid_service_type(&resolved.ty_domain)
                            || resolved.port == 0
                        {
                            continue;
                        }

                        for scoped_address in &resolved.addresses {
                            let IpAddr::V4(address) = scoped_address.to_ip_addr() else {
                                continue;
                            };
                            if !allowed_addresses.contains(&address) {
                                continue;
                            }

                            let service = MdnsService {
                                address,
                                fullname: resolved.fullname.clone(),
                                hostname: resolved.host.clone(),
                                service_type: resolved.ty_domain.clone(),
                                port: resolved.port,
                            };
                            if results.len() >= MAX_MDNS_RESULTS {
                                break;
                            }
                            if results.insert(service.clone())
                                && sender.send(MdnsEvent::ServiceFound(service)).is_err()
                            {
                                return Ok(());
                            }
                        }
                    }
                    _ => {}
                }
                if results.len() >= MAX_MDNS_RESULTS {
                    break;
                }
            }
            if results.len() >= MAX_MDNS_RESULTS {
                break;
            }
        }

        for service_type in pending_types.drain(..) {
            if service_types.len() >= MAX_MDNS_SERVICE_TYPES {
                break;
            }
            subscribe(
                daemon,
                &service_type,
                &mut service_types,
                &mut subscriptions,
            )?;
        }

        if results.len() >= MAX_MDNS_RESULTS {
            break;
        }
        thread::sleep(Duration::from_millis(40));
    }

    if let Some(error) = failed {
        return Err(error);
    }

    for service_type in &service_types {
        let _ = daemon.stop_browse(service_type);
    }
    let _ = sender.send(MdnsEvent::Finished {
        services: results.len(),
        cancelled: cancelled.load(Ordering::Relaxed),
    });
    Ok(())
}

fn subscribe(
    daemon: &ServiceDaemon,
    service_type: &str,
    service_types: &mut HashSet<String>,
    subscriptions: &mut Vec<(String, mdns_sd::Receiver<ServiceEvent>)>,
) -> Result<(), String> {
    if !service_types.insert(service_type.to_owned()) {
        return Ok(());
    }

    match daemon.browse(service_type) {
        Ok(receiver) => {
            subscriptions.push((service_type.to_owned(), receiver));
            Ok(())
        }
        Err(error) => {
            service_types.remove(service_type);
            Err(format!("could not browse {service_type}: {error}"))
        }
    }
}

fn is_safe_dns_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.chars().any(char::is_control)
}

fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.bytes().all(|byte| {
            !byte.is_ascii_control()
                && !byte.is_ascii_whitespace()
                && byte != b'/'
                && byte != b':'
        })
}

fn is_valid_service_type(service_type: &str) -> bool {
    let service_name = service_type
        .strip_suffix("._tcp.local.")
        .or_else(|| service_type.strip_suffix("._udp.local."));
    let Some(service_name) = service_name else {
        return false;
    };
    let Some(service_name) = service_name.strip_prefix('_') else {
        return false;
    };

    !service_name.is_empty()
        && service_name.len() <= 15
        && service_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{
        is_valid_interface_name, is_valid_service_type, start_mdns_discovery, MdnsStartError,
        DEFAULT_MDNS_WINDOW, MAX_MDNS_WINDOW,
    };
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn validates_dns_sd_service_types() {
        assert!(is_valid_service_type("_http._tcp.local."));
        assert!(is_valid_service_type("_ipp._tcp.local."));
        assert!(is_valid_service_type("_printer._udp.local."));
        assert!(!is_valid_service_type("http._tcp.local."));
        assert!(!is_valid_service_type("_bad_name._tcp.local."));
        assert!(!is_valid_service_type("_this-service-name-is-too-long._tcp.local."));
        assert!(!is_valid_service_type("_http._tcp.example.com."));
        assert!(!is_valid_service_type("_http._sctp.local."));
    }

    #[test]
    fn validates_linux_interface_names() {
        assert!(is_valid_interface_name("wlan0"));
        assert!(is_valid_interface_name("enp0s20f0u5"));
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("interface-name-too-long"));
        assert!(!is_valid_interface_name("bad name"));
    }

    #[test]
    fn rejects_invalid_scope_and_duration_before_starting_threads() {
        assert_eq!(
            start_mdns_discovery("wlan0".to_owned(), Vec::new(), DEFAULT_MDNS_WINDOW).err(),
            Some(MdnsStartError::EmptyAddressScope)
        );
        assert_eq!(
            start_mdns_discovery(
                "interface-name-too-long".to_owned(),
                vec![Ipv4Addr::new(192, 168, 1, 20)],
                DEFAULT_MDNS_WINDOW,
            )
            .err(),
            Some(MdnsStartError::InvalidInterfaceName)
        );
        assert_eq!(
            start_mdns_discovery(
                "wlan0".to_owned(),
                vec![Ipv4Addr::new(192, 168, 1, 20)],
                Duration::ZERO,
            )
            .err(),
            Some(MdnsStartError::InvalidDuration)
        );
        assert_eq!(
            start_mdns_discovery(
                "wlan0".to_owned(),
                vec![Ipv4Addr::new(192, 168, 1, 20)],
                MAX_MDNS_WINDOW + Duration::from_millis(1),
            )
            .err(),
            Some(MdnsStartError::InvalidDuration)
        );
    }
}
