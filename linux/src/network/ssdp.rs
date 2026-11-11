//! Bounded SSDP/UPnP discovery using ordinary IPv4 UDP sockets.
//!
//! The scanner sends one M-SEARCH multicast query on the selected interface,
//! accepts only unicast responses from the selected IPv4 subnet, and never
//! downloads a device-description URL.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

pub const DEFAULT_SSDP_WINDOW: Duration = Duration::from_secs(3);
pub const MAX_SSDP_WINDOW: Duration = Duration::from_secs(5);
pub const MAX_SSDP_RESULTS: usize = 256;
const MAX_SSDP_DATAGRAMS: usize = 2048;
const MAX_SSDP_PACKET_SIZE: usize = 8192;
const MAX_SSDP_HEADER_LINE: usize = 1024;
const MAX_SSDP_HEADERS: usize = 64;

const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const MSEARCH_REQUEST: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\nUSER-AGENT: PraxisScanner/0.1 UPnP/1.1\r\n\r\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpDevice {
    pub address: Ipv4Addr,
    pub search_target: String,
    pub unique_service_name: String,
    pub server: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug)]
pub enum SsdpEvent {
    DeviceFound(SsdpDevice),
    Finished {
        responses: usize,
        cancelled: bool,
    },
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SsdpStartError {
    InvalidInterfaceAddress,
    EmptyAddressScope,
    InvalidAddressScope,
    TooManyAddresses { requested: usize, limit: usize },
    InvalidDuration,
    ThreadSpawn(String),
}

impl std::fmt::Display for SsdpStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInterfaceAddress => formatter.write_str("SSDP requires an active private or IPv4 link-local interface address"),
            Self::EmptyAddressScope => formatter.write_str("SSDP discovery requires a non-empty selected subnet"),
            Self::InvalidAddressScope => formatter.write_str("SSDP discovery is limited to private IPv4 and IPv4 link-local addresses"),
            Self::TooManyAddresses { requested, limit } => write!(
                formatter,
                "SSDP scope contains {requested} addresses; the configured limit is {limit}"
            ),
            Self::InvalidDuration => formatter.write_str("SSDP discovery duration must be greater than zero and no longer than five seconds"),
            Self::ThreadSpawn(error) => write!(formatter, "could not start the SSDP worker thread: {error}"),
        }
    }
}

impl std::error::Error for SsdpStartError {}

pub struct SsdpHandle {
    cancelled: Arc<AtomicBool>,
}

impl SsdpHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

impl Drop for SsdpHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Send one SSDP M-SEARCH query using the selected interface's IPv4 address.
pub fn start_ssdp_discovery(
    interface_address: Ipv4Addr,
    allowed_addresses: Vec<Ipv4Addr>,
    duration: Duration,
) -> Result<(SsdpHandle, mpsc::Receiver<SsdpEvent>), SsdpStartError> {
    if !is_allowed_ipv4(interface_address) {
        return Err(SsdpStartError::InvalidInterfaceAddress);
    }
    if allowed_addresses.is_empty() {
        return Err(SsdpStartError::EmptyAddressScope);
    }
    if allowed_addresses
        .iter()
        .any(|address| !is_allowed_ipv4(*address))
    {
        return Err(SsdpStartError::InvalidAddressScope);
    }
    if allowed_addresses.len() > 1024 {
        return Err(SsdpStartError::TooManyAddresses {
            requested: allowed_addresses.len(),
            limit: 1024,
        });
    }
    if duration.is_zero() || duration > MAX_SSDP_WINDOW {
        return Err(SsdpStartError::InvalidDuration);
    }

    let allowed_addresses = allowed_addresses
        .into_iter()
        .filter(|address| *address != interface_address)
        .collect::<HashSet<_>>();
    if allowed_addresses.is_empty() {
        return Err(SsdpStartError::EmptyAddressScope);
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (sender, receiver) = mpsc::channel();

    thread::Builder::new()
        .name("praxis-ssdp-discovery".to_owned())
        .spawn(move || {
            let result = run_discovery(
                interface_address,
                &allowed_addresses,
                duration,
                &worker_cancelled,
                &sender,
            );
            if let Err(error) = result {
                let _ = sender.send(SsdpEvent::Failed(error));
            }
        })
        .map_err(|error| SsdpStartError::ThreadSpawn(error.to_string()))?;

    Ok((SsdpHandle { cancelled }, receiver))
}

fn run_discovery(
    interface_address: Ipv4Addr,
    allowed_addresses: &HashSet<Ipv4Addr>,
    duration: Duration,
    cancelled: &AtomicBool,
    sender: &mpsc::Sender<SsdpEvent>,
) -> Result<(), String> {
    let socket = create_ssdp_socket(interface_address)
        .map_err(|error| format!("could not create selected-interface SSDP socket: {error}"))?;
    let destination = SocketAddrV4::new(SSDP_GROUP, SSDP_PORT);
    let sent = socket
        .send_to(MSEARCH_REQUEST, destination)
        .map_err(|error| format!("could not send SSDP M-SEARCH query: {error}"))?;
    if sent != MSEARCH_REQUEST.len() {
        return Err("the SSDP M-SEARCH datagram was not sent completely".to_owned());
    }

    let deadline = Instant::now() + duration;
    let mut buffer = [0u8; MAX_SSDP_PACKET_SIZE];
    let mut datagrams = 0usize;
    let mut results = HashSet::<(Ipv4Addr, String, String)>::new();

    while Instant::now() < deadline
        && !cancelled.load(Ordering::Relaxed)
        && datagrams < MAX_SSDP_DATAGRAMS
        && results.len() < MAX_SSDP_RESULTS
    {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                datagrams += 1;
                if length == buffer.len() {
                    continue;
                }
                let IpAddr::V4(address) = source.ip() else {
                    continue;
                };
                if !allowed_addresses.contains(&address) {
                    continue;
                }

                let Ok(response) = parse_ssdp_response(&buffer[..length]) else {
                    continue;
                };
                let key = (
                    address,
                    response.unique_service_name.to_ascii_lowercase(),
                    response.search_target.to_ascii_lowercase(),
                );
                if results.insert(key) {
                    let device = SsdpDevice {
                        address,
                        search_target: response.search_target,
                        unique_service_name: response.unique_service_name,
                        server: response.server,
                        location: response.location,
                    };
                    if sender.send(SsdpEvent::DeviceFound(device)).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("error receiving SSDP responses: {error}")),
        }
    }

    let _ = sender.send(SsdpEvent::Finished {
        responses: results.len(),
        cancelled: cancelled.load(Ordering::Relaxed),
    });
    Ok(())
}

fn create_ssdp_socket(interface_address: Ipv4Addr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let bind_address = SocketAddrV4::new(interface_address, 0);
    socket.bind(&SocketAddr::V4(bind_address).into())?;
    socket.set_multicast_if_v4(&interface_address)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SsdpResponse {
    search_target: String,
    unique_service_name: String,
    server: Option<String>,
    location: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SsdpParseError {
    PacketTooLarge,
    InvalidUtf8,
    InvalidStatusLine,
    TooManyHeaders,
    InvalidHeader,
    DuplicateHeader,
    InvalidValue,
    MissingRequiredHeader,
}

fn parse_ssdp_response(packet: &[u8]) -> Result<SsdpResponse, SsdpParseError> {
    if packet.is_empty() || packet.len() > MAX_SSDP_PACKET_SIZE {
        return Err(SsdpParseError::PacketTooLarge);
    }
    let text = std::str::from_utf8(packet).map_err(|_| SsdpParseError::InvalidUtf8)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(SsdpParseError::InvalidStatusLine)?;
    let mut status_parts = status_line.split_whitespace();
    if !matches!(status_parts.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || status_parts.next() != Some("200")
    {
        return Err(SsdpParseError::InvalidStatusLine);
    }

    let mut search_target = None;
    let mut unique_service_name = None;
    let mut server = None;
    let mut location = None;
    let mut header_count = 0usize;

    for line in lines {
        if line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > MAX_SSDP_HEADERS || line.len() > MAX_SSDP_HEADER_LINE {
            return Err(SsdpParseError::TooManyHeaders);
        }

        let (name, value) = line.split_once(':').ok_or(SsdpParseError::InvalidHeader)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(SsdpParseError::InvalidHeader);
        }
        let value = value.trim();
        if value.chars().any(char::is_control) {
            return Err(SsdpParseError::InvalidValue);
        }

        match name.to_ascii_lowercase().as_str() {
            "st" => set_header(&mut search_target, value, 256)?,
            "usn" => set_header(&mut unique_service_name, value, 256)?,
            "server" => set_header(&mut server, value, 256)?,
            "location" => {
                if !is_safe_location(value) {
                    return Err(SsdpParseError::InvalidValue);
                }
                set_header(&mut location, value, 512)?;
            }
            _ => {}
        }
    }

    Ok(SsdpResponse {
        search_target: search_target.ok_or(SsdpParseError::MissingRequiredHeader)?,
        unique_service_name: unique_service_name
            .ok_or(SsdpParseError::MissingRequiredHeader)?,
        server,
        location,
    })
}

fn set_header(
    target: &mut Option<String>,
    value: &str,
    maximum_length: usize,
) -> Result<(), SsdpParseError> {
    if value.is_empty()
        || value.len() > maximum_length
        || value.chars().any(char::is_control)
    {
        return Err(SsdpParseError::InvalidValue);
    }
    if target.is_some() {
        return Err(SsdpParseError::DuplicateHeader);
    }
    *target = Some(value.to_owned());
    Ok(())
}

fn is_safe_location(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let Some(authority_and_path) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = authority_and_path.split('/').next().unwrap_or_default();

    !authority.is_empty()
        && !authority.starts_with(':')
        && !authority.ends_with(':')
        && !authority.contains(['?', '#'])
        && !value.chars().any(char::is_whitespace)
        && !value.contains('@')
        && value.len() <= 512
}

fn is_allowed_ipv4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && (address.is_private() || address.is_link_local())
}

#[cfg(test)]
mod tests {
    use super::{
        is_allowed_ipv4, parse_ssdp_response, start_ssdp_discovery, SsdpParseError,
        SsdpStartError, DEFAULT_SSDP_WINDOW, MAX_SSDP_WINDOW,
    };
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const VALID_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://192.168.1.1:1900/rootDesc.xml\r\nSERVER: Linux/6.1 UPnP/1.1 Router/1.0\r\nST: upnp:rootdevice\r\nUSN: uuid:router-123::upnp:rootdevice\r\n\r\n";

    #[test]
    fn parses_valid_ssdp_responses_case_insensitively() {
        let response = parse_ssdp_response(VALID_RESPONSE).expect("valid SSDP response");
        assert_eq!(response.search_target, "upnp:rootdevice");
        assert_eq!(
            response.unique_service_name,
            "uuid:router-123::upnp:rootdevice"
        );
        assert_eq!(
            response.server.as_deref(),
            Some("Linux/6.1 UPnP/1.1 Router/1.0")
        );
        assert_eq!(
            response.location.as_deref(),
            Some("http://192.168.1.1:1900/rootDesc.xml")
        );
    }

    #[test]
    fn accepts_the_required_empty_ext_header() {
        assert!(parse_ssdp_response(VALID_RESPONSE).is_ok());
    }

    #[test]
    fn rejects_malformed_or_ambiguous_ssdp_responses() {
        assert_eq!(
            parse_ssdp_response(b"HTTP/1.1 404 Not Found\r\n\r\n"),
            Err(SsdpParseError::InvalidStatusLine)
        );
        assert_eq!(
            parse_ssdp_response(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n"),
            Err(SsdpParseError::MissingRequiredHeader)
        );
        assert_eq!(
            parse_ssdp_response(
                b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nST: ssdp:all\r\nUSN: uuid:1\r\n\r\n"
            ),
            Err(SsdpParseError::DuplicateHeader)
        );
        assert_eq!(
            parse_ssdp_response(
                b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:1\r\nLOCATION: file:///etc/passwd\r\n\r\n"
            ),
            Err(SsdpParseError::InvalidValue)
        );
    }

    #[test]
    fn rejects_oversized_and_non_utf8_ssdp_packets() {
        assert_eq!(
            parse_ssdp_response(&[b'A'; 8193]),
            Err(SsdpParseError::PacketTooLarge)
        );
        assert_eq!(
            parse_ssdp_response(&[0xff, 0xfe]),
            Err(SsdpParseError::InvalidUtf8)
        );
    }

    #[test]
    fn validates_ipv4_scope_and_scan_limits_before_starting_threads() {
        assert!(is_allowed_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_allowed_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_allowed_ipv4(Ipv4Addr::LOCALHOST));
        assert!(!is_allowed_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_allowed_ipv4(Ipv4Addr::new(224, 0, 0, 1)));

        assert_eq!(
            start_ssdp_discovery(
                Ipv4Addr::new(192, 168, 1, 2),
                Vec::new(),
                DEFAULT_SSDP_WINDOW,
            )
            .err(),
            Some(SsdpStartError::EmptyAddressScope)
        );
        assert_eq!(
            start_ssdp_discovery(
                Ipv4Addr::LOCALHOST,
                vec![Ipv4Addr::new(192, 168, 1, 3)],
                DEFAULT_SSDP_WINDOW,
            )
            .err(),
            Some(SsdpStartError::InvalidInterfaceAddress)
        );
        assert_eq!(
            start_ssdp_discovery(
                Ipv4Addr::new(192, 168, 1, 2),
                vec![Ipv4Addr::new(8, 8, 8, 8)],
                DEFAULT_SSDP_WINDOW,
            )
            .err(),
            Some(SsdpStartError::InvalidAddressScope)
        );
        assert_eq!(
            start_ssdp_discovery(
                Ipv4Addr::new(192, 168, 1, 2),
                vec![Ipv4Addr::new(192, 168, 1, 3)],
                MAX_SSDP_WINDOW + Duration::from_millis(1),
            )
            .err(),
            Some(SsdpStartError::InvalidDuration)
        );
    }
}
