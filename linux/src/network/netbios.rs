//! Bounded NetBIOS Name Service (NBSTAT) discovery.
//!
//! Queries only explicitly supplied IPv4 targets over ordinary UDP. Responses are
//! untrusted network claims; this module never treats a name as verified identity.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const MAX_TARGETS: usize = 1024;
pub const MAX_WORKERS: usize = 20;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetbiosInfo {
    pub hostname: String,
    pub workgroup: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetbiosEvent {
    DeviceFound {
        address: Ipv4Addr,
        info: NetbiosInfo,
    },
    Finished {
        total: usize,
        completed: usize,
        cancelled: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetbiosStartError {
    TooManyTargets { requested: usize, limit: usize },
    InvalidTimeout,
    InvalidSourceAddress,
}

impl std::fmt::Display for NetbiosStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyTargets { requested, limit } => write!(
                formatter,
                "NetBIOS discovery contains {requested} targets; the configured limit is {limit}"
            ),
            Self::InvalidTimeout => formatter.write_str(
                "NetBIOS timeout must be greater than zero and no longer than two seconds",
            ),
            Self::InvalidSourceAddress => formatter.write_str(
                "NetBIOS discovery requires a specific local IPv4 source address",
            ),
        }
    }
}

impl std::error::Error for NetbiosStartError {}

pub struct NetbiosHandle {
    cancelled: Arc<AtomicBool>,
}

impl NetbiosHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Start bounded NBSTAT queries against a caller-selected list of discovered devices.
pub fn start_discovery(
    source_address: Ipv4Addr,
    mut targets: Vec<Ipv4Addr>,
    timeout: Duration,
) -> Result<(NetbiosHandle, mpsc::Receiver<NetbiosEvent>), NetbiosStartError> {
    if source_address.is_unspecified() || source_address.is_multicast() {
        return Err(NetbiosStartError::InvalidSourceAddress);
    }
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(NetbiosStartError::InvalidTimeout);
    }
    if targets.len() > MAX_TARGETS {
        return Err(NetbiosStartError::TooManyTargets {
            requested: targets.len(),
            limit: MAX_TARGETS,
        });
    }
    targets.sort_unstable();
    targets.dedup();

    let total = targets.len();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (event_sender, event_receiver) = mpsc::channel();

    thread::spawn(move || {
        if total == 0 {
            let _ = event_sender.send(NetbiosEvent::Finished {
                total: 0,
                completed: 0,
                cancelled: false,
            });
            return;
        }

        let (job_sender, job_receiver) = mpsc::channel();
        let shared_receiver = Arc::new(Mutex::new(job_receiver));
        let completed = Arc::new(AtomicUsize::new(0));
        let worker_count = total.min(MAX_WORKERS);
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let receiver = Arc::clone(&shared_receiver);
            let sender = event_sender.clone();
            let worker_cancelled = Arc::clone(&worker_cancelled);
            let worker_completed = Arc::clone(&completed);
            let worker_source_address = source_address;

            workers.push(thread::spawn(move || loop {
                let next_target = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv();
                let Ok(address) = next_target else {
                    break;
                };

                if worker_cancelled.load(Ordering::Relaxed) {
                    continue;
                }

                if let Some(info) = query_device(worker_source_address, address, timeout) {
                    if sender
                        .send(NetbiosEvent::DeviceFound { address, info })
                        .is_err()
                    {
                        worker_cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                worker_completed.fetch_add(1, Ordering::Relaxed);
            }));
        }

        for address in targets {
            if worker_cancelled.load(Ordering::Relaxed) || job_sender.send(address).is_err() {
                break;
            }
        }
        drop(job_sender);

        for worker in workers {
            let _ = worker.join();
        }

        let _ = event_sender.send(NetbiosEvent::Finished {
            total,
            completed: completed.load(Ordering::Relaxed),
            cancelled: worker_cancelled.load(Ordering::Relaxed),
        });
    });

    Ok((NetbiosHandle { cancelled }, event_receiver))
}

fn query_device(
    source_address: Ipv4Addr,
    address: Ipv4Addr,
    timeout: Duration,
) -> Option<NetbiosInfo> {
    let socket = UdpSocket::bind(SocketAddrV4::new(source_address, 0)).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    let target = SocketAddr::V4(SocketAddrV4::new(address, 137));
    let request = build_nbstat_request();
    socket.send_to(&request, target).ok()?;

    let mut buffer = [0_u8; MAX_RESPONSE_BYTES];
    let (length, source) = socket.recv_from(&mut buffer).ok()?;
    if source.ip() != IpAddr::V4(address) || source.port() != 137 {
        return None;
    }
    parse_nbstat_response(&buffer[..length])
}

fn build_nbstat_request() -> [u8; 50] {
    let mut packet = [0_u8; 50];
    packet[..12].copy_from_slice(&[
        0x13, 0x37, // transaction ID
        0x00, 0x00, // standard query
        0x00, 0x01, // one question
        0x00, 0x00, // no answers
        0x00, 0x00, // no authority records
        0x00, 0x00, // no additional records
    ]);
    packet[12] = 0x20;
    packet[13] = b'C'; // first-level encoded '*'
    packet[14] = b'K';
    packet[15..43].fill(b'A'); // first-level encoding of 14 null bytes
    packet[43] = b'A'; // final nibble of the fifteenth null byte
    packet[44] = b'A';
    packet[45] = 0x00;
    packet[46] = 0x00;
    packet[47] = 0x21; // NBSTAT
    packet[48] = 0x00;
    packet[49] = 0x01; // IN
    packet
}

fn parse_nbstat_response(data: &[u8]) -> Option<NetbiosInfo> {
    if data.len() < 12 || data.len() > MAX_RESPONSE_BYTES || data[2] & 0x80 == 0 {
        return None;
    }

    let question_count = read_u16(data, 4)? as usize;
    let answer_count = read_u16(data, 6)? as usize;
    if answer_count == 0 || answer_count > 16 || question_count > 4 {
        return None;
    }

    let mut offset = 12usize;
    for _ in 0..question_count {
        offset = skip_dns_name(data, offset)?;
        offset = offset.checked_add(4)?;
        if offset > data.len() {
            return None;
        }
    }

    for _ in 0..answer_count {
        offset = skip_dns_name(data, offset)?;
        let fixed_end = offset.checked_add(10)?;
        if fixed_end > data.len() {
            return None;
        }
        let record_type = read_u16(data, offset)?;
        let record_class = read_u16(data, offset + 2)?;
        let data_length = read_u16(data, offset + 8)? as usize;
        let data_start = fixed_end;
        let data_end = data_start.checked_add(data_length)?;
        if data_end > data.len() {
            return None;
        }

        if record_type == 33 && record_class == 1 {
            if let Some(info) = parse_nbstat_rdata(&data[data_start..data_end]) {
                return Some(info);
            }
        }
        offset = data_end;
    }
    None
}

fn parse_nbstat_rdata(data: &[u8]) -> Option<NetbiosInfo> {
    let count = *data.first()? as usize;
    if count == 0 || count > 64 || data.len() < 1 + count * 18 {
        return None;
    }

    let mut hostname = None;
    let mut workgroup = None;
    let mut offset = 1usize;

    for _ in 0..count {
        let entry = &data[offset..offset + 18];
        let name = String::from_utf8_lossy(&entry[..15])
            .trim_end_matches([' ', '\0'])
            .chars()
            .filter(|character| character.is_ascii_graphic() || *character == ' ')
            .collect::<String>();
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        let is_group = flags & 0x8000 != 0;

        if suffix == 0x00 && !is_group && hostname.is_none() && !name.trim().is_empty() {
            hostname = Some(name.clone());
        }
        if matches!(suffix, 0x00 | 0x1e)
            && is_group
            && workgroup.is_none()
            && !name.trim().is_empty()
        {
            workgroup = Some(name);
        }
        offset += 18;
    }

    Some(NetbiosInfo {
        hostname: hostname?,
        workgroup,
    })
}

fn skip_dns_name(data: &[u8], offset: usize) -> Option<usize> {
    let mut cursor = offset;
    loop {
        let length = *data.get(cursor)?;
        if length == 0 {
            return cursor.checked_add(1);
        }
        if length & 0xc0 == 0xc0 {
            return (cursor + 2 <= data.len()).then_some(cursor + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        cursor = cursor.checked_add(1 + length as usize)?;
        if cursor > data.len() {
            return None;
        }
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::{build_nbstat_request, parse_nbstat_response, start_discovery, NetbiosEvent};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn name_entry(name: &str, suffix: u8, flags: u16) -> [u8; 18] {
        let mut entry = [b' '; 18];
        for (target, source) in entry[..15].iter_mut().zip(name.bytes()) {
            *target = source;
        }
        entry[15] = suffix;
        entry[16..18].copy_from_slice(&flags.to_be_bytes());
        entry
    }

    #[test]
    fn builds_the_expected_50_byte_nbstat_query() {
        let request = build_nbstat_request();
        assert_eq!(request.len(), 50);
        assert_eq!(&request[0..2], &[0x13, 0x37]);
        assert_eq!(&request[47..50], &[0x21, 0x00, 0x01]);
    }

    #[test]
    fn parses_windows_style_response_without_echoed_question() {
        let mut response = vec![
            0x13, 0x37, 0x80, 0x00, // response flags
            0x00, 0x00, // no echoed question
            0x00, 0x01, // one answer
            0x00, 0x00, 0x00, 0x00, // remaining header
            0xc0, 0x0c, // compressed answer name
            0x00, 0x21, // NBSTAT
            0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x25, // RDLENGTH: 1 + 2 * 18
            0x02, // two names
        ];
        response.extend_from_slice(&name_entry("DESKTOP-TEST", 0x00, 0x0400));
        response.extend_from_slice(&name_entry("WORKGROUP", 0x1e, 0x8000));

        let info = parse_nbstat_response(&response).expect("valid NBSTAT response");
        assert_eq!(info.hostname, "DESKTOP-TEST");
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn rejects_truncated_or_non_response_packets() {
        assert!(parse_nbstat_response(&[0; 20]).is_none());
        let mut malformed = vec![0x13, 0x37, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c];
        malformed.extend_from_slice(&[0; 4]);
        assert!(parse_nbstat_response(&malformed).is_none());
    }

    #[test]
    fn empty_target_list_finishes_without_network_activity() {
        let (_handle, events) = start_discovery(Ipv4Addr::LOCALHOST, Vec::new(), Duration::from_millis(100))
            .expect("empty target list is valid");
        assert!(matches!(
            events.recv_timeout(Duration::from_secs(1)),
            Ok(NetbiosEvent::Finished {
                total: 0,
                completed: 0,
                cancelled: false,
            })
        ));
    }

    #[test]
    fn rejects_invalid_timeout_and_oversized_target_lists() {
        assert!(start_discovery(Ipv4Addr::LOCALHOST, vec![Ipv4Addr::LOCALHOST], Duration::ZERO).is_err());
        assert!(start_discovery(
            Ipv4Addr::LOCALHOST,
            vec![Ipv4Addr::LOCALHOST; super::MAX_TARGETS + 1],
            Duration::from_millis(100)
        )
        .is_err());
    }
}
