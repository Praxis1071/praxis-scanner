//! Read-only IPv4 route and ARP neighbour information from procfs.
//!
//! These files are observational interfaces. This module never changes routes,
//! neighbours, interfaces, firewall rules, or kernel settings.

use std::fs;
use std::io;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcNetParseError;

impl std::fmt::Display for ProcNetParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("malformed procfs network table")
    }
}

impl std::error::Error for ProcNetParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Route {
    pub interface: String,
    pub destination: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix: u8,
    pub metric: u32,
    pub is_default: bool,
    pub uses_gateway: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Neighbour {
    pub address: Ipv4Addr,
    pub hardware_address: String,
    pub interface: String,
}

/// Read active IPv4 routes from the kernel's procfs route table.
pub fn read_ipv4_routes() -> io::Result<Vec<Ipv4Route>> {
    let content = fs::read_to_string("/proc/net/route")?;
    parse_ipv4_routes(&content).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid /proc/net/route contents")
    })
}

/// Read complete IPv4 ARP neighbour entries from procfs.
/// Incomplete cache entries are intentionally omitted.
pub fn read_ipv4_neighbours() -> io::Result<Vec<Ipv4Neighbour>> {
    let content = fs::read_to_string("/proc/net/arp")?;
    parse_ipv4_neighbours(&content).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid /proc/net/arp contents")
    })
}

fn parse_ipv4_routes(contents: &str) -> Result<Vec<Ipv4Route>, ProcNetParseError> {
    let mut lines = contents.lines();
    let header = lines.next().ok_or(ProcNetParseError)?;
    if !header.starts_with("Iface") {
        return Err(ProcNetParseError);
    }

    let mut routes = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 11 {
            return Err(ProcNetParseError);
        }

        let flags = u32::from_str_radix(fields[3], 16).map_err(|_| ProcNetParseError)?;
        const RTF_UP: u32 = 0x0001;
        const RTF_GATEWAY: u32 = 0x0002;
        if flags & RTF_UP == 0 {
            continue;
        }

        let destination = parse_proc_ipv4(fields[1])?;
        let gateway = parse_proc_ipv4(fields[2])?;
        let mask = parse_proc_ipv4(fields[7])?;
        let prefix = contiguous_prefix(mask).ok_or(ProcNetParseError)?;
        let metric = fields[6].parse::<u32>().map_err(|_| ProcNetParseError)?;

        routes.push(Ipv4Route {
            interface: fields[0].to_owned(),
            destination,
            gateway,
            prefix,
            metric,
            is_default: destination.is_unspecified() && prefix == 0,
            uses_gateway: flags & RTF_GATEWAY != 0,
        });
    }

    routes.sort_by(|left, right| {
        right
            .is_default
            .cmp(&left.is_default)
            .then_with(|| left.metric.cmp(&right.metric))
            .then_with(|| left.interface.cmp(&right.interface))
    });
    Ok(routes)
}

fn parse_ipv4_neighbours(contents: &str) -> Result<Vec<Ipv4Neighbour>, ProcNetParseError> {
    let mut lines = contents.lines();
    let header = lines.next().ok_or(ProcNetParseError)?;
    if !header.starts_with("IP address") {
        return Err(ProcNetParseError);
    }

    let mut neighbours = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(ProcNetParseError);
        }

        let flags_text = fields[2].strip_prefix("0x").unwrap_or(fields[2]);
        let flags = u32::from_str_radix(flags_text, 16).map_err(|_| ProcNetParseError)?;
        const ATF_COM: u32 = 0x02;
        if flags & ATF_COM == 0 {
            continue;
        }

        let address = fields[0].parse::<Ipv4Addr>().map_err(|_| ProcNetParseError)?;
        let hardware_address = fields[3];
        if !is_valid_mac_address(hardware_address) {
            continue;
        }

        neighbours.push(Ipv4Neighbour {
            address,
            hardware_address: hardware_address.to_ascii_lowercase(),
            interface: fields[5].to_owned(),
        });
    }

    neighbours.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.address.cmp(&right.address))
    });
    Ok(neighbours)
}

fn parse_proc_ipv4(value: &str) -> Result<Ipv4Addr, ProcNetParseError> {
    let raw = u32::from_str_radix(value, 16).map_err(|_| ProcNetParseError)?;
    Ok(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn contiguous_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from_be_bytes(mask.octets());
    let inverted = !bits;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    Some(bits.count_ones() as u8)
}

fn is_valid_mac_address(value: &str) -> bool {
    let octets: Vec<_> = value.split(':').collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && u8::from_str_radix(octet, 16).is_ok())
}

#[cfg(test)]
mod tests {
    use super::{parse_ipv4_neighbours, parse_ipv4_routes};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_and_prioritizes_default_route() {
        let fixture = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\n",
            "eth0 0001A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\\n",
            "wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0\\n",
        );
        let routes = parse_ipv4_routes(fixture).expect("valid route fixture");
        assert_eq!(routes.len(), 2);
        assert!(routes[0].is_default);
        assert_eq!(routes[0].interface, "wlan0");
        assert_eq!(routes[0].gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(routes[0].metric, 600);
        assert_eq!(routes[1].destination, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(routes[1].prefix, 24);
    }

    #[test]
    fn ignores_down_routes_and_rejects_non_contiguous_masks() {
        let down = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\n",
            "eth0 00000000 0100000A 0000 0 0 10 00000000 0 0 0\\n",
        );
        assert!(parse_ipv4_routes(down).expect("valid but down route").is_empty());

        let invalid_mask = concat!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\n",
            "eth0 00000000 0100000A 0001 0 0 10 00FF00FF 0 0 0\\n",
        );
        assert!(parse_ipv4_routes(invalid_mask).is_err());
    }

    #[test]
    fn returns_only_complete_neighbour_entries_with_valid_mac() {
        let fixture = concat!(
            "IP address HW type Flags HW address Mask Device\\n",
            "192.168.1.10 0x1 0x2 aa:bb:cc:dd:ee:ff * wlan0\\n",
            "192.168.1.11 0x1 0x0 00:00:00:00:00:00 * wlan0\\n",
            "192.168.1.12 0x1 0x2 invalid * wlan0\\n",
        );
        let neighbours = parse_ipv4_neighbours(fixture).expect("valid ARP fixture");
        assert_eq!(neighbours.len(), 1);
        assert_eq!(neighbours[0].address, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(neighbours[0].hardware_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(neighbours[0].interface, "wlan0");
    }
}
