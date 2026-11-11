//! Unprivileged, read-only network information.
//!
//! This module deliberately does not open raw sockets, modify routes, change
//! system settings, or require elevated capabilities.

pub mod cidr;
pub mod scanner;
pub mod system;

use std::net::Ipv4Addr;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: Option<u8>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Enumerate IPv4 interface addresses using the unprivileged getifaddrs API.
pub fn ipv4_interfaces() -> Result<Vec<NetworkInterface>, String> {
    let addresses = getifaddrs().map_err(|error| error.to_string())?;
    let mut interfaces = Vec::new();

    for entry in addresses {
        let Some(address) = entry.address else {
            continue;
        };
        let Some(address_v4) = address.as_sockaddr_in() else {
            continue;
        };

        let ip = address_v4.ip();
        let prefix = entry
            .netmask
            .as_ref()
            .and_then(|mask| mask.as_sockaddr_in())
            .and_then(|mask| netmask_prefix(mask.ip()));

        let interface = NetworkInterface {
            name: entry.interface_name,
            address: ip,
            prefix,
            is_up: entry.flags.contains(InterfaceFlags::IFF_UP),
            is_loopback: entry.flags.contains(InterfaceFlags::IFF_LOOPBACK),
        };

        if !interfaces.contains(&interface) {
            interfaces.push(interface);
        }
    }

    interfaces.sort_by(|left, right| {
        left.is_loopback
            .cmp(&right.is_loopback)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.address.cmp(&right.address))
    });

    Ok(interfaces)
}

/// Return the prefix length only when the netmask consists of contiguous ones.
fn netmask_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from_be_bytes(mask.octets());
    let inverted = !bits;

    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }

    Some(bits.count_ones() as u8)
}

#[cfg(test)]
mod tests {
    use super::netmask_prefix;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_common_prefixes() {
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
        assert_eq!(netmask_prefix(Ipv4Addr::UNSPECIFIED), Some(0));
    }

    #[test]
    fn reads_local_ipv4_interface_state_without_privileges() {
        assert!(super::ipv4_interfaces().is_ok());
    }

    #[test]
    fn rejects_non_contiguous_netmask() {
        assert_eq!(netmask_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
    }
}
