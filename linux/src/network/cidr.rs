//! Validated IPv4 subnet calculations for bounded local-network discovery.
//!
//! This module only calculates candidate addresses. It does not send packets.

use std::net::Ipv4Addr;

/// A validated IPv4 network derived from an interface address and prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Network {
    address: Ipv4Addr,
    prefix: u8,
    first_host: u32,
    host_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkRangeError {
    InvalidPrefix(u8),
    EmptyHostLimit,
    TooManyHosts { requested: u64, limit: u32 },
}

impl std::fmt::Display for NetworkRangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix(prefix) => {
                write!(formatter, "invalid IPv4 prefix: /{prefix}")
            }
            Self::EmptyHostLimit => {
                formatter.write_str("host limit must be greater than zero")
            }
            Self::TooManyHosts { requested, limit } => write!(
                formatter,
                "network contains {requested} candidate hosts; the configured limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for NetworkRangeError {}

impl Ipv4Network {
    /// Build a candidate range, rejecting networks larger than max_hosts.
    /// /31 networks include both endpoints; /32 networks contain one address.
    /// For prefixes through /30, network and broadcast addresses are excluded.
    pub fn from_interface(
        address: Ipv4Addr,
        prefix: u8,
        max_hosts: u32,
    ) -> Result<Self, NetworkRangeError> {
        if prefix > 32 {
            return Err(NetworkRangeError::InvalidPrefix(prefix));
        }
        if max_hosts == 0 {
            return Err(NetworkRangeError::EmptyHostLimit);
        }

        let address_bits = u32::from(address);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = address_bits & mask;
        let broadcast = network | !mask;
        let (first_host, last_host) = match prefix {
            32 => (network, network),
            31 => (network, broadcast),
            _ => (network + 1, broadcast - 1),
        };
        let requested = u64::from(last_host) - u64::from(first_host) + 1;

        if requested > u64::from(max_hosts) {
            return Err(NetworkRangeError::TooManyHosts {
                requested,
                limit: max_hosts,
            });
        }

        Ok(Self {
            address: Ipv4Addr::from(network),
            prefix,
            first_host,
            host_count: requested as u32,
        })
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn host_count(&self) -> u32 {
        self.host_count
    }

    /// Return the bounded candidate host list in ascending address order.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        (0..self.host_count)
            .map(|offset| Ipv4Addr::from(self.first_host + offset))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Ipv4Network, NetworkRangeError};
    use std::net::Ipv4Addr;

    #[test]
    fn calculates_a_typical_lan_range() {
        let network = Ipv4Network::from_interface(
            Ipv4Addr::new(192, 168, 1, 42),
            24,
            1024,
        )
        .expect("/24 should fit the default bound");
        let hosts = network.hosts();

        assert_eq!(network.address(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(network.prefix(), 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn rejects_networks_above_the_host_limit_before_allocating() {
        assert_eq!(
            Ipv4Network::from_interface(Ipv4Addr::new(10, 0, 0, 1), 16, 1024),
            Err(NetworkRangeError::TooManyHosts {
                requested: 65_534,
                limit: 1024,
            })
        );
    }

    #[test]
    fn supports_point_to_point_and_single_host_prefixes() {
        let point_to_point = Ipv4Network::from_interface(
            Ipv4Addr::new(192, 0, 2, 10),
            31,
            2,
        )
        .expect("/31 contains two endpoints");
        assert_eq!(
            point_to_point.hosts(),
            vec![Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)]
        );

        let single = Ipv4Network::from_interface(Ipv4Addr::new(192, 0, 2, 9), 32, 1)
            .expect("/32 contains one address");
        assert_eq!(single.hosts(), vec![Ipv4Addr::new(192, 0, 2, 9)]);
    }

    #[test]
    fn rejects_invalid_prefix_and_zero_limit() {
        assert_eq!(
            Ipv4Network::from_interface(Ipv4Addr::LOCALHOST, 33, 1024),
            Err(NetworkRangeError::InvalidPrefix(33))
        );
        assert_eq!(
            Ipv4Network::from_interface(Ipv4Addr::LOCALHOST, 32, 0),
            Err(NetworkRangeError::EmptyHostLimit)
        );
    }
}
