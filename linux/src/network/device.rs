//! A bounded, protocol-neutral model for merging discovery evidence.
//!
//! Device names and service advertisements are claims received from the network.
//! This model preserves their source and never promotes them to verified identity.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const MAX_MDNS_EVIDENCE_PER_DEVICE: usize = 32;
pub const MAX_SSDP_EVIDENCE_PER_DEVICE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdnsEvidence {
    pub fullname: String,
    pub hostname: String,
    pub service_type: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpEvidence {
    pub search_target: String,
    pub unique_service_name: String,
    pub server: Option<String>,
    /// Untrusted text only. Callers must never fetch this URL automatically.
    pub location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetbiosEvidence {
    pub hostname: String,
    pub workgroup: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    pub address: Ipv4Addr,
    pub mac_address: Option<String>,
    /// True when at least one TCP connection attempt received a TCP response.
    pub tcp_responded: bool,
    /// Whether a datagram-only ICMP echo check was completed for this address.
    pub icmp_checked: bool,
    /// Round-trip time for a validated ICMP echo reply, if one was received.
    pub icmp_round_trip_time: Option<Duration>,
    pub open_tcp_ports: BTreeSet<u16>,
    pub mdns_services: Vec<MdnsEvidence>,
    pub ssdp_advertisements: Vec<SsdpEvidence>,
    pub netbios_info: Option<NetbiosEvidence>,
}

impl DeviceRecord {
    pub fn new(address: Ipv4Addr) -> Self {
        Self {
            address,
            mac_address: None,
            tcp_responded: false,
            icmp_checked: false,
            icmp_round_trip_time: None,
            open_tcp_ports: BTreeSet::new(),
            mdns_services: Vec::new(),
            ssdp_advertisements: Vec::new(),
            netbios_info: None,
        }
    }

    pub fn record_icmp(&mut self, round_trip_time: Option<Duration>) {
        self.icmp_checked = true;
        self.icmp_round_trip_time = round_trip_time;
    }

    pub fn record_tcp(&mut self, responded: bool, open_ports: impl IntoIterator<Item = u16>) {
        self.tcp_responded |= responded;
        self.open_tcp_ports
            .extend(open_ports.into_iter().filter(|port| *port != 0));
    }

    pub fn record_mdns(&mut self, evidence: MdnsEvidence) {
        if evidence.port == 0 || self.mdns_services.len() >= MAX_MDNS_EVIDENCE_PER_DEVICE {
            return;
        }
        let duplicate = self.mdns_services.iter().any(|existing| {
            existing.fullname.eq_ignore_ascii_case(&evidence.fullname)
                && existing.port == evidence.port
                && existing.service_type.eq_ignore_ascii_case(&evidence.service_type)
        });
        if !duplicate {
            self.mdns_services.push(evidence);
        }
    }

    pub fn record_ssdp(&mut self, evidence: SsdpEvidence) {
        if self.ssdp_advertisements.len() >= MAX_SSDP_EVIDENCE_PER_DEVICE {
            return;
        }
        let duplicate = self.ssdp_advertisements.iter().any(|existing| {
            existing.unique_service_name.eq_ignore_ascii_case(&evidence.unique_service_name)
                && existing.search_target.eq_ignore_ascii_case(&evidence.search_target)
        });
        if !duplicate {
            self.ssdp_advertisements.push(evidence);
        }
    }

    pub fn record_netbios(&mut self, evidence: NetbiosEvidence) {
        let hostname = evidence.hostname.trim();
        if hostname.is_empty()
            || hostname.len() > 15
            || !hostname.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ' ')
            })
        {
            return;
        }
        let workgroup = evidence.workgroup.as_deref().map(str::trim).filter(|value| {
            !value.is_empty()
                && value.len() <= 15
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ' ')
                })
        }).map(str::to_owned);
        self.netbios_info = Some(NetbiosEvidence {
            hostname: hostname.to_ascii_uppercase(),
            workgroup,
        });
    }

    pub fn set_mac_address(&mut self, mac_address: String) -> bool {
        if !is_valid_unicast_mac(&mac_address) {
            return false;
        }
        self.mac_address = Some(mac_address.to_ascii_lowercase());
        true
    }

    pub fn has_discovery_evidence(&self) -> bool {
        self.tcp_responded
            || self.icmp_round_trip_time.is_some()
            || !self.open_tcp_ports.is_empty()
            || !self.mdns_services.is_empty()
            || !self.ssdp_advertisements.is_empty()
            || self.netbios_info.is_some()
            || self.mac_address.is_some()
    }
}

/// Merge independent protocol results by IPv4 address in deterministic order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceCatalog {
    devices: BTreeMap<Ipv4Addr, DeviceRecord>,
}

impl DeviceCatalog {
    pub fn record_icmp(
        &mut self,
        address: Ipv4Addr,
        round_trip_time: Option<Duration>,
    ) {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .record_icmp(round_trip_time);
    }

    pub fn record_tcp(
        &mut self,
        address: Ipv4Addr,
        responded: bool,
        open_ports: impl IntoIterator<Item = u16>,
    ) {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .record_tcp(responded, open_ports);
    }

    pub fn record_mdns(&mut self, address: Ipv4Addr, evidence: MdnsEvidence) {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .record_mdns(evidence);
    }

    pub fn record_ssdp(&mut self, address: Ipv4Addr, evidence: SsdpEvidence) {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .record_ssdp(evidence);
    }

    pub fn record_netbios(&mut self, address: Ipv4Addr, evidence: NetbiosEvidence) {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .record_netbios(evidence);
    }

    pub fn set_mac_address(&mut self, address: Ipv4Addr, mac_address: String) -> bool {
        self.devices
            .entry(address)
            .or_insert_with(|| DeviceRecord::new(address))
            .set_mac_address(mac_address)
    }

    pub fn clear(&mut self) {
        self.devices.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices.values()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

fn is_valid_unicast_mac(value: &str) -> bool {
    let octets = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>();
    let Ok(octets) = octets else {
        return false;
    };
    octets.len() == 6
        && octets[0] & 1 == 0
        && octets.iter().any(|octet| *octet != 0)
        && octets.iter().any(|octet| *octet != 0xff)
}

#[cfg(test)]
mod tests {
    use super::{DeviceCatalog, MdnsEvidence, NetbiosEvidence, SsdpEvidence, MAX_MDNS_EVIDENCE_PER_DEVICE};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn address() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 20)
    }

    #[test]
    fn merges_tcp_mdns_ssdp_and_mac_evidence_for_one_device() {
        let mut catalog = DeviceCatalog::default();
        catalog.record_tcp(address(), true, [22, 80, 0]);
        catalog.record_mdns(
            address(),
            MdnsEvidence {
                fullname: "Office Printer._ipp._tcp.local.".to_owned(),
                hostname: "printer.local.".to_owned(),
                service_type: "_ipp._tcp.local.".to_owned(),
                port: 631,
            },
        );
        catalog.record_ssdp(
            address(),
            SsdpEvidence {
                search_target: "urn:schemas-upnp-org:device:Basic:1".to_owned(),
                unique_service_name: "uuid:device-1".to_owned(),
                server: Some("Example UPnP/1.0".to_owned()),
                location: Some("http://192.168.1.20/description.xml".to_owned()),
            },
        );
        assert!(catalog.set_mac_address(address(), "02:11:22:33:44:55".to_owned()));

        let device = catalog
            .iter()
            .find(|device| device.address == address())
            .expect("device should be merged");
        assert!(device.tcp_responded);
        assert_eq!(device.open_tcp_ports.iter().copied().collect::<Vec<_>>(), vec![22, 80]);
        assert_eq!(device.mdns_services.len(), 1);
        assert_eq!(device.ssdp_advertisements.len(), 1);
        assert_eq!(device.mac_address.as_deref(), Some("02:11:22:33:44:55"));
        assert!(device.has_discovery_evidence());
        assert_eq!(catalog.len(), 1);
    }

    #[test]
    fn deduplicates_protocol_evidence_and_sorts_devices_by_address() {
        let mut catalog = DeviceCatalog::default();
        catalog.record_tcp(Ipv4Addr::new(192, 168, 1, 30), false, []);
        catalog.record_tcp(address(), true, [443, 443]);
        catalog.record_tcp(address(), false, [80]);

        let service = MdnsEvidence {
            fullname: "Host._ssh._tcp.local.".to_owned(),
            hostname: "host.local.".to_owned(),
            service_type: "_ssh._tcp.local.".to_owned(),
            port: 22,
        };
        catalog.record_mdns(address(), service.clone());
        catalog.record_mdns(address(), service);
        assert_eq!(catalog.len(), 2);
        let first = catalog.iter().next().expect("catalog should not be empty");
        assert_eq!(first.address, address());
        assert_eq!(first.open_tcp_ports.len(), 2);
        assert_eq!(first.mdns_services.len(), 1);
    }

    #[test]
    fn records_icmp_latency_without_claiming_no_reply_means_offline() {
        let mut catalog = DeviceCatalog::default();
        catalog.record_icmp(address(), Some(Duration::from_millis(8)));
        let device = catalog.iter().next().expect("device exists");
        assert!(device.icmp_checked);
        assert_eq!(
            device.icmp_round_trip_time,
            Some(Duration::from_millis(8))
        );
        assert!(device.has_discovery_evidence());

        catalog.record_icmp(address(), None);
        let device = catalog.iter().next().expect("device exists");
        assert!(device.icmp_checked);
        assert_eq!(device.icmp_round_trip_time, None);
        assert!(!device.tcp_responded);
    }

    #[test]
    fn stores_sanitized_netbios_identity_as_unverified_evidence() {
        let mut catalog = DeviceCatalog::default();
        catalog.record_netbios(
            address(),
            NetbiosEvidence {
                hostname: "desktop-test".to_owned(),
                workgroup: Some("workgroup".to_owned()),
            },
        );
        let device = catalog.iter().next().expect("device exists");
        let info = device.netbios_info.as_ref().expect("NetBIOS evidence exists");
        assert_eq!(info.hostname, "DESKTOP-TEST");
        assert_eq!(info.workgroup.as_deref(), Some("workgroup"));

        catalog.record_netbios(
            address(),
            NetbiosEvidence {
                hostname: "invalid\\nname".to_owned(),
                workgroup: None,
            },
        );
        assert_eq!(
            catalog.iter().next().unwrap().netbios_info.as_ref().unwrap().hostname,
            "DESKTOP-TEST"
        );
    }

    #[test]
    fn rejects_invalid_mac_addresses_and_port_zero() {
        let mut catalog = DeviceCatalog::default();
        catalog.record_tcp(address(), false, [0]);
        assert!(!catalog.set_mac_address(address(), "01:11:22:33:44:55".to_owned()));
        assert!(!catalog.set_mac_address(address(), "00:00:00:00:00:00".to_owned()));
        assert!(!catalog.set_mac_address(address(), "not-a-mac".to_owned()));
        let device = catalog
            .iter()
            .find(|device| device.address == address())
            .expect("record exists");
        assert!(device.open_tcp_ports.is_empty());
        assert!(device.mac_address.is_none());
        assert!(!device.has_discovery_evidence());
    }

    #[test]
    fn bounds_per_device_advertisement_memory() {
        let mut catalog = DeviceCatalog::default();
        for index in 0..MAX_MDNS_EVIDENCE_PER_DEVICE + 5 {
            catalog.record_mdns(
                address(),
                MdnsEvidence {
                    fullname: format!("Service {index}._http._tcp.local."),
                    hostname: "host.local.".to_owned(),
                    service_type: "_http._tcp.local.".to_owned(),
                    port: 8000 + index as u16,
                },
            );
        }
        assert_eq!(
            catalog
                .iter()
                .find(|device| device.address == address())
                .expect("record exists")
                .mdns_services
                .len(),
            MAX_MDNS_EVIDENCE_PER_DEVICE
        );
    }

    #[test]
    fn deduplicates_ssdp_advertisements_case_insensitively() {
        let mut catalog = DeviceCatalog::default();
        let first = SsdpEvidence {
            search_target: "upnp:rootdevice".to_owned(),
            unique_service_name: "uuid:abc".to_owned(),
            server: None,
            location: None,
        };
        let mut second = first.clone();
        second.search_target = "UPNP:ROOTDEVICE".to_owned();
        second.unique_service_name = "UUID:ABC".to_owned();
        catalog.record_ssdp(address(), first);
        catalog.record_ssdp(address(), second);
        assert_eq!(
            catalog
                .iter()
                .find(|device| device.address == address())
                .expect("record exists")
                .ssdp_advertisements
                .len(),
            1
        );
    }
}
