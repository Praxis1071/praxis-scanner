use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use adw::prelude::*;
use gtk::glib;

use crate::preferences::{AppPreferences, ThemeMode};
use crate::network::cidr::Ipv4Network;
use crate::network::device::{DeviceCatalog, DeviceRecord, MdnsEvidence, NetbiosEvidence, SsdpEvidence};
use crate::network::mdns::{self, MdnsEvent, MdnsHandle};
use crate::network::netbios::{self, NetbiosEvent, NetbiosHandle};
use crate::network::ssdp::{self, SsdpEvent, SsdpHandle};
use crate::network::scanner::{
    self, HostScanResult, ScanEvent, ScanHandle, MAX_SCAN_TARGETS,
};
use crate::network::{self, NetworkInterface};

pub fn build_ui(application: &adw::Application) {
    let header = adw::HeaderBar::new();
    let refresh_button = gtk::Button::with_label("Refresh");
    refresh_button.set_tooltip_text(Some("Refresh local network interfaces"));
    header.pack_end(&refresh_button);
    let settings_button = gtk::Button::from_icon_name("emblem-system-symbolic");
    settings_button.set_tooltip_text(Some("Settings"));
    header.pack_end(&settings_button);

    let heading = gtk::Label::new(Some("Local network interfaces"));
    heading.add_css_class("title-2");
    heading.set_halign(gtk::Align::Start);
    heading.set_margin_start(18);
    heading.set_margin_top(18);
    heading.set_margin_bottom(8);

    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    list.add_css_class("boxed-list");
    list.set_margin_start(18);
    list.set_margin_end(18);

    let system_info = gtk::Label::new(Some("Reading route and neighbour information…"));
    system_info.set_halign(gtk::Align::Start);
    system_info.set_wrap(true);
    system_info.set_margin_start(18);
    system_info.set_margin_end(18);
    system_info.set_margin_top(8);
    system_info.add_css_class("dim-label");

    let devices_heading = gtk::Label::new(Some("Discovered devices"));
    devices_heading.add_css_class("title-2");
    devices_heading.set_halign(gtk::Align::Start);
    devices_heading.set_margin_start(18);
    devices_heading.set_margin_top(18);
    devices_heading.set_margin_bottom(8);

    let devices_list = gtk::ListBox::new();
    devices_list.set_selection_mode(gtk::SelectionMode::None);
    devices_list.add_css_class("boxed-list");
    devices_list.set_margin_start(18);
    devices_list.set_margin_end(18);

    let ports_heading = gtk::Label::new(Some("TCP ports (comma-separated)"));
    ports_heading.set_halign(gtk::Align::Start);
    ports_heading.set_margin_start(18);
    ports_heading.set_margin_top(12);

    let port_entry = gtk::Entry::new();
    let default_ports = scanner::DEFAULT_TCP_PORTS
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    port_entry.set_text(&default_ports);
    port_entry.set_placeholder_text(Some("22, 53, 80, 443"));
    port_entry.set_max_length(1024);
    port_entry.set_margin_start(18);
    port_entry.set_margin_end(18);

    let scan_button = gtk::Button::with_label("Scan selected network");
    scan_button.add_css_class("suggested-action");
    scan_button.set_sensitive(false);
    scan_button.set_halign(gtk::Align::Start);
    scan_button.set_margin_start(18);
    scan_button.set_margin_top(12);

    let mdns_button = gtk::Button::with_label("Discover advertised services (mDNS)");
    mdns_button.set_sensitive(false);
    mdns_button.set_halign(gtk::Align::Start);
    mdns_button.set_margin_start(18);
    mdns_button.set_margin_top(8);

    let ssdp_button = gtk::Button::with_label("Discover UPnP devices (SSDP)");
    ssdp_button.set_sensitive(false);
    ssdp_button.set_halign(gtk::Align::Start);
    ssdp_button.set_margin_start(18);
    ssdp_button.set_margin_top(8);

    let netbios_button = gtk::Button::with_label("Discover NetBIOS names");
    netbios_button.set_sensitive(false);
    netbios_button.set_halign(gtk::Align::Start);
    netbios_button.set_margin_start(18);
    netbios_button.set_margin_top(8);

    let netbios_note = gtk::Label::new(Some(
        "Queries NBSTAT names only from devices already discovered on the selected local network. Names and workgroups are unverified network-provided data.",
    ));
    netbios_note.set_halign(gtk::Align::Start);
    netbios_note.set_wrap(true);
    netbios_note.set_margin_start(18);
    netbios_note.set_margin_end(18);
    netbios_note.add_css_class("dim-label");

    let ssdp_note = gtk::Label::new(Some(
        "Sends one SSDP M-SEARCH multicast query on the selected IPv4 interface. Responses are unauthenticated; device-description URLs are shown only as untrusted text and are never downloaded.",
    ));
    ssdp_note.set_halign(gtk::Align::Start);
    ssdp_note.set_wrap(true);
    ssdp_note.set_margin_start(18);
    ssdp_note.set_margin_end(18);
    ssdp_note.add_css_class("dim-label");

    let mdns_note = gtk::Label::new(Some(
        "mDNS/DNS-SD sends multicast queries on the selected interface only. Responses are unauthenticated and may be spoofed; use on trusted local networks. It does not identify every device.",
    ));
    mdns_note.set_halign(gtk::Align::Start);
    mdns_note.set_wrap(true);
    mdns_note.set_margin_start(18);
    mdns_note.set_margin_end(18);
    mdns_note.add_css_class("dim-label");

    let scope_note = gtk::Label::new(Some(
        "Scans use ordinary TCP connections on the selected private or link-local subnet. Up to 256 unique ports and 1024 addresses are allowed; timeouts do not prove a device is offline.",
    ));
    scope_note.set_halign(gtk::Align::Start);
    scope_note.set_wrap(true);
    scope_note.set_margin_start(18);
    scope_note.set_margin_end(18);
    scope_note.set_margin_top(6);
    scope_note.add_css_class("dim-label");

    let results_heading = gtk::Label::new(Some("Scan results"));
    results_heading.add_css_class("title-2");
    results_heading.set_halign(gtk::Align::Start);
    results_heading.set_margin_start(18);
    results_heading.set_margin_top(18);
    results_heading.set_margin_bottom(8);

    let results_list = gtk::ListBox::new();
    results_list.set_selection_mode(gtk::SelectionMode::None);
    results_list.add_css_class("boxed-list");
    results_list.set_margin_start(18);
    results_list.set_margin_end(18);

    let mdns_results_heading = gtk::Label::new(Some("Advertised mDNS services"));
    mdns_results_heading.add_css_class("title-2");
    mdns_results_heading.set_halign(gtk::Align::Start);
    mdns_results_heading.set_margin_start(18);
    mdns_results_heading.set_margin_top(18);
    mdns_results_heading.set_margin_bottom(8);

    let mdns_results_list = gtk::ListBox::new();
    mdns_results_list.set_selection_mode(gtk::SelectionMode::None);
    mdns_results_list.add_css_class("boxed-list");
    mdns_results_list.set_margin_start(18);
    mdns_results_list.set_margin_end(18);

    let ssdp_results_heading = gtk::Label::new(Some("Discovered UPnP devices (SSDP)"));
    ssdp_results_heading.add_css_class("title-2");
    ssdp_results_heading.set_halign(gtk::Align::Start);
    ssdp_results_heading.set_margin_start(18);
    ssdp_results_heading.set_margin_top(18);
    ssdp_results_heading.set_margin_bottom(8);

    let ssdp_results_list = gtk::ListBox::new();
    ssdp_results_list.set_selection_mode(gtk::SelectionMode::None);
    ssdp_results_list.add_css_class("boxed-list");
    ssdp_results_list.set_margin_start(18);
    ssdp_results_list.set_margin_end(18);

    let status = gtk::Label::new(Some("Reading local interface information…"));
    status.set_halign(gtk::Align::Start);
    status.set_wrap(true);
    status.set_margin_start(18);
    status.set_margin_end(18);
    status.set_margin_top(12);
    status.set_margin_bottom(12);
    status.add_css_class("dim-label");

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&header);
    content.append(&heading);
    content.append(&list);
    content.append(&system_info);
    content.append(&devices_heading);
    content.append(&devices_list);
    content.append(&ports_heading);
    content.append(&port_entry);
    content.append(&scan_button);
    content.append(&mdns_button);
    content.append(&mdns_note);
    content.append(&ssdp_button);
    content.append(&ssdp_note);
    content.append(&netbios_button);
    content.append(&netbios_note);
    content.append(&scope_note);
    content.append(&results_heading);
    content.append(&results_list);
    content.append(&mdns_results_heading);
    content.append(&mdns_results_list);
    content.append(&ssdp_results_heading);
    content.append(&ssdp_results_list);
    content.append(&status);

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&content)
        .build();

    let navigation_view = adw::NavigationView::new();
    let home_page = adw::NavigationPage::builder()
        .title("Praxis Scanner")
        .child(&scrolled)
        .build();
    navigation_view.push(&home_page);

    let preferences = Rc::new(RefCell::new(AppPreferences::load()));
    apply_theme(preferences.borrow().theme);

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Praxis Scanner")
        .default_width(900)
        .default_height(700)
        .content(&navigation_view)
        .build();

    let navigation_for_settings = navigation_view.clone();
    let window_for_settings = window.clone();
    let preferences_for_settings = Rc::clone(&preferences);
    settings_button.connect_clicked(move |_| {
        let page = settings_page(
            &navigation_for_settings,
            &window_for_settings,
            Rc::clone(&preferences_for_settings),
        );
        navigation_for_settings.push(&page);
    });

    let interfaces = Rc::new(RefCell::new(Vec::<NetworkInterface>::new()));
    let selected_interface = Rc::new(RefCell::new(None::<NetworkInterface>));
    let active_scan = Rc::new(RefCell::new(None::<ScanHandle>));
    let active_device_scan = Rc::new(RefCell::new(None::<ScanHandle>));
    let active_mdns = Rc::new(RefCell::new(None::<MdnsHandle>));
    let active_ssdp = Rc::new(RefCell::new(None::<SsdpHandle>));
    let active_netbios = Rc::new(RefCell::new(None::<NetbiosHandle>));
    let device_catalog = Rc::new(RefCell::new(DeviceCatalog::default()));

    let interfaces_for_selection = Rc::clone(&interfaces);
    let selected_for_selection = Rc::clone(&selected_interface);
    let catalog_for_selection = Rc::clone(&device_catalog);
    let devices_for_selection = devices_list.clone();
    let scan_button_for_selection = scan_button.clone();
    let mdns_button_for_selection = mdns_button.clone();
    let ssdp_button_for_selection = ssdp_button.clone();
    let netbios_button_for_selection = netbios_button.clone();
    let status_for_selection = status.clone();
    list.connect_row_selected(move |_, row| {
        let selected = row.and_then(|row| {
            interfaces_for_selection
                .borrow()
                .get(row.index() as usize)
                .cloned()
        });
        let previous = selected_for_selection.borrow().clone();
        let changed = previous.as_ref().map(|item| (item.name.as_str(), item.address))
            != selected.as_ref().map(|item| (item.name.as_str(), item.address));
        if changed {
            catalog_for_selection.borrow_mut().clear();
            clear_list(&devices_for_selection);
        }
        let can_scan = selected.as_ref().is_some_and(is_scannable_interface);
        scan_button_for_selection.set_sensitive(can_scan);
        mdns_button_for_selection.set_sensitive(can_scan);
        ssdp_button_for_selection.set_sensitive(can_scan);
        netbios_button_for_selection.set_sensitive(can_scan);
        if let Some(interface) = selected.as_ref() {
            status_for_selection.set_text(&format!(
                "Selected {} ({}/{}). Press Scan selected network to begin; no scan starts automatically.",
                interface.name,
                interface.address,
                interface.prefix.map_or_else(|| "?".to_owned(), |prefix| prefix.to_string())
            ));
        }
        *selected_for_selection.borrow_mut() = selected;
    });

    let list_for_refresh = list.clone();
    let status_for_refresh = status.clone();
    let system_info_for_refresh = system_info.clone();
    let interfaces_for_refresh = Rc::clone(&interfaces);
    let selected_for_refresh = Rc::clone(&selected_interface);
    let scan_button_for_refresh = scan_button.clone();
    let mdns_button_for_refresh = mdns_button.clone();
    let ssdp_button_for_refresh = ssdp_button.clone();
    let netbios_button_for_refresh = netbios_button.clone();
    refresh_button.connect_clicked(move |_| {
        refresh_interfaces(
            RefreshWidgets {
                list: &list_for_refresh,
                status: &status_for_refresh,
                system_info: &system_info_for_refresh,
                scan_button: &scan_button_for_refresh,
                mdns_button: &mdns_button_for_refresh,
                ssdp_button: &ssdp_button_for_refresh,
                netbios_button: &netbios_button_for_refresh,
            },
            &interfaces_for_refresh,
            &selected_for_refresh,
        );
    });

    let status_for_scan = status.clone();
    let results_for_scan = results_list.clone();
    let button_for_scan = scan_button.clone();
    let selected_for_scan = Rc::clone(&selected_interface);
    let active_for_scan = Rc::clone(&active_scan);
    let catalog_for_scan = Rc::clone(&device_catalog);
    let devices_for_scan = devices_list.clone();
    let refresh_button_for_scan = refresh_button.clone();
    let port_entry_for_scan = port_entry.clone();
    let interface_list_for_scan = list.clone();
    let port_entry_for_sensitivity = port_entry.clone();
    let mdns_button_for_tcp = mdns_button.clone();
    let ssdp_button_for_tcp = ssdp_button.clone();
    let netbios_button_for_tcp = netbios_button.clone();
    let active_mdns_for_tcp = Rc::clone(&active_mdns);
    let active_ssdp_for_tcp = Rc::clone(&active_ssdp);
    let active_netbios_for_tcp = Rc::clone(&active_netbios);
    scan_button.connect_clicked(move |_| {
        if let Some(handle) = active_for_scan.borrow().as_ref() {
            handle.cancel();
            status_for_scan.set_text(
                "Cancellation requested. Waiting for in-flight TCP connection attempts to finish…",
            );
            button_for_scan.set_label("Cancelling…");
            return;
        }

        if active_mdns_for_tcp.borrow().is_some() || active_ssdp_for_tcp.borrow().is_some() || active_netbios_for_tcp.borrow().is_some() {
            status_for_scan.set_text("Wait for the active service-discovery operation to finish first.");
            return;
        }
        let Some(interface) = selected_for_scan.borrow().clone() else {
            status_for_scan.set_text("Select an IPv4 network interface first.");
            return;
        };
        if !interface.is_up || interface.is_loopback || interface.address.is_unspecified() {
            status_for_scan.set_text(
                "Select an active, non-loopback IPv4 interface with a usable address.",
            );
            return;
        }
        if !interface.address.is_private() && !interface.address.is_link_local() {
            status_for_scan.set_text(
                "For safety, scanning is limited to private IPv4 and link-local interfaces.",
            );
            return;
        }
        let Some(prefix) = interface.prefix else {
            status_for_scan.set_text(
                "The selected interface has no valid contiguous IPv4 netmask.",
            );
            return;
        };

        let network = match Ipv4Network::from_interface(
            interface.address,
            prefix,
            MAX_SCAN_TARGETS as u32,
        ) {
            Ok(network) => network,
            Err(error) => {
                status_for_scan.set_text(&format!("Cannot scan this subnet: {error}"));
                return;
            }
        };
        let mut hosts = network.hosts();
        hosts.retain(|address| *address != interface.address);
        if hosts.is_empty() {
            status_for_scan.set_text("The selected subnet has no other candidate addresses.");
            return;
        }

        while let Some(child) = results_for_scan.first_child() {
            results_for_scan.remove(&child);
        }

        let ports = match scanner::parse_tcp_ports(&port_entry_for_scan.text()) {
            Ok(ports) => ports,
            Err(error) => {
                status_for_scan.set_text(&format!("Invalid TCP port list: {error}"));
                return;
            }
        };
        let target_count = hosts.len();
        let port_count = ports.len();
        let selected_interface_name = interface.name.clone();
        match scanner::start_tcp_discovery_with_ports(
            hosts,
            ports,
            scanner::DEFAULT_TCP_TIMEOUT,
        ) {
            Ok((handle, events)) => {
                *active_for_scan.borrow_mut() = Some(handle);
                button_for_scan.set_label("Cancel scan");
                refresh_button_for_scan.set_sensitive(false);
                interface_list_for_scan.set_sensitive(false);
                port_entry_for_sensitivity.set_sensitive(false);
                mdns_button_for_tcp.set_sensitive(false);
                ssdp_button_for_tcp.set_sensitive(false);
                netbios_button_for_tcp.set_sensitive(false);
                status_for_scan.set_text(&format!(
                    "Scanning {target_count} target(s) across {port_count} TCP port(s) on {}/{} using unprivileged TCP connections…",
                    network.address(),
                    network.prefix()
                ));

                let status_for_events = status_for_scan.clone();
                let results_for_events = results_for_scan.clone();
                let button_for_events = button_for_scan.clone();
                let refresh_for_events = refresh_button_for_scan.clone();
                let interface_list_for_events = interface_list_for_scan.clone();
                let port_entry_for_events = port_entry_for_sensitivity.clone();
                let mdns_button_for_events = mdns_button_for_tcp.clone();
                let ssdp_button_for_events = ssdp_button_for_tcp.clone();
                let netbios_button_for_events = netbios_button_for_tcp.clone();
                let active_for_events = Rc::clone(&active_for_scan);
                let selected_for_events = Rc::clone(&selected_for_scan);
                let catalog_for_events = Rc::clone(&catalog_for_scan);
                let devices_for_events = devices_for_scan.clone();
                let navigation_for_events = navigation_view.clone();
                let mut completed = 0usize;
                let mut responsive = 0usize;
                let mut inconclusive = 0usize;
                let mut result_rows = Vec::<(std::net::Ipv4Addr, adw::ActionRow, String)>::new();
                glib::timeout_add_local(Duration::from_millis(100), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            ScanEvent::HostCompleted(result) => {
                                catalog_for_events.borrow_mut().record_tcp(
                                    result.address,
                                    result.tcp_responded,
                                    result.open_ports.iter().copied(),
                                );
                                refresh_device_list(&devices_for_events, &catalog_for_events.borrow(), &navigation_for_events);
                                completed += 1;
                                if result.tcp_responded {
                                    responsive += 1;
                                    let details = result_details(&result);
                                    let row = result_row(&result, &details);
                                    results_for_events.append(&row);
                                    result_rows.push((result.address, row, details));
                                } else {
                                    inconclusive += 1;
                                }
                                status_for_events.set_text(&format!(
                                    "Checked {completed} of {target_count}: {responsive} TCP responders, {inconclusive} without a response (inconclusive)."
                                ));
                            }
                            ScanEvent::Finished {
                                total,
                                completed: finished_count,
                                cancelled,
                            } => {
                                *active_for_events.borrow_mut() = None;
                                button_for_events.set_label("Scan selected network");
                                refresh_for_events.set_sensitive(true);
                                interface_list_for_events.set_sensitive(true);
                                port_entry_for_events.set_sensitive(true);
                                mdns_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                ssdp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                netbios_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                let mac_summary = match network::system::read_ipv4_neighbours() {
                                    Ok(neighbours) => {
                                        let mac_by_address: HashMap<_, _> = neighbours
                                            .into_iter()
                                            .filter(|neighbour| neighbour.interface == selected_interface_name)
                                            .map(|neighbour| (neighbour.address, neighbour.hardware_address))
                                            .collect();
                                        for (address, mac) in &mac_by_address {
                                            catalog_for_events.borrow_mut().set_mac_address(*address, mac.clone());
                                        }
                                        refresh_device_list(&devices_for_events, &catalog_for_events.borrow(), &navigation_for_events);
                                        let mut enriched = 0usize;
                                        for (address, row, details) in &result_rows {
                                            if let Some(mac) = mac_by_address.get(address) {
                                                row.set_subtitle(&format!("{details}\nMAC address: {mac}"));
                                                enriched += 1;
                                            }
                                        }
                                        format!("{enriched} MAC address(es) available from the neighbour table")
                                    }
                                    Err(_) => "MAC information unavailable".to_owned(),
                                };
                                let state = if cancelled { "cancelled" } else { "finished" };
                                status_for_events.set_text(&format!(
                                    "Scan {state}: {finished_count} of {total} checked; {responsive} TCP responders; {inconclusive} without a response (not proof they are offline); {mac_summary}."
                                ));
                                return glib::ControlFlow::Break;
                            }
                        }
                    }
                    glib::ControlFlow::Continue
                });
            }
            Err(error) => status_for_scan.set_text(&format!("Could not start scan: {error}")),
        }
    });

    let status_for_mdns = status.clone();
    let mdns_button_for_scan = mdns_button.clone();
    let selected_for_mdns = Rc::clone(&selected_interface);
    let active_mdns_for_scan = Rc::clone(&active_mdns);
    let active_tcp_for_mdns = Rc::clone(&active_scan);
    let active_ssdp_for_mdns = Rc::clone(&active_ssdp);
    let active_netbios_for_mdns = Rc::clone(&active_netbios);
    let ssdp_button_for_mdns = ssdp_button.clone();
    let netbios_button_for_mdns = netbios_button.clone();
    let refresh_for_mdns = refresh_button.clone();
    let interface_list_for_mdns = list.clone();
    let port_entry_for_mdns = port_entry.clone();
    let tcp_button_for_mdns = scan_button.clone();
    let mdns_results_for_scan = mdns_results_list.clone();
    let catalog_for_mdns = Rc::clone(&device_catalog);
    let devices_for_mdns = devices_list.clone();
    mdns_button.connect_clicked(move |_| {
        if let Some(handle) = active_mdns_for_scan.borrow().as_ref() {
            handle.cancel();
            mdns_button_for_scan.set_label("Cancelling mDNS…");
            status_for_mdns.set_text("mDNS cancellation requested; waiting for the discovery worker to stop.");
            return;
        }
        if active_tcp_for_mdns.borrow().is_some() || active_ssdp_for_mdns.borrow().is_some() || active_netbios_for_mdns.borrow().is_some() {
            status_for_mdns.set_text("Wait for the active scan or SSDP discovery to finish before starting mDNS discovery.");
            return;
        }

        let Some(interface) = selected_for_mdns.borrow().clone() else {
            status_for_mdns.set_text("Select an eligible IPv4 network interface first.");
            return;
        };
        if !is_scannable_interface(&interface) {
            status_for_mdns.set_text("Select an active private or link-local IPv4 interface first.");
            return;
        }
        let Some(prefix) = interface.prefix else {
            status_for_mdns.set_text("The selected interface has no valid IPv4 netmask.");
            return;
        };
        let network = match Ipv4Network::from_interface(
            interface.address,
            prefix,
            MAX_SCAN_TARGETS as u32,
        ) {
            Ok(network) => network,
            Err(error) => {
                status_for_mdns.set_text(&format!("Cannot discover services on this subnet: {error}"));
                return;
            }
        };
        let mut allowed_addresses = network.hosts();
        allowed_addresses.retain(|address| *address != interface.address);
        if allowed_addresses.is_empty() {
            status_for_mdns.set_text("The selected subnet has no other candidate addresses.");
            return;
        }

        while let Some(child) = mdns_results_for_scan.first_child() {
            mdns_results_for_scan.remove(&child);
        }

        match mdns::start_mdns_discovery(
            interface.name.clone(),
            allowed_addresses,
            mdns::DEFAULT_MDNS_WINDOW,
        ) {
            Ok((handle, events)) => {
                *active_mdns_for_scan.borrow_mut() = Some(handle);
                mdns_button_for_scan.set_label("Cancel mDNS discovery");
                tcp_button_for_mdns.set_sensitive(false);
                ssdp_button_for_mdns.set_sensitive(false);
                netbios_button_for_mdns.set_sensitive(false);
                refresh_for_mdns.set_sensitive(false);
                interface_list_for_mdns.set_sensitive(false);
                port_entry_for_mdns.set_sensitive(false);
                status_for_mdns.set_text(&format!(
                    "Querying DNS-SD services on {} ({}/{}) for up to {} seconds…",
                    interface.name,
                    network.address(),
                    network.prefix(),
                    mdns::DEFAULT_MDNS_WINDOW.as_secs()
                ));

                let status_for_events = status_for_mdns.clone();
                let mdns_button_for_events = mdns_button_for_scan.clone();
                let tcp_button_for_events = tcp_button_for_mdns.clone();
                let ssdp_button_for_events = ssdp_button_for_mdns.clone();
                let netbios_button_for_events = netbios_button_for_mdns.clone();
                let refresh_for_events = refresh_for_mdns.clone();
                let interface_list_for_events = interface_list_for_mdns.clone();
                let port_entry_for_events = port_entry_for_mdns.clone();
                let results_for_events = mdns_results_for_scan.clone();
                let active_for_events = Rc::clone(&active_mdns_for_scan);
                let selected_for_events = Rc::clone(&selected_for_mdns);
                let catalog_for_events = Rc::clone(&catalog_for_mdns);
                let devices_for_events = devices_for_mdns.clone();
                let navigation_for_events = navigation_view.clone();

                glib::timeout_add_local(Duration::from_millis(100), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            MdnsEvent::ServiceFound(service) => {
                                catalog_for_events.borrow_mut().record_mdns(
                                    service.address,
                                    MdnsEvidence {
                                        fullname: service.fullname.clone(),
                                        hostname: service.hostname.clone(),
                                        service_type: service.service_type.clone(),
                                        port: service.port,
                                    },
                                );
                                refresh_device_list(&devices_for_events, &catalog_for_events.borrow(), &navigation_for_events);
                                let details = format!(
                                    "{}  ·  {}:{}  ·  {}",
                                    service.hostname,
                                    service.address,
                                    service.port,
                                    service.service_type
                                );
                                let row = adw::ActionRow::builder()
                                    .title(&service.fullname)
                                    .subtitle(&details)
                                    .activatable(false)
                                    .build();
                                results_for_events.append(&row);
                            }
                            MdnsEvent::Failed(error) => {
                                active_for_events.borrow_mut().take();
                                mdns_button_for_events.set_label("Discover advertised services (mDNS)");
                                mdns_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                tcp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                ssdp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                netbios_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                refresh_for_events.set_sensitive(true);
                                interface_list_for_events.set_sensitive(true);
                                port_entry_for_events.set_sensitive(true);
                                status_for_events.set_text(&format!("mDNS discovery failed: {error}"));
                                return glib::ControlFlow::Break;
                            }
                            MdnsEvent::Finished { services, cancelled } => {
                                active_for_events.borrow_mut().take();
                                mdns_button_for_events.set_label("Discover advertised services (mDNS)");
                                mdns_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                tcp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                ssdp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                netbios_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                refresh_for_events.set_sensitive(true);
                                interface_list_for_events.set_sensitive(true);
                                port_entry_for_events.set_sensitive(true);
                                let state = if cancelled { "cancelled" } else { "finished" };
                                status_for_events.set_text(&format!(
                                    "mDNS discovery {state}: {services} advertised service instance(s) found. Results are limited to the selected IPv4 subnet."
                                ));
                                return glib::ControlFlow::Break;
                            }
                        }
                    }
                    glib::ControlFlow::Continue
                });
            }
            Err(error) => {
                status_for_mdns.set_text(&format!("Could not start mDNS discovery: {error}"));
            }
        }
    });

    let status_for_ssdp = status.clone();
    let ssdp_button_for_scan = ssdp_button.clone();
    let selected_for_ssdp = Rc::clone(&selected_interface);
    let active_ssdp_for_scan = Rc::clone(&active_ssdp);
    let active_tcp_for_ssdp = Rc::clone(&active_scan);
    let active_mdns_for_ssdp = Rc::clone(&active_mdns);
    let active_netbios_for_ssdp = Rc::clone(&active_netbios);
    let refresh_for_ssdp = refresh_button.clone();
    let interface_list_for_ssdp = list.clone();
    let port_entry_for_ssdp = port_entry.clone();
    let tcp_button_for_ssdp = scan_button.clone();
    let mdns_button_for_ssdp = mdns_button.clone();
    let netbios_button_for_ssdp = netbios_button.clone();
    let ssdp_results_for_scan = ssdp_results_list.clone();
    let catalog_for_ssdp = Rc::clone(&device_catalog);
    let devices_for_ssdp = devices_list.clone();
    ssdp_button.connect_clicked(move |_| {
        if let Some(handle) = active_ssdp_for_scan.borrow().as_ref() {
            handle.cancel();
            ssdp_button_for_scan.set_label("Cancelling SSDP…");
            status_for_ssdp.set_text("SSDP cancellation requested; waiting for the discovery worker to stop.");
            return;
        }
        if active_tcp_for_ssdp.borrow().is_some() || active_mdns_for_ssdp.borrow().is_some() || active_netbios_for_ssdp.borrow().is_some() {
            status_for_ssdp.set_text("Wait for the active scan to finish before starting SSDP discovery.");
            return;
        }

        let Some(interface) = selected_for_ssdp.borrow().clone() else {
            status_for_ssdp.set_text("Select an eligible IPv4 network interface first.");
            return;
        };
        if !is_scannable_interface(&interface) {
            status_for_ssdp.set_text("Select an active private or link-local IPv4 interface first.");
            return;
        }
        let Some(prefix) = interface.prefix else {
            status_for_ssdp.set_text("The selected interface has no valid IPv4 netmask.");
            return;
        };
        let network = match Ipv4Network::from_interface(
            interface.address,
            prefix,
            MAX_SCAN_TARGETS as u32,
        ) {
            Ok(network) => network,
            Err(error) => {
                status_for_ssdp.set_text(&format!("Cannot discover devices on this subnet: {error}"));
                return;
            }
        };
        let mut allowed_addresses = network.hosts();
        allowed_addresses.retain(|address| *address != interface.address);
        if allowed_addresses.is_empty() {
            status_for_ssdp.set_text("The selected subnet has no other candidate addresses.");
            return;
        }

        while let Some(child) = ssdp_results_for_scan.first_child() {
            ssdp_results_for_scan.remove(&child);
        }

        match ssdp::start_ssdp_discovery(
            interface.address,
            allowed_addresses,
            ssdp::DEFAULT_SSDP_WINDOW,
        ) {
            Ok((handle, events)) => {
                *active_ssdp_for_scan.borrow_mut() = Some(handle);
                ssdp_button_for_scan.set_label("Cancel SSDP discovery");
                tcp_button_for_ssdp.set_sensitive(false);
                mdns_button_for_ssdp.set_sensitive(false);
                netbios_button_for_ssdp.set_sensitive(false);
                refresh_for_ssdp.set_sensitive(false);
                interface_list_for_ssdp.set_sensitive(false);
                port_entry_for_ssdp.set_sensitive(false);
                status_for_ssdp.set_text(&format!(
                    "Sending one SSDP M-SEARCH query on {} ({}/{}) for up to {} seconds…",
                    interface.name,
                    network.address(),
                    network.prefix(),
                    ssdp::DEFAULT_SSDP_WINDOW.as_secs()
                ));

                let status_for_events = status_for_ssdp.clone();
                let ssdp_button_for_events = ssdp_button_for_scan.clone();
                let tcp_button_for_events = tcp_button_for_ssdp.clone();
                let mdns_button_for_events = mdns_button_for_ssdp.clone();
                let netbios_button_for_events = netbios_button_for_ssdp.clone();
                let refresh_for_events = refresh_for_ssdp.clone();
                let interface_list_for_events = interface_list_for_ssdp.clone();
                let port_entry_for_events = port_entry_for_ssdp.clone();
                let results_for_events = ssdp_results_for_scan.clone();
                let active_for_events = Rc::clone(&active_ssdp_for_scan);
                let selected_for_events = Rc::clone(&selected_for_ssdp);
                let catalog_for_events = Rc::clone(&catalog_for_ssdp);
                let devices_for_events = devices_for_ssdp.clone();
                let navigation_for_events = navigation_view.clone();

                glib::timeout_add_local(Duration::from_millis(100), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            SsdpEvent::DeviceFound(device) => {
                                catalog_for_events.borrow_mut().record_ssdp(
                                    device.address,
                                    SsdpEvidence {
                                        search_target: device.search_target.clone(),
                                        unique_service_name: device.unique_service_name.clone(),
                                        server: device.server.clone(),
                                        location: device.location.clone(),
                                    },
                                );
                                refresh_device_list(&devices_for_events, &catalog_for_events.borrow(), &navigation_for_events);
                                let server = device.server.as_deref().unwrap_or("server header not supplied");
                                let location = device.location.as_deref().unwrap_or("location not supplied");
                                let details = format!(
                                    "{}  ·  {}  ·  {server}  ·  untrusted location (not fetched): {location}",
                                    device.address,
                                    device.search_target
                                );
                                let row = adw::ActionRow::builder()
                                    .title(&device.unique_service_name)
                                    .subtitle(&details)
                                    .activatable(false)
                                    .build();
                                results_for_events.append(&row);
                            }
                            SsdpEvent::Failed(error) => {
                                active_for_events.borrow_mut().take();
                                ssdp_button_for_events.set_label("Discover UPnP devices (SSDP)");
                                ssdp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                tcp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                mdns_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                netbios_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                refresh_for_events.set_sensitive(true);
                                interface_list_for_events.set_sensitive(true);
                                port_entry_for_events.set_sensitive(true);
                                status_for_events.set_text(&format!("SSDP discovery failed: {error}"));
                                return glib::ControlFlow::Break;
                            }
                            SsdpEvent::Finished { responses, cancelled } => {
                                active_for_events.borrow_mut().take();
                                ssdp_button_for_events.set_label("Discover UPnP devices (SSDP)");
                                ssdp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                tcp_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                mdns_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                netbios_button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                refresh_for_events.set_sensitive(true);
                                interface_list_for_events.set_sensitive(true);
                                port_entry_for_events.set_sensitive(true);
                                let state = if cancelled { "cancelled" } else { "finished" };
                                status_for_events.set_text(&format!(
                                    "SSDP discovery {state}: {responses} response(s) received from the selected IPv4 subnet. Responses are unverified."
                                ));
                                return glib::ControlFlow::Break;
                            }
                        }
                    }
                    glib::ControlFlow::Continue
                });
            }
            Err(error) => {
                status_for_ssdp.set_text(&format!("Could not start SSDP discovery: {error}"));
            }
        }
    });

    let status_for_netbios = status.clone();
    let netbios_button_for_scan = netbios_button.clone();
    let selected_for_netbios = Rc::clone(&selected_interface);
    let catalog_for_netbios = Rc::clone(&device_catalog);
    let devices_for_netbios = devices_list.clone();
    let navigation_for_netbios = navigation_view.clone();
    let active_netbios_for_scan = Rc::clone(&active_netbios);
    let active_tcp_for_netbios = Rc::clone(&active_scan);
    let active_mdns_for_netbios = Rc::clone(&active_mdns);
    let active_ssdp_for_netbios = Rc::clone(&active_ssdp);
    let interface_list_for_netbios = list.clone();
    let refresh_for_netbios = refresh_button.clone();
    let tcp_button_for_netbios = scan_button.clone();
    let mdns_button_for_netbios = mdns_button.clone();
    let ssdp_button_for_netbios = ssdp_button.clone();
    netbios_button.connect_clicked(move |_| {
        if let Some(handle) = active_netbios_for_scan.borrow().as_ref() {
            handle.cancel();
            netbios_button_for_scan.set_label("Cancelling NetBIOS discovery…");
            status_for_netbios.set_text("NetBIOS cancellation requested; waiting for outstanding UDP queries to finish.");
            return;
        }
        if active_tcp_for_netbios.borrow().is_some()
            || active_mdns_for_netbios.borrow().is_some()
            || active_ssdp_for_netbios.borrow().is_some()
        {
            status_for_netbios.set_text("Wait for the active scan or service-discovery operation to finish first.");
            return;
        }
        let Some(interface) = selected_for_netbios.borrow().clone() else {
            status_for_netbios.set_text("Select an eligible IPv4 interface first.");
            return;
        };
        if !is_scannable_interface(&interface) {
            status_for_netbios.set_text("Select an active private or link-local IPv4 interface first.");
            return;
        }

        let targets = catalog_for_netbios
            .borrow()
            .iter()
            .filter(|device| device.has_discovery_evidence())
            .map(|device| device.address)
            .filter(|address| *address != interface.address)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            status_for_netbios.set_text("No other discovered devices are available. Run a TCP, mDNS, or SSDP discovery first.");
            return;
        }

        match netbios::start_discovery(interface.address, targets.clone(), netbios::DEFAULT_TIMEOUT) {
            Ok((handle, events)) => {
                *active_netbios_for_scan.borrow_mut() = Some(handle);
                netbios_button_for_scan.set_label("Cancel NetBIOS discovery");
                interface_list_for_netbios.set_sensitive(false);
                refresh_for_netbios.set_sensitive(false);
                tcp_button_for_netbios.set_sensitive(false);
                mdns_button_for_netbios.set_sensitive(false);
                ssdp_button_for_netbios.set_sensitive(false);
                status_for_netbios.set_text(&format!(
                    "Querying NetBIOS NBSTAT names for {} previously discovered device(s)…",
                    targets.len()
                ));

                let status_for_events = status_for_netbios.clone();
                let button_for_events = netbios_button_for_scan.clone();
                let selected_for_events = Rc::clone(&selected_for_netbios);
                let interface_list_for_events = interface_list_for_netbios.clone();
                let refresh_for_events = refresh_for_netbios.clone();
                let tcp_button_for_events = tcp_button_for_netbios.clone();
                let mdns_button_for_events = mdns_button_for_netbios.clone();
                let ssdp_button_for_events = ssdp_button_for_netbios.clone();
                let active_for_events = Rc::clone(&active_netbios_for_scan);
                let catalog_for_events = Rc::clone(&catalog_for_netbios);
                let devices_for_events = devices_for_netbios.clone();
                let navigation_for_events = navigation_for_netbios.clone();

                glib::timeout_add_local(Duration::from_millis(80), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            NetbiosEvent::DeviceFound { address, info } => {
                                catalog_for_events.borrow_mut().record_netbios(
                                    address,
                                    NetbiosEvidence {
                                        hostname: info.hostname.clone(),
                                        workgroup: info.workgroup.clone(),
                                    },
                                );
                                refresh_device_list(
                                    &devices_for_events,
                                    &catalog_for_events.borrow(),
                                    &navigation_for_events,
                                );
                            }
                            NetbiosEvent::Finished { total, completed, cancelled } => {
                                active_for_events.borrow_mut().take();
                                button_for_events.set_label("Discover NetBIOS names");
                                button_for_events.set_sensitive(
                                    selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface),
                                );
                                interface_list_for_events.set_sensitive(true);
                                refresh_for_events.set_sensitive(true);
                                let can_scan = selected_for_events.borrow().as_ref().is_some_and(is_scannable_interface);
                                tcp_button_for_events.set_sensitive(can_scan);
                                mdns_button_for_events.set_sensitive(can_scan);
                                ssdp_button_for_events.set_sensitive(can_scan);
                                let state = if cancelled { "cancelled" } else { "finished" };
                                status_for_events.set_text(&format!(
                                    "NetBIOS discovery {state}: queried {completed}/{total} device(s). Names are unverified."
                                ));
                                return glib::ControlFlow::Break;
                            }
                        }
                    }
                    glib::ControlFlow::Continue
                });
            }
            Err(error) => {
                status_for_netbios.set_text(&format!("Could not start NetBIOS discovery: {error}"));
            }
        }
    });

    let active_for_close = Rc::clone(&active_scan);
    let active_device_for_close = Rc::clone(&active_device_scan);
    let active_ssdp_for_close = Rc::clone(&active_ssdp);
    let active_netbios_for_close = Rc::clone(&active_netbios);
    let active_mdns_for_close = Rc::clone(&active_mdns);
    window.connect_close_request(move |_| {
        if let Some(handle) = active_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_device_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_mdns_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_ssdp_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_netbios_for_close.borrow().as_ref() {
            handle.cancel();
        }
        glib::Propagation::Proceed
    });

    refresh_interfaces(
        RefreshWidgets {
            list: &list,
            status: &status,
            system_info: &system_info,
            scan_button: &scan_button,
            mdns_button: &mdns_button,
            ssdp_button: &ssdp_button,
            netbios_button: &netbios_button,
        },
        &interfaces,
        &selected_interface,
    );
    window.present();

    if preferences.borrow().auto_scan_on_start {
        let default_interface = network::system::read_ipv4_routes()
            .ok()
            .and_then(|routes| routes.into_iter().find(|route| route.is_default))
            .map(|route| route.interface);
        let selected_index = {
            let available_interfaces = interfaces.borrow();
            available_interfaces
                .iter()
                .position(|interface| {
                    is_scannable_interface(interface)
                        && default_interface
                            .as_deref()
                            .is_some_and(|name| name == interface.name.as_str())
                })
                .or_else(|| {
                    available_interfaces
                        .iter()
                        .position(is_scannable_interface)
                })
        };
        if let Some(index) = selected_index {
            if let Some(row) = list.row_at_index(index as i32) {
                list.select_row(Some(&row));
                scan_button.emit_clicked();
            }
        }
    }
}

fn clear_list(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn refresh_device_list(
    list: &gtk::ListBox,
    catalog: &DeviceCatalog,
    navigation: &adw::NavigationView,
) {
    clear_list(list);

    let records = catalog
        .iter()
        .filter(|device| device.has_discovery_evidence())
        .collect::<Vec<_>>();

    if records.is_empty() {
        let subtitle = if catalog.is_empty() {
            "Run TCP, mDNS, or SSDP discovery to populate this list.".to_owned()
        } else {
            format!(
                "{} candidate address(es) have no confirmed discovery evidence yet.",
                catalog.len()
            )
        };
        let row = adw::ActionRow::builder()
            .title("No discovered devices yet")
            .subtitle(&subtitle)
            .activatable(false)
            .build();
        list.append(&row);
        return;
    }

    for device in records {
        let mut details = Vec::new();

        if let Some(mac) = device.mac_address.as_deref() {
            details.push(format!("MAC {mac}"));
        }
        if device.tcp_responded {
            details.push("TCP response".to_owned());
        }
        if !device.open_tcp_ports.is_empty() {
            let ports = device
                .open_tcp_ports
                .iter()
                .map(|port| match scanner::service_name(*port) {
                    Some(service) => format!("{port}/{service}"),
                    None => port.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            details.push(format!("Open ports: {ports}"));
        }
        if !device.mdns_services.is_empty() {
            let service_types = device
                .mdns_services
                .iter()
                .map(|service| service.service_type.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            details.push(format!(
                "mDNS: {} service(s) ({service_types})",
                device.mdns_services.len()
            ));
        }
        if !device.ssdp_advertisements.is_empty() {
            details.push(format!(
                "SSDP: {} advertisement(s)",
                device.ssdp_advertisements.len()
            ));
        }
        if let Some(netbios) = device.netbios_info.as_ref() {
            details.push(format!("NetBIOS: {}", netbios.hostname));
        }

        let row = adw::ActionRow::builder()
            .title(device.address.to_string())
            .subtitle(details.join("  ·  "))
            .activatable(true)
            .build();
        let navigation_for_row = navigation.clone();
        let active_scan_for_row = Rc::clone(&active_device_scan);
        let selected_device = device.clone();
        row.connect_activated(move |_| {
            let page = device_detail_page(
                &selected_device,
                &navigation_for_row,
                Rc::clone(&active_scan_for_row),
            );
            navigation_for_row.push(&page);
        });
        list.append(&row);
    }
}


fn device_detail_page(
    device: &DeviceRecord,
    navigation: &adw::NavigationView,
    active_device_scan: Rc<RefCell<Option<ScanHandle>>>,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    let back_button = gtk::Button::from_icon_name("go-previous-symbolic");
    back_button.set_tooltip_text(Some("Back to discovered devices"));
    let navigation_for_back = navigation.clone();
    let active_scan_for_back = Rc::clone(&active_device_scan);
    back_button.connect_clicked(move |_| {
        if let Some(handle) = active_scan_for_back.borrow().as_ref() {
            handle.cancel();
        }
        navigation_for_back.pop();
    });
    header.pack_start(&back_button);
    let title = adw::WindowTitle::new(
        &format!("Device {}", device.address),
        "Network details",
    );
    header.set_title_widget(Some(&title));
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(24);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let identity_heading = gtk::Label::new(Some("Device identity"));
    identity_heading.add_css_class("title-2");
    identity_heading.set_halign(gtk::Align::Start);
    content.append(&identity_heading);

    let identity = gtk::ListBox::new();
    identity.add_css_class("boxed-list");
    append_detail_row(&identity, "IPv4 address", &device.address.to_string());
    append_detail_row(
        &identity,
        "TCP reachability",
        if device.tcp_responded {
            "A TCP response was observed"
        } else {
            "No TCP response observed; this does not prove the device is offline"
        },
    );
    if let Some(mac) = device.mac_address.as_deref() {
        append_detail_row(&identity, "MAC address", mac);
    }
    if let Some(netbios) = device.netbios_info.as_ref() {
        append_detail_row(&identity, "NetBIOS hostname", &netbios.hostname);
        if let Some(workgroup) = netbios.workgroup.as_deref() {
            append_detail_row(&identity, "NetBIOS workgroup", workgroup);
        }
    }
    content.append(&identity);

    let preferences = AppPreferences::load();
    let custom_service_names = preferences
        .custom_ports
        .iter()
        .map(|item| (item.port, item.service_name.clone()))
        .collect::<HashMap<_, _>>();
    let mut deep_scan_ports = scanner::DEEP_SCAN_TCP_PORTS.to_vec();
    deep_scan_ports.extend(preferences.enabled_custom_ports());
    deep_scan_ports.sort_unstable();
    deep_scan_ports.dedup();

    let ports_heading = gtk::Label::new(Some("Open TCP ports"));
    ports_heading.add_css_class("title-2");
    ports_heading.set_halign(gtk::Align::Start);
    content.append(&ports_heading);

    let ports = gtk::ListBox::new();
    ports.add_css_class("boxed-list");
    if device.open_tcp_ports.is_empty() {
        append_detail_row(&ports, "No open ports recorded", "No configured TCP probe found an open port.");
    } else {
        for port in &device.open_tcp_ports {
            let service = custom_service_names
                .get(port)
                .map(String::as_str)
                .or_else(|| scanner::service_name(*port))
                .unwrap_or("Unknown service");
            append_detail_row(&ports, &format!("TCP {port}"), service);
        }
    }
    content.append(&ports);

    let deep_scan_heading = gtk::Label::new(Some("Deep scan results"));
    deep_scan_heading.add_css_class("title-2");
    deep_scan_heading.set_halign(gtk::Align::Start);
    content.append(&deep_scan_heading);

    let deep_scan_note = gtk::Label::new(Some(
        "Automatically checks the Android app's standard common TCP ports plus enabled custom ports. Timeouts are inconclusive; service names are port-based hints. A full 1–65535 scan is not available in this Linux build because scans are deliberately bounded.",
    ));
    deep_scan_note.add_css_class("dim-label");
    deep_scan_note.set_wrap(true);
    deep_scan_note.set_halign(gtk::Align::Start);
    content.append(&deep_scan_note);

    let deep_scan_progress = gtk::ProgressBar::new();
    deep_scan_progress.set_show_text(true);
    deep_scan_progress.set_text(Some("Preparing scan…"));
    content.append(&deep_scan_progress);

    let deep_scan_status = gtk::Label::new(Some("Starting standard port scan…"));
    deep_scan_status.set_halign(gtk::Align::Start);
    deep_scan_status.set_wrap(true);
    content.append(&deep_scan_status);

    let deep_scan_cancel = gtk::Button::with_label("Cancel deep scan");
    deep_scan_cancel.set_halign(gtk::Align::Start);
    deep_scan_cancel.add_css_class("destructive-action");
    content.append(&deep_scan_cancel);

    let deep_scan_results = gtk::ListBox::new();
    deep_scan_results.add_css_class("boxed-list");
    deep_scan_results.set_selection_mode(gtk::SelectionMode::None);
    content.append(&deep_scan_results);

    start_device_deep_scan(
        device.address,
        deep_scan_ports,
        custom_service_names,
        &deep_scan_progress,
        &deep_scan_status,
        &deep_scan_cancel,
        &deep_scan_results,
        active_device_scan,
    );

    if !device.mdns_services.is_empty() {
        let heading = gtk::Label::new(Some("Advertised mDNS services"));
        heading.add_css_class("title-2");
        heading.set_halign(gtk::Align::Start);
        content.append(&heading);

        let services = gtk::ListBox::new();
        services.add_css_class("boxed-list");
        for service in &device.mdns_services {
            append_detail_row(
                &services,
                &service.fullname,
                &format!("{}:{}  ·  {}", service.hostname, service.port, service.service_type),
            );
        }
        content.append(&services);
    }

    if !device.ssdp_advertisements.is_empty() {
        let heading = gtk::Label::new(Some("UPnP / SSDP advertisements"));
        heading.add_css_class("title-2");
        heading.set_halign(gtk::Align::Start);
        content.append(&heading);

        let advertisements = gtk::ListBox::new();
        advertisements.add_css_class("boxed-list");
        for advertisement in &device.ssdp_advertisements {
            append_detail_row(
                &advertisements,
                &advertisement.search_target,
                &format!(
                    "USN: {}  ·  Server: {}",
                    advertisement.unique_service_name,
                    advertisement.server.as_deref().unwrap_or("not supplied")
                ),
            );
            if let Some(location) = advertisement.location.as_deref() {
                append_detail_row(
                    &advertisements,
                    "Untrusted LOCATION header",
                    &format!("{location} (not fetched)"),
                );
            }
        }
        content.append(&advertisements);
    }

    let note = gtk::Label::new(Some(
        "Network-advertised names and service details are unverified claims. Missing information does not mean the device lacks that capability.",
    ));
    note.add_css_class("dim-label");
    note.set_wrap(true);
    note.set_halign(gtk::Align::Start);
    content.append(&note);

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&content)
        .build();
    let page_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    page_content.append(&header);
    page_content.append(&scrolled);

    adw::NavigationPage::builder()
        .title(format!("Device {}", device.address))
        .child(&page_content)
        .build()
}

fn start_device_deep_scan(
    address: std::net::Ipv4Addr,
    ports: Vec<u16>,
    service_names: HashMap<u16, String>,
    progress: &gtk::ProgressBar,
    status: &gtk::Label,
    cancel_button: &gtk::Button,
    results: &gtk::ListBox,
    active_scan: Rc<RefCell<Option<ScanHandle>>>,
) {
    if let Some(previous) = active_scan.borrow_mut().take() {
        previous.cancel();
    }
    clear_list(results);
    progress.set_fraction(0.0);
    progress.set_text(Some("0 ports checked"));
    status.set_text("Scanning standard and enabled custom TCP ports…");
    cancel_button.set_sensitive(true);

    let total_ports = ports.len();
    match scanner::start_device_deep_scan(
        address,
        ports,
        scanner::DEFAULT_TCP_TIMEOUT,
    ) {
        Ok((handle, events)) => {
            let scan_identity = handle.clone();
            *active_scan.borrow_mut() = Some(handle);

            let active_for_cancel = Rc::clone(&active_scan);
            let status_for_cancel = status.clone();
            cancel_button.connect_clicked(move |button| {
                if let Some(handle) = active_for_cancel.borrow().as_ref() {
                    handle.cancel();
                    button.set_sensitive(false);
                    status_for_cancel.set_text("Cancellation requested; waiting for in-flight connections to finish…");
                }
            });

            let progress_for_events = progress.clone();
            let status_for_events = status.clone();
            let cancel_for_events = cancel_button.clone();
            let results_for_events = results.clone();
            let active_for_events = Rc::clone(&active_scan);
            let scan_identity_for_events = scan_identity.clone();
            let started = Instant::now();
            let mut completed_ports = 0usize;
            let mut open_ports = 0usize;
            let service_names_for_events = service_names.clone();

            glib::timeout_add_local(Duration::from_millis(80), move || {
                while let Ok(event) = events.try_recv() {
                    match event {
                        DeepScanEvent::PortCompleted {
                            port,
                            open,
                            tcp_responded: _,
                            banner,
                        } => {
                            completed_ports = completed_ports.saturating_add(1);
                            if open {
                                open_ports = open_ports.saturating_add(1);
                                let service = service_names_for_events
                                    .get(&port)
                                    .map(String::as_str)
                                    .or_else(|| scanner::service_name(port))
                                    .unwrap_or("Unknown service");
                                append_detail_row(
                                    &results_for_events,
                                    &format!("TCP {port} · {service}"),
                                    banner.as_deref().unwrap_or("Open; no readable service banner received"),
                                );
                            }
                            let fraction = completed_ports as f64 / total_ports.max(1) as f64;
                            progress_for_events.set_fraction(fraction);
                            progress_for_events.set_text(Some(&format!(
                                "{completed_ports}/{total_ports} ports checked"
                            )));
                            status_for_events.set_text(&format!(
                                "Checked {completed_ports} of {total_ports} ports · {open_ports} open"
                            ));
                        }
                        DeepScanEvent::Finished {
                            total,
                            completed,
                            cancelled,
                        } => {
                            let is_current_scan = active_for_events
                                .borrow()
                                .as_ref()
                                .is_some_and(|active| active.refers_to_same_scan(&scan_identity_for_events));
                            if is_current_scan {
                                active_for_events.borrow_mut().take();
                            }
                            cancel_for_events.set_sensitive(false);
                            progress_for_events.set_fraction(1.0);
                            progress_for_events.set_text(Some(if cancelled {
                                "Cancelled"
                            } else {
                                "Complete"
                            }));
                            if open_ports == 0 && !cancelled {
                                append_detail_row(
                                    &results_for_events,
                                    "No open TCP ports found",
                                    "None of the scanned common TCP ports accepted a connection.",
                                );
                            }
                            let state = if cancelled { "cancelled" } else { "completed" };
                            status_for_events.set_text(&format!(
                                "Deep scan {state}: {completed}/{total} ports checked, {open_ports} open · {:.2}s",
                                started.elapsed().as_secs_f64()
                            ));
                            return glib::ControlFlow::Break;
                        }
                    }
                }
                glib::ControlFlow::Continue
            });
        }
        Err(error) => {
            cancel_button.set_sensitive(false);
            progress.set_text(Some("Could not start"));
            status.set_text(&format!("Deep scan could not start: {error}"));
        }
    }
}

fn append_detail_row(list: &gtk::ListBox, title: &str, subtitle: &str) {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .activatable(false)
        .build();
    list.append(&row);
}

fn is_scannable_interface(interface: &NetworkInterface) -> bool {
    interface.is_up
        && !interface.is_loopback
        && !interface.address.is_unspecified()
        && interface.prefix.is_some()
        && (interface.address.is_private() || interface.address.is_link_local())
}

struct RefreshWidgets<'a> {
    list: &'a gtk::ListBox,
    status: &'a gtk::Label,
    system_info: &'a gtk::Label,
    scan_button: &'a gtk::Button,
    mdns_button: &'a gtk::Button,
    ssdp_button: &'a gtk::Button,
    netbios_button: &'a gtk::Button,
}

fn refresh_interfaces(
    widgets: RefreshWidgets<'_>,
    interfaces_state: &Rc<RefCell<Vec<NetworkInterface>>>,
    selected_state: &Rc<RefCell<Option<NetworkInterface>>>,
) {
    let RefreshWidgets {
        list,
        status,
        system_info,
        scan_button,
        mdns_button,
        ssdp_button,
        netbios_button,
    } = widgets;

    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    *selected_state.borrow_mut() = None;
    scan_button.set_sensitive(false);
    mdns_button.set_sensitive(false);
    ssdp_button.set_sensitive(false);
    netbios_button.set_sensitive(false);

    match network::ipv4_interfaces() {
        Ok(interfaces) => {
            for interface in &interfaces {
                list.append(&interface_row(interface));
            }

            *interfaces_state.borrow_mut() = interfaces;

            let count = interfaces_state.borrow().len();
            let route_summary = match network::system::read_ipv4_routes() {
                Ok(routes) => routes
                    .iter()
                    .find(|route| route.is_default)
                    .map(|route| {
                        let route_label = if route.uses_gateway && !route.gateway.is_unspecified() {
                            format!("Default gateway: {}", route.gateway)
                        } else {
                            "Default IPv4 route".to_owned()
                        };
                        format!("{route_label} via {} (metric {})", route.interface, route.metric)
                    })
                    .unwrap_or_else(|| "Default gateway: no active IPv4 default route".to_owned()),
                Err(_) => "Default gateway: route information unavailable".to_owned(),
            };
            let neighbour_summary = match network::system::read_ipv4_neighbours() {
                Ok(neighbours) => {
                    format!("Complete IPv4 neighbour entries: {}", neighbours.len())
                }
                Err(_) => "IPv4 neighbour table: unavailable".to_owned(),
            };
            system_info.set_text(&format!("{route_summary}\n{neighbour_summary}"));
            status.set_text(&format!(
                "{count} IPv4 interface address(es) found. Select a private or link-local interface to enable scanning. No scan has started."
            ));
        }
        Err(error) => {
            interfaces_state.borrow_mut().clear();
            system_info.set_text("Route and neighbour information not refreshed.");
            status.set_text(&format!("Could not read interface information: {error}"));
        }
    }
}

fn interface_row(interface: &NetworkInterface) -> adw::ActionRow {
    let state = if interface.is_up { "UP" } else { "DOWN" };
    let kind = if interface.is_loopback {
        "loopback"
    } else {
        "network"
    };
    let prefix = interface.prefix.map_or_else(
        || "prefix unavailable".to_owned(),
        |value| format!("/{value}"),
    );
    let subtitle = format!("{}{prefix}  ·  {kind}  ·  {state}", interface.address);

    adw::ActionRow::builder()
        .title(&interface.name)
        .subtitle(&subtitle)
        .activatable(true)
        .build()
}

fn result_details(result: &HostScanResult) -> String {
    if result.open_ports.is_empty() {
        if result.tcp_responded {
            "TCP response received; none of the configured ports was open".to_owned()
        } else {
            "No TCP response observed; this does not prove the host is offline".to_owned()
        }
    } else {
        let ports = result
            .open_ports
            .iter()
            .map(|port| match scanner::service_name(*port) {
                Some(service) => format!("{port} ({service})"),
                None => port.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Open TCP ports: {ports}. Service names are port-based hints, not verified identities."
        )
    }
}

fn result_row(result: &HostScanResult, details: &str) -> adw::ActionRow {
    adw::ActionRow::builder()
        .title(result.address.to_string())
        .subtitle(details)
        .activatable(false)
        .build()
}


fn apply_theme(theme: ThemeMode) {
    let color_scheme = match theme {
        ThemeMode::System => adw::ColorScheme::Default,
        ThemeMode::Light => adw::ColorScheme::ForceLight,
        ThemeMode::Dark => adw::ColorScheme::ForceDark,
    };
    adw::StyleManager::default().set_color_scheme(color_scheme);
}

fn settings_page(
    navigation: &adw::NavigationView,
    window: &adw::ApplicationWindow,
    preferences: Rc<RefCell<AppPreferences>>,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    let back_button = gtk::Button::from_icon_name("go-previous-symbolic");
    back_button.set_tooltip_text(Some("Back"));
    let navigation_for_back = navigation.clone();
    back_button.connect_clicked(move |_| navigation_for_back.pop());
    header.pack_start(&back_button);
    let title = adw::WindowTitle::new("Settings", "Application preferences");
    header.set_title_widget(Some(&title));

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(24);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let appearance_heading = gtk::Label::new(Some("Appearance"));
    appearance_heading.add_css_class("title-2");
    appearance_heading.set_halign(gtk::Align::Start);
    content.append(&appearance_heading);

    let theme_row = adw::ActionRow::builder()
        .title("Theme")
        .subtitle("Follow the desktop theme or choose a fixed appearance")
        .build();
    let theme_dropdown = gtk::DropDown::from_strings(&["System", "Light", "Dark"]);
    theme_dropdown.set_selected(match preferences.borrow().theme {
        ThemeMode::System => 0,
        ThemeMode::Light => 1,
        ThemeMode::Dark => 2,
    });
    theme_row.add_suffix(&theme_dropdown);
    let preferences_for_theme = Rc::clone(&preferences);
    let theme_status = gtk::Label::new(None);
    theme_status.set_halign(gtk::Align::Start);
    theme_status.add_css_class("dim-label");
    theme_dropdown.connect_selected_notify(move |dropdown| {
        let theme = match dropdown.selected() {
            1 => ThemeMode::Light,
            2 => ThemeMode::Dark,
            _ => ThemeMode::System,
        };
        let mut updated = preferences_for_theme.borrow().clone();
        updated.theme = theme;
        match updated.save() {
            Ok(()) => {
                *preferences_for_theme.borrow_mut() = updated;
                apply_theme(theme);
            }
            Err(error) => theme_status.set_text(&format!("Could not save theme preference: {error}")),
        }
    });
    let appearance_list = gtk::ListBox::new();
    appearance_list.add_css_class("boxed-list");
    appearance_list.append(&theme_row);
    content.append(&appearance_list);

    let scanning_heading = gtk::Label::new(Some("Scanning"));
    scanning_heading.add_css_class("title-2");
    scanning_heading.set_halign(gtk::Align::Start);
    content.append(&scanning_heading);

    let auto_scan_row = adw::ActionRow::builder()
        .title("Scan automatically on launch")
        .subtitle("When enabled, the app selects the default-route interface and starts a bounded scan")
        .build();
    let auto_scan_switch = gtk::Switch::new();
    auto_scan_switch.set_valign(gtk::Align::Center);
    auto_scan_switch.set_active(preferences.borrow().auto_scan_on_start);
    auto_scan_row.add_suffix(&auto_scan_switch);
    let preferences_for_auto_scan = Rc::clone(&preferences);
    let auto_scan_status = gtk::Label::new(None);
    auto_scan_status.set_halign(gtk::Align::Start);
    auto_scan_status.add_css_class("dim-label");
    auto_scan_switch.connect_active_notify(move |switch| {
        let mut updated = preferences_for_auto_scan.borrow().clone();
        updated.auto_scan_on_start = switch.is_active();
        match updated.save() {
            Ok(()) => *preferences_for_auto_scan.borrow_mut() = updated,
            Err(error) => auto_scan_status.set_text(&format!("Could not save startup preference: {error}")),
        }
    });
    let scanning_list = gtk::ListBox::new();
    scanning_list.add_css_class("boxed-list");
    scanning_list.append(&auto_scan_row);
    content.append(&scanning_list);

    let custom_ports_heading = gtk::Label::new(Some("Custom TCP ports"));
    custom_ports_heading.add_css_class("title-2");
    custom_ports_heading.set_halign(gtk::Align::Start);
    content.append(&custom_ports_heading);

    let custom_ports_row = adw::ActionRow::builder()
        .title("Manage custom ports")
        .subtitle("Add, enable, disable, and remove ports used by device deep scans")
        .activatable(true)
        .build();
    let custom_ports_button = gtk::Button::from_icon_name("go-next-symbolic");
    custom_ports_button.set_tooltip_text(Some("Manage custom ports"));
    custom_ports_row.add_suffix(&custom_ports_button);
    let navigation_for_ports = navigation.clone();
    let preferences_for_ports = Rc::clone(&preferences);
    custom_ports_button.connect_clicked(move |_| {
        let page = custom_ports_page(
            &navigation_for_ports,
            Rc::clone(&preferences_for_ports),
        );
        navigation_for_ports.push(&page);
    });
    let custom_ports_list = gtk::ListBox::new();
    custom_ports_list.add_css_class("boxed-list");
    custom_ports_list.append(&custom_ports_row);
    content.append(&custom_ports_list);

    let about_heading = gtk::Label::new(Some("About"));
    about_heading.add_css_class("title-2");
    about_heading.set_halign(gtk::Align::Start);
    content.append(&about_heading);

    let about_button = gtk::Button::with_label("About Praxis Scanner");
    let window_for_about = window.clone();
    about_button.connect_clicked(move |_| {
        show_information_dialog(
            &window_for_about,
            "Praxis Scanner",
            "A native Linux network discovery application. Licensed under GPL-3.0-only.",
        );
    });
    content.append(&about_button);

    let privacy_button = gtk::Button::with_label("Privacy and network behavior");
    let window_for_privacy = window.clone();
    privacy_button.connect_clicked(move |_| {
        show_information_dialog(
            &window_for_privacy,
            "Privacy",
            "Praxis Scanner runs locally. Network probes begin only after you select an eligible interface and start a scan, unless automatic scanning is explicitly enabled. It does not upload scan results, use raw sockets, require root privileges, or automatically fetch SSDP device-description URLs. Network advertisements are unverified.",
        );
    });
    content.append(&privacy_button);

    let github_link = gtk::LinkButton::with_label(
        "https://github.com/Praxis1071/praxis-scanner",
        "Praxis Scanner on GitHub",
    );
    content.append(&github_link);

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&content)
        .build();
    let page_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    page_content.append(&header);
    page_content.append(&scrolled);

    adw::NavigationPage::builder()
        .title("Settings")
        .child(&page_content)
        .build()
}

fn custom_ports_page(
    navigation: &adw::NavigationView,
    preferences: Rc<RefCell<AppPreferences>>,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    let back_button = gtk::Button::from_icon_name("go-previous-symbolic");
    back_button.set_tooltip_text(Some("Back to settings"));
    let navigation_for_back = navigation.clone();
    back_button.connect_clicked(move |_| navigation_for_back.pop());
    header.pack_start(&back_button);
    let title = adw::WindowTitle::new("Custom TCP ports", "Device deep-scan configuration");
    header.set_title_widget(Some(&title));

    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.set_margin_top(18);
    content.set_margin_bottom(24);
    content.set_margin_start(18);
    content.set_margin_end(18);

    let note = gtk::Label::new(Some(
        "Enabled custom ports are added to the standard per-device deep scan. Ports are checked with ordinary TCP connections and remain subject to the application's scan limits.",
    ));
    note.set_wrap(true);
    note.set_halign(gtk::Align::Start);
    note.add_css_class("dim-label");
    content.append(&note);

    let form_heading = gtk::Label::new(Some("Add a port"));
    form_heading.add_css_class("title-2");
    form_heading.set_halign(gtk::Align::Start);
    content.append(&form_heading);

    let form = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let port_entry = gtk::Entry::new();
    port_entry.set_placeholder_text(Some("Port"));
    port_entry.set_max_length(5);
    port_entry.set_input_purpose(gtk::InputPurpose::Digits);
    port_entry.set_width_chars(7);
    let service_entry = gtk::Entry::new();
    service_entry.set_placeholder_text(Some("Service name"));
    service_entry.set_hexpand(true);
    let add_button = gtk::Button::with_label("Add");
    add_button.add_css_class("suggested-action");
    form.append(&port_entry);
    form.append(&service_entry);
    form.append(&add_button);
    content.append(&form);

    let status = gtk::Label::new(Some("Port numbers must be between 1 and 65535. Service names are local labels."));
    status.set_wrap(true);
    status.set_halign(gtk::Align::Start);
    status.add_css_class("dim-label");
    content.append(&status);

    let ports_heading = gtk::Label::new(Some("Saved custom ports"));
    ports_heading.add_css_class("title-2");
    ports_heading.set_halign(gtk::Align::Start);
    content.append(&ports_heading);

    let ports_list = gtk::ListBox::new();
    ports_list.set_selection_mode(gtk::SelectionMode::None);
    ports_list.add_css_class("boxed-list");
    content.append(&ports_list);
    refresh_custom_ports_list(&ports_list, Rc::clone(&preferences), &status);

    let preferences_for_add = Rc::clone(&preferences);
    let list_for_add = ports_list.clone();
    let status_for_add = status.clone();
    let port_entry_for_add = port_entry.clone();
    let service_entry_for_add = service_entry.clone();
    add_button.connect_clicked(move |_| {
        let port = match port_entry_for_add.text().parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => {
                status_for_add.set_text("Enter a valid TCP port between 1 and 65535.");
                return;
            }
        };
        let mut updated = preferences_for_add.borrow().clone();
        match updated.add_custom_port(port, &service_entry_for_add.text()) {
            Ok(()) => match updated.save() {
                Ok(()) => {
                    *preferences_for_add.borrow_mut() = updated;
                    port_entry_for_add.set_text("");
                    service_entry_for_add.set_text("");
                    status_for_add.set_text("Custom TCP port saved.");
                    refresh_custom_ports_list(
                        &list_for_add,
                        Rc::clone(&preferences_for_add),
                        &status_for_add,
                    );
                }
                Err(error) => status_for_add.set_text(&format!("Could not save custom port: {error}")),
            },
            Err(error) => status_for_add.set_text(error),
        }
    });

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&content)
        .build();
    let page_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    page_content.append(&header);
    page_content.append(&scrolled);

    adw::NavigationPage::builder()
        .title("Custom TCP ports")
        .child(&page_content)
        .build()
}

fn refresh_custom_ports_list(
    list: &gtk::ListBox,
    preferences: Rc<RefCell<AppPreferences>>,
    status: &gtk::Label,
) {
    clear_list(list);
    let ports = preferences.borrow().custom_ports.clone();
    if ports.is_empty() {
        let row = adw::ActionRow::builder()
            .title("No custom ports")
            .subtitle("Add a TCP port above to include it in device deep scans")
            .build();
        list.append(&row);
        return;
    }

    for item in ports {
        let row = adw::ActionRow::builder()
            .title(format!("TCP {}", item.port))
            .subtitle(&item.service_name)
            .build();

        let enabled_switch = gtk::Switch::new();
        enabled_switch.set_valign(gtk::Align::Center);
        enabled_switch.set_active(item.enabled);
        let preferences_for_switch = Rc::clone(&preferences);
        let status_for_switch = status.clone();
        enabled_switch.connect_active_notify(move |switch| {
            let mut updated = preferences_for_switch.borrow().clone();
            updated.set_custom_port_enabled(item.port, switch.is_active());
            match updated.save() {
                Ok(()) => *preferences_for_switch.borrow_mut() = updated,
                Err(error) => status_for_switch.set_text(&format!("Could not save port setting: {error}")),
            }
        });
        row.add_suffix(&enabled_switch);

        let delete_button = gtk::Button::from_icon_name("user-trash-symbolic");
        delete_button.set_tooltip_text(Some("Remove custom port"));
        let preferences_for_delete = Rc::clone(&preferences);
        let list_for_delete = list.clone();
        let status_for_delete = status.clone();
        delete_button.connect_clicked(move |_| {
            let mut updated = preferences_for_delete.borrow().clone();
            updated.remove_custom_port(item.port);
            match updated.save() {
                Ok(()) => {
                    *preferences_for_delete.borrow_mut() = updated;
                    status_for_delete.set_text("Custom port removed.");
                    refresh_custom_ports_list(
                        &list_for_delete,
                        Rc::clone(&preferences_for_delete),
                        &status_for_delete,
                    );
                }
                Err(error) => status_for_delete.set_text(&format!("Could not remove custom port: {error}")),
            }
        });
        row.add_suffix(&delete_button);
        list.append(&row);
    }
}

fn show_information_dialog(
    window: &adw::ApplicationWindow,
    title: &str,
    message: &str,
) {
    let dialog = gtk::MessageDialog::builder()
        .transient_for(window)
        .modal(true)
        .message_type(gtk::MessageType::Info)
        .buttons(gtk::ButtonsType::Close)
        .text(title)
        .secondary_text(message)
        .build();
    dialog.connect_response(|dialog, _| dialog.close());
    dialog.present();
}
