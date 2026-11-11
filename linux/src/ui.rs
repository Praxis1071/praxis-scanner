use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use crate::network::cidr::Ipv4Network;
use crate::network::device::{DeviceCatalog, DeviceRecord, MdnsEvidence, SsdpEvidence};
use crate::network::mdns::{self, MdnsEvent, MdnsHandle};
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

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Praxis Scanner")
        .default_width(900)
        .default_height(700)
        .content(&navigation_view)
        .build();

    let interfaces = Rc::new(RefCell::new(Vec::<NetworkInterface>::new()));
    let selected_interface = Rc::new(RefCell::new(None::<NetworkInterface>));
    let active_scan = Rc::new(RefCell::new(None::<ScanHandle>));
    let active_mdns = Rc::new(RefCell::new(None::<MdnsHandle>));
    let active_ssdp = Rc::new(RefCell::new(None::<SsdpHandle>));
    let device_catalog = Rc::new(RefCell::new(DeviceCatalog::default()));

    let interfaces_for_selection = Rc::clone(&interfaces);
    let selected_for_selection = Rc::clone(&selected_interface);
    let catalog_for_selection = Rc::clone(&device_catalog);
    let devices_for_selection = devices_list.clone();
    let scan_button_for_selection = scan_button.clone();
    let mdns_button_for_selection = mdns_button.clone();
    let ssdp_button_for_selection = ssdp_button.clone();
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
    refresh_button.connect_clicked(move |_| {
        refresh_interfaces(
            RefreshWidgets {
                list: &list_for_refresh,
                status: &status_for_refresh,
                system_info: &system_info_for_refresh,
                scan_button: &scan_button_for_refresh,
                mdns_button: &mdns_button_for_refresh,
                ssdp_button: &ssdp_button_for_refresh,
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
    let active_mdns_for_tcp = Rc::clone(&active_mdns);
    let active_ssdp_for_tcp = Rc::clone(&active_ssdp);
    scan_button.connect_clicked(move |_| {
        if let Some(handle) = active_for_scan.borrow().as_ref() {
            handle.cancel();
            status_for_scan.set_text(
                "Cancellation requested. Waiting for in-flight TCP connection attempts to finish…",
            );
            button_for_scan.set_label("Cancelling…");
            return;
        }

        if active_mdns_for_tcp.borrow().is_some() || active_ssdp_for_tcp.borrow().is_some() {
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
    let ssdp_button_for_mdns = ssdp_button.clone();
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
        if active_tcp_for_mdns.borrow().is_some() || active_ssdp_for_mdns.borrow().is_some() {
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
    let refresh_for_ssdp = refresh_button.clone();
    let interface_list_for_ssdp = list.clone();
    let port_entry_for_ssdp = port_entry.clone();
    let tcp_button_for_ssdp = scan_button.clone();
    let mdns_button_for_ssdp = mdns_button.clone();
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
        if active_tcp_for_ssdp.borrow().is_some() || active_mdns_for_ssdp.borrow().is_some() {
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

    let active_for_close = Rc::clone(&active_scan);
    let active_ssdp_for_close = Rc::clone(&active_ssdp);
    let active_mdns_for_close = Rc::clone(&active_mdns);
    window.connect_close_request(move |_| {
        if let Some(handle) = active_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_mdns_for_close.borrow().as_ref() {
            handle.cancel();
        }
        if let Some(handle) = active_ssdp_for_close.borrow().as_ref() {
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
        },
        &interfaces,
        &selected_interface,
    );
    window.present();
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

        let row = adw::ActionRow::builder()
            .title(device.address.to_string())
            .subtitle(details.join("  ·  "))
            .activatable(true)
            .build();
        let navigation_for_row = navigation.clone();
        let selected_device = device.clone();
        row.connect_activated(move |_| {
            let page = device_detail_page(&selected_device, &navigation_for_row);
            navigation_for_row.push(&page);
        });
        list.append(&row);
    }
}


fn device_detail_page(
    device: &DeviceRecord,
    navigation: &adw::NavigationView,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    let back_button = gtk::Button::from_icon_name("go-previous-symbolic");
    back_button.set_tooltip_text(Some("Back to discovered devices"));
    let navigation_for_back = navigation.clone();
    back_button.connect_clicked(move |_| {
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
    content.append(&identity);

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
            let service = scanner::service_name(*port)
                .unwrap_or("Unknown service");
            append_detail_row(&ports, &format!("TCP {port}"), service);
        }
    }
    content.append(&ports);

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
    } = widgets;

    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    *selected_state.borrow_mut() = None;
    scan_button.set_sensitive(false);
    mdns_button.set_sensitive(false);
    ssdp_button.set_sensitive(false);

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
