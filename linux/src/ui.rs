use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use crate::network::cidr::Ipv4Network;
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

    let ports_heading = gtk::Label::new(Some("TCP ports (comma-separated)"));
    ports_heading.set_halign(gtk::Align::Start);
    ports_heading.set_margin_start(18);
    ports_heading.set_margin_top(12);

    let port_entry = gtk::Entry::new();
    port_entry.set_text("22,53,80,139,443,445,3389");
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
    content.append(&ports_heading);
    content.append(&port_entry);
    content.append(&scan_button);
    content.append(&scope_note);
    content.append(&results_heading);
    content.append(&results_list);
    content.append(&status);

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&content)
        .build();

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Praxis Scanner")
        .default_width(900)
        .default_height(700)
        .content(&scrolled)
        .build();

    let interfaces = Rc::new(RefCell::new(Vec::<NetworkInterface>::new()));
    let selected_interface = Rc::new(RefCell::new(None::<NetworkInterface>));
    let active_scan = Rc::new(RefCell::new(None::<ScanHandle>));

    let interfaces_for_selection = Rc::clone(&interfaces);
    let selected_for_selection = Rc::clone(&selected_interface);
    let scan_button_for_selection = scan_button.clone();
    let status_for_selection = status.clone();
    list.connect_row_selected(move |_, row| {
        let selected = row.and_then(|row| {
            interfaces_for_selection
                .borrow()
                .get(row.index() as usize)
                .cloned()
        });
        let can_scan = selected.as_ref().is_some_and(|interface| {
            interface.is_up
                && !interface.is_loopback
                && interface.prefix.is_some()
                && (interface.address.is_private() || interface.address.is_link_local())
        });
        scan_button_for_selection.set_sensitive(can_scan);
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
    refresh_button.connect_clicked(move |_| {
        refresh_interfaces(
            &list_for_refresh,
            &status_for_refresh,
            &system_info_for_refresh,
            &interfaces_for_refresh,
            &selected_for_refresh,
            &scan_button_for_refresh,
        );
    });

    let status_for_scan = status.clone();
    let results_for_scan = results_list.clone();
    let button_for_scan = scan_button.clone();
    let selected_for_scan = Rc::clone(&selected_interface);
    let active_for_scan = Rc::clone(&active_scan);
    let refresh_button_for_scan = refresh_button.clone();
    let port_entry_for_scan = port_entry.clone();
    let interface_list_for_scan = list.clone();
    let port_entry_for_sensitivity = port_entry.clone();
    scan_button.connect_clicked(move |_| {
        if let Some(handle) = active_for_scan.borrow().as_ref() {
            handle.cancel();
            status_for_scan.set_text(
                "Cancellation requested. Waiting for in-flight TCP connection attempts to finish…",
            );
            button_for_scan.set_label("Cancelling…");
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
                let active_for_events = Rc::clone(&active_for_scan);
                let mut completed = 0usize;
                let mut responsive = 0usize;
                let mut inconclusive = 0usize;
                let mut result_rows = Vec::<(std::net::Ipv4Addr, adw::ActionRow, String)>::new();
                glib::timeout_add_local(Duration::from_millis(100), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            ScanEvent::HostCompleted(result) => {
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
                                let mac_summary = match network::system::read_ipv4_neighbours() {
                                    Ok(neighbours) => {
                                        let mac_by_address: HashMap<_, _> = neighbours
                                            .into_iter()
                                            .map(|neighbour| (neighbour.address, neighbour.hardware_address))
                                            .collect();
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

    let active_for_close = Rc::clone(&active_scan);
    window.connect_close_request(move |_| {
        if let Some(handle) = active_for_close.borrow().as_ref() {
            handle.cancel();
        }
        glib::Propagation::Proceed
    });

    refresh_interfaces(
        &list,
        &status,
        &system_info,
        &interfaces,
        &selected_interface,
        &scan_button,
    );
    window.present();
}

fn refresh_interfaces(
    list: &gtk::ListBox,
    status: &gtk::Label,
    system_info: &gtk::Label,
    interfaces_state: &Rc<RefCell<Vec<NetworkInterface>>>,
    selected_state: &Rc<RefCell<Option<NetworkInterface>>>,
    scan_button: &gtk::Button,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    *selected_state.borrow_mut() = None;
    scan_button.set_sensitive(false);

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
                        format!(
                            "Default gateway: {} via {} (metric {})",
                            route.gateway, route.interface, route.metric
                        )
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
