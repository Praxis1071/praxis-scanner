use std::cell::RefCell;
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

    let scan_button = gtk::Button::with_label("Scan selected network");
    scan_button.add_css_class("suggested-action");
    scan_button.set_halign(gtk::Align::Start);
    scan_button.set_margin_start(18);
    scan_button.set_margin_top(12);

    let scope_note = gtk::Label::new(Some(
        "A scan checks TCP ports 22, 53, 80, 139, 443, 445 and 3389 on the selected private or link-local subnet (maximum 1024 addresses).",
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
    list.connect_row_selected(move |_, row| {
        let selected = row.and_then(|row| {
            interfaces_for_selection
                .borrow()
                .get(row.index() as usize)
                .cloned()
        });
        *selected_for_selection.borrow_mut() = selected;
    });

    let list_for_refresh = list.clone();
    let status_for_refresh = status.clone();
    let interfaces_for_refresh = Rc::clone(&interfaces);
    let selected_for_refresh = Rc::clone(&selected_interface);
    refresh_button.connect_clicked(move |_| {
        refresh_interfaces(
            &list_for_refresh,
            &status_for_refresh,
            &interfaces_for_refresh,
            &selected_for_refresh,
        );
    });

    let status_for_scan = status.clone();
    let results_for_scan = results_list.clone();
    let button_for_scan = scan_button.clone();
    let selected_for_scan = Rc::clone(&selected_interface);
    let active_for_scan = Rc::clone(&active_scan);
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
            status_for_scan.set_text("The selected interface has no valid contiguous IPv4 netmask.");
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

        let target_count = hosts.len();
        match scanner::start_tcp_discovery(hosts, scanner::DEFAULT_TCP_TIMEOUT) {
            Ok((handle, events)) => {
                *active_for_scan.borrow_mut() = Some(handle);
                button_for_scan.set_label("Cancel scan");
                status_for_scan.set_text(&format!(
                    "Scanning {target_count} target(s) on {}/{} using unprivileged TCP connections…",
                    network.address(),
                    network.prefix()
                ));

                let status_for_events = status_for_scan.clone();
                let results_for_events = results_for_scan.clone();
                let button_for_events = button_for_scan.clone();
                let active_for_events = Rc::clone(&active_for_scan);
                let mut completed = 0usize;
                glib::timeout_add_local(Duration::from_millis(100), move || {
                    while let Ok(event) = events.try_recv() {
                        match event {
                            ScanEvent::HostCompleted(result) => {
                                completed += 1;
                                results_for_events.append(&result_row(&result));
                                status_for_events.set_text(&format!(
                                    "Checked {completed} of {target_count} addresses. A missing response does not prove a device is offline."
                                ));
                            }
                            ScanEvent::Finished {
                                total,
                                completed,
                                cancelled,
                            } => {
                                *active_for_events.borrow_mut() = None;
                                button_for_events.set_label("Scan selected network");
                                let state = if cancelled { "cancelled" } else { "finished" };
                                status_for_events.set_text(&format!(
                                    "Scan {state}: {completed} of {total} addresses checked. No-response results are inconclusive."
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

    refresh_interfaces(&list, &status, &interfaces, &selected_interface);
    window.present();
}

fn refresh_interfaces(
    list: &gtk::ListBox,
    status: &gtk::Label,
    interfaces_state: &Rc<RefCell<Vec<NetworkInterface>>>,
    selected_state: &Rc<RefCell<Option<NetworkInterface>>>,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    *selected_state.borrow_mut() = None;

    match network::ipv4_interfaces() {
        Ok(interfaces) => {
            for interface in &interfaces {
                list.append(&interface_row(interface));
            }

            let first_usable = interfaces
                .iter()
                .enumerate()
                .find(|(_, interface)| {
                    interface.is_up
                        && !interface.is_loopback
                        && !interface.address.is_unspecified()
                        && interface.prefix.is_some()
                })
                .map(|(index, interface)| (index, interface.clone()));
            *interfaces_state.borrow_mut() = interfaces;

            if let Some((index, interface)) = first_usable {
                *selected_state.borrow_mut() = Some(interface);
                if let Some(row) = list.row_at_index(index as i32) {
                    list.select_row(Some(&row));
                }
            }

            let count = interfaces_state.borrow().len();
            status.set_text(&format!(
                "{count} IPv4 interface address(es) found. Select an active interface to scan its local subnet. No scan has started."
            ));
        }
        Err(error) => {
            interfaces_state.borrow_mut().clear();
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

fn result_row(result: &HostScanResult) -> adw::ActionRow {
    let details = if result.open_ports.is_empty() {
        if result.tcp_responded {
            "TCP response received; no common scanned port was open".to_owned()
        } else {
            "No TCP response observed; this does not prove the host is offline".to_owned()
        }
    } else {
        format!(
            "Open TCP ports: {}",
            result
                .open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    adw::ActionRow::builder()
        .title(result.address.to_string())
        .subtitle(&details)
        .activatable(false)
        .build()
}
