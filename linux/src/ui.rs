use adw::prelude::*;

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
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");

    let status = gtk::Label::new(Some("Reading local interface information…"));
    status.set_halign(gtk::Align::Start);
    status.set_margin_start(18);
    status.set_margin_end(18);
    status.set_margin_top(12);
    status.set_margin_bottom(12);
    status.add_css_class("dim-label");

    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&list)
        .build();

    let page = gtk::Box::new(gtk::Orientation::Vertical, 0);
    page.append(&header);
    page.append(&heading);
    page.append(&scrolled);
    page.append(&status);

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Praxis Scanner")
        .default_width(900)
        .default_height(640)
        .content(&page)
        .build();

    let list_for_refresh = list.clone();
    let status_for_refresh = status.clone();
    refresh_button.connect_clicked(move |_| {
        refresh_interfaces(&list_for_refresh, &status_for_refresh);
    });

    refresh_interfaces(&list, &status);
    window.present();
}

fn refresh_interfaces(list: &gtk::ListBox, status: &gtk::Label) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    match network::ipv4_interfaces() {
        Ok(interfaces) => {
            for interface in &interfaces {
                list.append(&interface_row(interface));
            }

            let count = interfaces.len();
            status.set_text(&format!(
                "{count} IPv4 interface address(es) found. No scan traffic has been sent."
            ));
        }
        Err(error) => {
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
    let prefix = interface
        .prefix
        .map_or_else(|| "prefix unavailable".to_owned(), |value| format!("/{value}"));
    let subtitle = format!(
        "{}{prefix}  ·  {kind}  ·  {state}",
        interface.address
    );

    adw::ActionRow::builder()
        .title(&interface.name)
        .subtitle(&subtitle)
        .activatable(false)
        .build()
}
