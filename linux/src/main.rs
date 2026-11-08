mod network;
mod ui;

use adw::prelude::*;
use gtk::glib;

fn main() -> glib::ExitCode {
    let application = adw::Application::builder()
        .application_id("io.github.praxis1071.PraxisScanner")
        .build();

    application.connect_activate(ui::build_ui);
    application.run()
}
