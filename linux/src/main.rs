mod preferences {
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub enum ThemeMode {
        #[default]
        System,
        Light,
        Dark,
    }

    impl ThemeMode {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::System => "system",
                Self::Light => "light",
                Self::Dark => "dark",
            }
        }

        fn parse(value: &str) -> Option<Self> {
            match value {
                "system" => Some(Self::System),
                "light" => Some(Self::Light),
                "dark" => Some(Self::Dark),
                _ => None,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CustomPort {
        pub port: u16,
        pub service_name: String,
        pub enabled: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AppPreferences {
        pub auto_scan_on_start: bool,
        pub theme: ThemeMode,
        pub custom_ports: Vec<CustomPort>,
    }

    impl Default for AppPreferences {
        fn default() -> Self {
            Self {
                // Network activity remains opt-in until the user enables this preference.
                auto_scan_on_start: false,
                theme: ThemeMode::System,
                custom_ports: Vec::new(),
            }
        }
    }

    impl AppPreferences {
        pub fn load() -> Self {
            Self::load_from(&preferences_path()).unwrap_or_default()
        }

        pub fn save(&self) -> io::Result<()> {
            self.save_to(&preferences_path())
        }

        pub fn enabled_custom_ports(&self) -> Vec<u16> {
            self.custom_ports
                .iter()
                .filter(|port| port.enabled)
                .map(|port| port.port)
                .collect()
        }

        pub fn add_custom_port(
            &mut self,
            port: u16,
            service_name: &str,
        ) -> Result<(), &'static str> {
            if port == 0 {
                return Err("Port must be between 1 and 65535.");
            }
            if self.custom_ports.iter().any(|item| item.port == port) {
                return Err("That TCP port is already in the list.");
            }
            let service_name = service_name.trim();
            if !valid_service_name(service_name) {
                return Err("Use a service name of 1–32 letters, numbers, spaces, or - _ . / characters.");
            }
            self.custom_ports.push(CustomPort {
                port,
                service_name: service_name.to_owned(),
                enabled: true,
            });
            self.custom_ports.sort_by_key(|item| item.port);
            Ok(())
        }

        pub fn remove_custom_port(&mut self, port: u16) {
            self.custom_ports.retain(|item| item.port != port);
        }

        pub fn set_custom_port_enabled(&mut self, port: u16, enabled: bool) {
            if let Some(item) = self.custom_ports.iter_mut().find(|item| item.port == port) {
                item.enabled = enabled;
            }
        }

        fn load_from(path: &Path) -> io::Result<Self> {
            let contents = match fs::read_to_string(path) {
                Ok(contents) => contents,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Self::default());
                }
                Err(error) => return Err(error),
            };

            let mut preferences = Self::default();
            let mut supported_version = false;
            for line in contents.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                match key.trim() {
                    "version" => {
                        if value.trim() != "1" {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unsupported preferences file version",
                            ));
                        }
                        supported_version = true;
                    }
                    "auto_scan" => {
                        if let Ok(enabled) = value.trim().parse::<bool>() {
                            preferences.auto_scan_on_start = enabled;
                        }
                    }
                    "theme" => {
                        if let Some(theme) = ThemeMode::parse(value.trim()) {
                            preferences.theme = theme;
                        }
                    }
                    "port" => {
                        let mut fields = value.splitn(3, '|');
                        let Some(port) = fields.next().and_then(|item| item.parse::<u16>().ok()) else {
                            continue;
                        };
                        let Some(enabled) = fields.next().and_then(|item| item.parse::<bool>().ok()) else {
                            continue;
                        };
                        let Some(name) = fields.next() else {
                            continue;
                        };
                        if port == 0 || !valid_service_name(name) {
                            continue;
                        }
                        if preferences.custom_ports.iter().any(|item| item.port == port) {
                            continue;
                        }
                        preferences.custom_ports.push(CustomPort {
                            port,
                            service_name: name.to_owned(),
                            enabled,
                        });
                    }
                    _ => {}
                }
            }

            if !supported_version {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "preferences file has no supported version header",
                ));
            }
            preferences.custom_ports.sort_by_key(|item| item.port);
            Ok(preferences)
        }

        fn save_to(&self, path: &Path) -> io::Result<()> {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "preferences path has no parent")
            })?;
            fs::create_dir_all(parent)?;

            let mut contents = format!(
                "version=1\nauto_scan={}\ntheme={}\n",
                self.auto_scan_on_start,
                self.theme.as_str()
            );
            for item in &self.custom_ports {
                if item.port == 0 || !valid_service_name(&item.service_name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "custom port contains an invalid value",
                    ));
                }
                contents.push_str(&format!(
                    "port={}|{}|{}\n",
                    item.port, item.enabled, item.service_name
                ));
            }

            let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            Ok(())
        }
    }

    fn valid_service_name(value: &str) -> bool {
        !value.is_empty()
            && value.chars().count() <= 32
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric() || " -_./".contains(character)
            })
    }

    fn preferences_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from(".config"));
        base.join("praxis-scanner").join("settings.ini")
    }

    #[cfg(test)]
    mod tests {
        use super::{AppPreferences, ThemeMode};
        use std::fs;

        #[test]
        fn preferences_and_custom_ports_round_trip_atomically() {
            let path = std::env::temp_dir().join(format!(
                "praxis-scanner-preferences-{}.ini",
                std::process::id()
            ));
            let mut expected = AppPreferences {
                auto_scan_on_start: true,
                theme: ThemeMode::Dark,
                custom_ports: Vec::new(),
            };
            expected.add_custom_port(11434, "Ollama").expect("valid custom port");
            expected.set_custom_port_enabled(11434, false);
            expected.add_custom_port(8080, "HTTP Alt").expect("valid custom port");

            expected.save_to(&path).expect("save preferences");
            let actual = AppPreferences::load_from(&path).expect("load preferences");
            assert_eq!(actual, expected);
            assert_eq!(actual.enabled_custom_ports(), vec![8080]);
            let _ = fs::remove_file(path);
        }

        #[test]
        fn custom_port_validation_rejects_duplicates_and_unsafe_names() {
            let mut preferences = AppPreferences::default();
            preferences.add_custom_port(22, "SSH").expect("first port");
            assert!(preferences.add_custom_port(22, "Duplicate").is_err());
            assert!(preferences.add_custom_port(23, "bad|name").is_err());
            assert!(preferences.add_custom_port(0, "Zero").is_err());
        }

        #[test]
        fn unsupported_preferences_version_is_rejected() {
            let path = std::env::temp_dir().join(format!(
                "praxis-scanner-invalid-preferences-{}.ini",
                std::process::id()
            ));
            fs::write(&path, "version=99\nauto_scan=true\n").expect("write invalid file");
            assert!(AppPreferences::load_from(&path).is_err());
            let _ = fs::remove_file(path);
        }
    }
}

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
