mod preferences {
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::net::Ipv4Addr;
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

    pub const MAX_CUSTOM_PORTS: usize = 128;
    pub const MAX_DEVICE_CUSTOMIZATIONS: usize = 1024;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CustomPort {
        pub port: u16,
        pub service_name: String,
        pub enabled: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct DeviceCustomization {
        pub address: Ipv4Addr,
        pub custom_name: Option<String>,
        pub icon_key: Option<String>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AppPreferences {
        pub auto_scan_on_start: bool,
        pub theme: ThemeMode,
        pub custom_ports: Vec<CustomPort>,
        pub device_customizations: Vec<DeviceCustomization>,
    }

    impl Default for AppPreferences {
        fn default() -> Self {
            Self {
                // Network activity remains opt-in until the user enables this preference.
                auto_scan_on_start: false,
                theme: ThemeMode::System,
                custom_ports: Vec::new(),
                device_customizations: Vec::new(),
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
            if self.custom_ports.len() >= MAX_CUSTOM_PORTS {
                return Err("The custom port list is full (128 entries maximum).");
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

        pub fn customization_for(&self, address: Ipv4Addr) -> Option<&DeviceCustomization> {
            self.device_customizations
                .iter()
                .find(|item| item.address == address)
        }

        pub fn set_device_customization(
            &mut self,
            address: Ipv4Addr,
            custom_name: Option<&str>,
            icon_key: Option<&str>,
        ) -> Result<(), &'static str> {
            let custom_name = custom_name.map(str::trim).filter(|name| !name.is_empty());
            if custom_name.is_some_and(|name| !valid_device_name(name)) {
                return Err("Device names must be 1–48 characters and contain no control characters or |.");
            }
            let icon_key = icon_key.filter(|key| *key != "auto");
            if icon_key.is_some_and(|key| !valid_icon_key(key)) {
                return Err("Choose one of the supported device icons.");
            }

            if custom_name.is_none() && icon_key.is_none() {
                self.device_customizations
                    .retain(|item| item.address != address);
                return Ok(());
            }

            if let Some(item) = self
                .device_customizations
                .iter_mut()
                .find(|item| item.address == address)
            {
                item.custom_name = custom_name.map(str::to_owned);
                item.icon_key = icon_key.map(str::to_owned);
                return Ok(());
            }

            if self.device_customizations.len() >= MAX_DEVICE_CUSTOMIZATIONS {
                return Err("The device customization list is full.");
            }

            self.device_customizations.push(DeviceCustomization {
                address,
                custom_name: custom_name.map(str::to_owned),
                icon_key: icon_key.map(str::to_owned),
            });
            self.device_customizations.sort_by_key(|item| item.address);
            Ok(())
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
                        if preferences.custom_ports.iter().any(|item| item.port == port)
                            || preferences.custom_ports.len() >= MAX_CUSTOM_PORTS
                        {
                            continue;
                        }
                        preferences.custom_ports.push(CustomPort {
                            port,
                            service_name: name.to_owned(),
                            enabled,
                        });
                    }
                    "device" => {
                        let mut fields = value.splitn(3, '|');
                        let Some(address) = fields.next().and_then(|item| item.parse::<Ipv4Addr>().ok()) else {
                            continue;
                        };
                        let Some(name) = fields.next() else {
                            continue;
                        };
                        let Some(icon) = fields.next() else {
                            continue;
                        };
                        let custom_name = if name.is_empty() {
                            None
                        } else if valid_device_name(name) {
                            Some(name.to_owned())
                        } else {
                            continue;
                        };
                        let icon_key = if icon.is_empty() {
                            None
                        } else if valid_icon_key(icon) {
                            Some(icon.to_owned())
                        } else {
                            continue;
                        };
                        if custom_name.is_none() && icon_key.is_none() {
                            continue;
                        }
                        if preferences
                            .device_customizations
                            .iter()
                            .any(|item| item.address == address)
                            || preferences.device_customizations.len() >= MAX_DEVICE_CUSTOMIZATIONS
                        {
                            continue;
                        }
                        preferences.device_customizations.push(DeviceCustomization {
                            address,
                            custom_name,
                            icon_key,
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
            preferences.device_customizations.sort_by_key(|item| item.address);
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
            for item in &self.device_customizations {
                if item.custom_name.as_deref().is_some_and(|name| !valid_device_name(name))
                    || item.icon_key.as_deref().is_some_and(|icon| !valid_icon_key(icon))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "device customization contains an invalid value",
                    ));
                }
                contents.push_str(&format!(
                    "device={}|{}|{}\n",
                    item.address,
                    item.custom_name.as_deref().unwrap_or(""),
                    item.icon_key.as_deref().unwrap_or("")
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
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

    fn valid_device_name(value: &str) -> bool {
        !value.is_empty()
            && value.chars().count() <= 48
            && value.chars().all(|character| !character.is_control() && character != '|')
    }

    fn valid_icon_key(value: &str) -> bool {
        matches!(
            value,
            "computer" | "phone" | "tablet" | "printer" | "router" | "server" | "network" | "other"
        )
    }

    fn preferences_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
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
                device_customizations: Vec::new(),
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
        fn custom_port_count_is_bounded() {
            let mut preferences = AppPreferences::default();
            for port in 1..=super::MAX_CUSTOM_PORTS {
                preferences
                    .add_custom_port(port as u16, "Custom")
                    .expect("port should fit");
            }
            assert!(preferences
                .add_custom_port(20_000, "Overflow")
                .is_err());
        }

        #[test]
        fn device_customizations_round_trip_and_can_be_reset() {
            let path = std::env::temp_dir().join(format!(
                "praxis-scanner-device-preferences-{}.ini",
                std::process::id()
            ));
            let address = "192.0.2.42".parse().expect("valid test IPv4");
            let mut preferences = AppPreferences::default();
            preferences
                .set_device_customization(address, Some("Office NAS"), Some("server"))
                .expect("valid device customization");
            preferences.save_to(&path).expect("save customizations");

            let mut loaded = AppPreferences::load_from(&path).expect("load customizations");
            let customization = loaded.customization_for(address).expect("saved customization");
            assert_eq!(customization.custom_name.as_deref(), Some("Office NAS"));
            assert_eq!(customization.icon_key.as_deref(), Some("server"));

            loaded
                .set_device_customization(address, None, None)
                .expect("reset customization");
            assert!(loaded.customization_for(address).is_none());
            let _ = fs::remove_file(path);
        }

        #[test]
        fn device_customization_rejects_invalid_names_and_icons() {
            let mut preferences = AppPreferences::default();
            let address = "192.0.2.43".parse().expect("valid test IPv4");
            assert!(preferences
                .set_device_customization(address, Some("bad|name"), Some("server"))
                .is_err());
            assert!(preferences
                .set_device_customization(address, Some("Valid"), Some("unknown"))
                .is_err());
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
