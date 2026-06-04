//! Public schema model for Intent files.

use std::fmt;

use serde::Deserialize;

/// Current schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Top-level intent document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentDocument {
    /// Schema version declared by the document.
    pub version: u32,
    /// Application identity and launch context.
    pub application: Application,
    /// Files and directories the application expects to use.
    #[serde(default)]
    pub storage: Storage,
    /// Network access requested by the application.
    #[serde(default)]
    pub network: Network,
    /// Local IPC access requested by the application.
    #[serde(default)]
    pub ipc: Ipc,
    /// Linux capabilities requested by friendly name.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Free-form maintainer notes.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl IntentDocument {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut errors = Vec::new();

        if self.version != CURRENT_SCHEMA_VERSION {
            errors.push(format!(
                "version must be {CURRENT_SCHEMA_VERSION}; found {}",
                self.version
            ));
        }

        self.application.validate(&mut errors);
        self.storage.validate(&mut errors);
        self.network.validate(&mut errors);
        self.ipc.validate(&mut errors);

        for (index, capability) in self.capabilities.iter().enumerate() {
            validate_non_empty(&mut errors, format!("capabilities[{index}]"), capability);
            validate_kebab_name(
                &mut errors,
                format!("capabilities[{index}]"),
                capability,
                "use developer-friendly kebab-case such as net-bind-service",
            );
        }

        for (index, note) in self.notes.iter().enumerate() {
            validate_non_empty(&mut errors, format!("notes[{index}]"), note);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError { errors })
        }
    }
}

/// Application identity and launch context.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub executable: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

impl Application {
    fn validate(&self, errors: &mut Vec<String>) {
        validate_non_empty(errors, "application.name", &self.name);
        validate_non_empty(errors, "application.executable", &self.executable);

        if !self.executable.starts_with('/') {
            errors.push(format!(
                "application.executable must be an absolute path; found '{}'",
                self.executable
            ));
        }

        if let Some(description) = &self.description {
            validate_non_empty(errors, "application.description", description);
        }

        if let Some(user) = &self.user {
            validate_non_empty(errors, "application.user", user);
        }

        if let Some(group) = &self.group {
            validate_non_empty(errors, "application.group", group);
        }
    }
}

/// Files and directories the application expects to use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    #[serde(default)]
    pub config: Vec<StoragePath>,
    #[serde(default)]
    pub cache: Vec<StoragePath>,
    #[serde(default)]
    pub state: Vec<StoragePath>,
    #[serde(default)]
    pub runtime: Vec<StoragePath>,
}

impl Storage {
    fn validate(&self, errors: &mut Vec<String>) {
        validate_storage_paths(errors, "storage.config", &self.config);
        validate_storage_paths(errors, "storage.cache", &self.cache);
        validate_storage_paths(errors, "storage.state", &self.state);
        validate_storage_paths(errors, "storage.runtime", &self.runtime);
    }
}

/// A file or directory with a high-level access mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePath {
    pub path: String,
    pub access: StorageAccess,
}

/// Storage access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageAccess {
    Read,
    ReadWrite,
}

/// Network access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub outbound: Vec<OutboundNetwork>,
}

impl Network {
    fn validate(&self, errors: &mut Vec<String>) {
        for (index, outbound) in self.outbound.iter().enumerate() {
            let prefix = format!("network.outbound[{index}]");
            validate_non_empty(errors, format!("{prefix}.to"), &outbound.to);

            if let Some(port) = outbound.port {
                if port == 0 {
                    errors.push(format!("{prefix}.port must be between 1 and 65535"));
                }
            }

            if matches!(
                outbound.protocol,
                NetworkProtocol::Tcp | NetworkProtocol::Udp
            ) && outbound.port.is_none()
            {
                errors.push(format!(
                    "{prefix}.port is required when protocol is tcp or udp"
                ));
            }
        }
    }
}

/// An outbound network destination.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundNetwork {
    pub to: String,
    pub protocol: NetworkProtocol,
    #[serde(default)]
    pub port: Option<u16>,
}

/// Developer-facing network protocol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProtocol {
    Http,
    Https,
    Tcp,
    Udp,
}

/// Local IPC access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipc {
    #[serde(default)]
    pub unix_sockets: Vec<UnixSocket>,
    #[serde(default)]
    pub dbus: Dbus,
}

impl Ipc {
    fn validate(&self, errors: &mut Vec<String>) {
        for (index, socket) in self.unix_sockets.iter().enumerate() {
            let prefix = format!("ipc.unix_sockets[{index}]");
            validate_non_empty(errors, format!("{prefix}.path"), &socket.path);

            if !socket.path.starts_with('/') {
                errors.push(format!(
                    "{prefix}.path must be an absolute path; found '{}'",
                    socket.path
                ));
            }
        }

        self.dbus.validate(errors);
    }
}

/// A Unix domain socket used by the application.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixSocket {
    pub path: String,
    pub mode: UnixSocketMode,
}

/// Whether the application creates or connects to a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnixSocketMode {
    Server,
    Client,
}

/// D-Bus access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dbus {
    #[serde(default)]
    pub system: SystemBus,
}

impl Dbus {
    fn validate(&self, errors: &mut Vec<String>) {
        self.system.validate(errors);
    }
}

/// System bus names owned or contacted by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemBus {
    #[serde(default)]
    pub owns: Vec<String>,
    #[serde(default)]
    pub talks_to: Vec<String>,
}

impl SystemBus {
    fn validate(&self, errors: &mut Vec<String>) {
        for (index, name) in self.owns.iter().enumerate() {
            validate_dbus_name(errors, format!("ipc.dbus.system.owns[{index}]"), name);
        }

        for (index, name) in self.talks_to.iter().enumerate() {
            validate_dbus_name(errors, format!("ipc.dbus.system.talks_to[{index}]"), name);
        }
    }
}

/// Validation failures found after a document was syntactically parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub errors: Vec<String>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.errors.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "- {error}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ValidationError {}

fn validate_storage_paths(errors: &mut Vec<String>, field: &str, paths: &[StoragePath]) {
    for (index, entry) in paths.iter().enumerate() {
        let prefix = format!("{field}[{index}]");
        validate_non_empty(errors, format!("{prefix}.path"), &entry.path);

        if !entry.path.starts_with('/') {
            errors.push(format!(
                "{prefix}.path must be an absolute path; found '{}'",
                entry.path
            ));
        }
    }
}

fn validate_dbus_name(errors: &mut Vec<String>, field: String, name: &str) {
    validate_non_empty(errors, &field, name);

    if !name.contains('.') {
        errors.push(format!(
            "{field} should be a well-known D-Bus name such as org.example.Service"
        ));
    }
}

fn validate_non_empty(errors: &mut Vec<String>, field: impl AsRef<str>, value: &str) {
    if value.trim().is_empty() {
        errors.push(format!("{} must not be empty", field.as_ref()));
    }
}

fn validate_kebab_name(errors: &mut Vec<String>, field: String, value: &str, help: &str) {
    if value.is_empty() {
        return;
    }

    let valid = value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--");

    if !valid {
        errors.push(format!("{field} must be kebab-case; {help}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> IntentDocument {
        serde_yaml::from_str(value).expect("intent yaml should parse")
    }

    #[test]
    fn accepts_minimal_document() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
"#,
        );

        assert!(document.validate().is_ok());
        assert_eq!(document.storage.config, Vec::new());
    }

    #[test]
    fn accepts_supported_fields() {
        let document = parse(
            r#"
version: 1
application:
  name: himmelblaud
  description: Entra ID login daemon
  executable: /usr/libexec/himmelblaud
  user: root
  group: root
storage:
  config:
    - path: /etc/himmelblaud
      access: read
  cache:
    - path: /var/cache/himmelblaud
      access: read-write
  state:
    - path: /var/lib/himmelblaud
      access: read-write
  runtime:
    - path: /run/himmelblaud
      access: read-write
network:
  outbound:
    - to: login.microsoftonline.com
      protocol: https
ipc:
  unix_sockets:
    - path: /run/himmelblaud/socket
      mode: server
  dbus:
    system:
      owns:
        - org.freedesktop.resolve1
      talks_to:
        - org.freedesktop.DBus
capabilities:
  - net-bind-service
notes:
  - Example only.
"#,
        );

        assert!(document.validate().is_ok());
        assert_eq!(
            document.network.outbound[0].protocol,
            NetworkProtocol::Https
        );
        assert_eq!(document.ipc.unix_sockets[0].mode, UnixSocketMode::Server);
    }

    #[test]
    fn rejects_invalid_values_with_helpful_errors() {
        let document = parse(
            r#"
version: 99
application:
  name: " "
  executable: usr/bin/demo
storage:
  config:
    - path: relative/path
      access: read
network:
  outbound:
    - to: ""
      protocol: tcp
      port: 0
ipc:
  unix_sockets:
    - path: socket
      mode: client
  dbus:
    system:
      owns:
        - invalid
capabilities:
  - CAP_SYS_ADMIN
notes:
  - ""
"#,
        );

        let error = document.validate().expect_err("document should be invalid");
        let message = error.to_string();

        assert!(message.contains("version must be 1"));
        assert!(message.contains("application.name must not be empty"));
        assert!(message.contains("application.executable must be an absolute path"));
        assert!(message.contains("storage.config[0].path must be an absolute path"));
        assert!(message.contains("network.outbound[0].to must not be empty"));
        assert!(message.contains("network.outbound[0].port must be between 1 and 65535"));
        assert!(message.contains("ipc.unix_sockets[0].path must be an absolute path"));
        assert!(message.contains("ipc.dbus.system.owns[0] should be a well-known D-Bus name"));
        assert!(message.contains("capabilities[0] must be kebab-case"));
        assert!(message.contains("notes[0] must not be empty"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = serde_yaml::from_str::<IntentDocument>(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
unexpected: true
"#,
        )
        .expect_err("unknown field should fail");

        assert!(error.to_string().contains("unknown field"));
    }
}
