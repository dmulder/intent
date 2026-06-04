//! Public schema model for Intent files.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::diagnostics::{Diagnostic, Severity};

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
        self.validate_with_options(ValidationOptions::default())
            .map(|_| ())
    }

    pub fn validate_with_options(
        &self,
        options: ValidationOptions,
    ) -> Result<ValidationReport, ValidationError> {
        let diagnostics = self.diagnostics();
        let has_fatal = diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error
                || (options.deny_warnings && diagnostic.severity == Severity::Warning)
        });

        if has_fatal {
            Err(ValidationError { diagnostics })
        } else {
            Ok(ValidationReport { diagnostics })
        }
    }

    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if self.version != CURRENT_SCHEMA_VERSION {
            diagnostics.push(
                Diagnostic::error(format!("version must be {CURRENT_SCHEMA_VERSION}"))
                    .found(self.version.to_string())
                    .help(format!("set version: {CURRENT_SCHEMA_VERSION}")),
            );
        }

        self.application.validate(&mut diagnostics);
        self.storage.validate(&mut diagnostics);
        self.network.validate(&mut diagnostics);
        self.ipc.validate(&mut diagnostics);

        for (index, capability) in self.capabilities.iter().enumerate() {
            validate_non_empty(
                &mut diagnostics,
                format!("capabilities[{index}]"),
                capability,
            );
            validate_kebab_name(
                &mut diagnostics,
                format!("capabilities[{index}]"),
                capability,
                "use developer-friendly kebab-case such as net-bind-service",
            );
        }

        for (index, note) in self.notes.iter().enumerate() {
            validate_non_empty(&mut diagnostics, format!("notes[{index}]"), note);
        }

        diagnostics
    }
}

/// Validation options used by `intent validate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationOptions {
    pub deny_warnings: bool,
}

/// Diagnostics found while validating a syntactically parsed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
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
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        validate_non_empty(diagnostics, "application.name", &self.name);
        validate_non_empty(diagnostics, "application.executable", &self.executable);

        if !self.executable.starts_with('/') {
            diagnostics.push(
                Diagnostic::error("application.executable must be an absolute path")
                    .found(self.executable.clone())
                    .help(format!("use /{}", self.executable.trim_start_matches('/'))),
            );
        } else {
            validate_path(diagnostics, "application.executable", &self.executable);
        }

        if let Some(description) = &self.description {
            validate_non_empty(diagnostics, "application.description", description);
        }

        if let Some(user) = &self.user {
            validate_non_empty(diagnostics, "application.user", user);
        }

        if let Some(group) = &self.group {
            validate_non_empty(diagnostics, "application.group", group);
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
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        validate_storage_paths(
            diagnostics,
            "storage.config",
            &self.config,
            StorageKind::Config,
        );
        validate_storage_paths(
            diagnostics,
            "storage.cache",
            &self.cache,
            StorageKind::Cache,
        );
        validate_storage_paths(
            diagnostics,
            "storage.state",
            &self.state,
            StorageKind::State,
        );
        validate_storage_paths(
            diagnostics,
            "storage.runtime",
            &self.runtime,
            StorageKind::Runtime,
        );
    }
}

/// A file or directory with a high-level access mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePath {
    pub path: String,
    pub access: StorageAccess,
    #[serde(default)]
    pub justification: Option<String>,
}

/// Storage access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageAccess {
    Read,
    ReadWrite,
}

impl<'de> Deserialize<'de> for StorageAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "read" => Ok(Self::Read),
            "read-write" => Ok(Self::ReadWrite),
            other => Err(de::Error::custom(format!(
                "invalid access mode '{other}'; expected read or read-write"
            ))),
        }
    }
}

/// Network access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub outbound: Vec<OutboundNetwork>,
}

impl Network {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, outbound) in self.outbound.iter().enumerate() {
            let prefix = format!("network.outbound[{index}]");
            validate_non_empty(diagnostics, format!("{prefix}.to"), &outbound.to);

            if let Some(port) = outbound.port {
                if port == 0 {
                    diagnostics.push(
                        Diagnostic::error(format!("{prefix}.port must be between 1 and 65535"))
                            .found("0")
                            .help("use a TCP or UDP port from 1 through 65535"),
                    );
                }
            }

            if matches!(
                outbound.protocol,
                NetworkProtocol::Tcp | NetworkProtocol::Udp
            ) && outbound.port.is_none()
            {
                diagnostics.push(
                    Diagnostic::error(format!(
                        "{prefix}.port is required when protocol is tcp or udp"
                    ))
                    .help("add a port field, for example port: 443"),
                );
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Http,
    Https,
    Tcp,
    Udp,
}

impl<'de> Deserialize<'de> for NetworkProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(de::Error::custom(format!(
                "unknown network protocol '{other}'; expected http, https, tcp, or udp"
            ))),
        }
    }
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
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, socket) in self.unix_sockets.iter().enumerate() {
            let prefix = format!("ipc.unix_sockets[{index}]");
            validate_non_empty(diagnostics, format!("{prefix}.path"), &socket.path);

            if !socket.path.starts_with('/') {
                diagnostics.push(
                    Diagnostic::error(format!("{prefix}.path must be an absolute path"))
                        .found(socket.path.clone())
                        .help(format!("use /{}", socket.path.trim_start_matches('/'))),
                );
            } else {
                validate_path(diagnostics, format!("{prefix}.path"), &socket.path);
            }
        }

        self.dbus.validate(diagnostics);
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketMode {
    Server,
    Client,
}

impl<'de> Deserialize<'de> for UnixSocketMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            other => Err(de::Error::custom(format!(
                "invalid socket mode '{other}'; expected server or client"
            ))),
        }
    }
}

/// D-Bus access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dbus {
    #[serde(default)]
    pub system: SystemBus,
}

impl Dbus {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        self.system.validate(diagnostics);
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
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, name) in self.owns.iter().enumerate() {
            validate_dbus_name(diagnostics, format!("ipc.dbus.system.owns[{index}]"), name);
        }

        for (index, name) in self.talks_to.iter().enumerate() {
            validate_dbus_name(
                diagnostics,
                format!("ipc.dbus.system.talks_to[{index}]"),
                name,
            );
        }
    }
}

/// Validation failures found after a document was syntactically parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{diagnostic}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug, Clone, Copy)]
enum StorageKind {
    Config,
    Cache,
    State,
    Runtime,
}

fn validate_storage_paths(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    paths: &[StoragePath],
    kind: StorageKind,
) {
    for (index, entry) in paths.iter().enumerate() {
        let prefix = format!("{field}[{index}]");
        validate_non_empty(diagnostics, format!("{prefix}.path"), &entry.path);

        if !entry.path.starts_with('/') {
            diagnostics.push(
                Diagnostic::error(format!("{prefix}.path must be an absolute path"))
                    .found(entry.path.clone())
                    .help(format!("use /{}", entry.path.trim_start_matches('/'))),
            );
            continue;
        }

        validate_path(diagnostics, format!("{prefix}.path"), &entry.path);

        let broad_path = trim_trailing_slashes(&entry.path);
        if matches!(broad_path.as_str(), "/" | "/etc" | "/var" | "/usr") {
            diagnostics.push(
                Diagnostic::warning(format!("{prefix}.path is very broad"))
                    .found(entry.path.clone())
                    .help("declare the narrowest application-specific directory instead"),
            );
        }

        match kind {
            StorageKind::Config => {}
            StorageKind::Runtime => {
                if !is_under(&entry.path, "/run") && !is_under(&entry.path, "/var/run") {
                    diagnostics.push(
                        Diagnostic::error(format!(
                            "{prefix}.path must be under /run or /var/run for runtime storage"
                        ))
                        .found(entry.path.clone())
                        .help("move runtime files to /run/<application>"),
                    );
                }
            }
            StorageKind::Cache => {
                validate_expected_storage_root(
                    diagnostics,
                    &prefix,
                    &entry.path,
                    entry.justification.as_deref(),
                    "/var/cache",
                    "cache",
                    "move cache files to /var/cache/<application> or add justification",
                );
            }
            StorageKind::State => {
                validate_expected_storage_root(
                    diagnostics,
                    &prefix,
                    &entry.path,
                    entry.justification.as_deref(),
                    "/var/lib",
                    "state",
                    "move state files to /var/lib/<application> or add justification",
                );
            }
        }
    }
}

fn validate_dbus_name(diagnostics: &mut Vec<Diagnostic>, field: String, name: &str) {
    validate_non_empty(diagnostics, &field, name);

    if name.trim().is_empty() {
        return;
    }

    if !is_valid_dbus_name(name) {
        diagnostics.push(
            Diagnostic::error(format!("{field} must be a valid D-Bus well-known name"))
                .found(name.to_string())
                .help("use a dotted name such as org.example.Service"),
        );
    }
}

fn validate_non_empty(diagnostics: &mut Vec<Diagnostic>, field: impl AsRef<str>, value: &str) {
    if value.trim().is_empty() {
        diagnostics.push(Diagnostic::error(format!(
            "{} must not be empty",
            field.as_ref()
        )));
    }
}

fn validate_kebab_name(diagnostics: &mut Vec<Diagnostic>, field: String, value: &str, help: &str) {
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
        diagnostics.push(
            Diagnostic::error(format!("{field} must be kebab-case"))
                .found(value.to_string())
                .help(help),
        );
    }
}

fn validate_path(diagnostics: &mut Vec<Diagnostic>, field: impl AsRef<str>, path: &str) {
    let field = field.as_ref();

    if path.contains('\0') {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain NUL bytes"))
                .found(path.to_string()),
        );
    }

    if path.lines().count() > 1 {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain line breaks"))
                .found(path.to_string())
                .help("keep paths on one line"),
        );
    }

    if path
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain . or .. path components"))
                .found(path.to_string())
                .help("use a normalized absolute path"),
        );
    }
}

fn validate_expected_storage_root(
    diagnostics: &mut Vec<Diagnostic>,
    prefix: &str,
    path: &str,
    justification: Option<&str>,
    expected_root: &str,
    kind: &str,
    help: &str,
) {
    if is_under(path, expected_root) {
        return;
    }

    if justification.is_some_and(|value| !value.trim().is_empty()) {
        return;
    }

    diagnostics.push(
        Diagnostic::warning(format!(
            "{prefix}.path is outside {expected_root} for {kind} storage"
        ))
        .found(path.to_string())
        .help(help),
    );
}

fn is_under(path: &str, expected_root: &str) -> bool {
    let path = trim_trailing_slashes(path);
    path == expected_root || path.starts_with(&format!("{expected_root}/"))
}

fn trim_trailing_slashes(path: &str) -> String {
    if path == "/" {
        return path.to_string();
    }

    path.trim_end_matches('/').to_string()
}

fn is_valid_dbus_name(name: &str) -> bool {
    if name.len() > 255 || !name.contains('.') || name.starts_with('.') || name.ends_with('.') {
        return false;
    }

    name.split('.').all(|part| {
        let Some(first) = part.chars().next() else {
            return false;
        };

        !first.is_ascii_digit()
            && part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    })
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
        assert!(message.contains("ipc.dbus.system.owns[0] must be a valid D-Bus"));
        assert!(message.contains("capabilities[0] must be kebab-case"));
        assert!(message.contains("notes[0] must not be empty"));
    }

    #[test]
    fn warns_for_suspicious_broad_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config:
    - path: /etc
      access: read
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        let message = report
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(message.contains("warning: storage.config[0].path is very broad"));
        assert!(document
            .validate_with_options(ValidationOptions {
                deny_warnings: true
            })
            .is_err());
    }

    #[test]
    fn rejects_invalid_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/../bin/demo
storage:
  config:
    - path: /etc/demo/./config
      access: read
"#,
        );

        let message = document
            .validate()
            .expect_err("invalid paths should fail")
            .to_string();

        assert!(message.contains("application.executable must not contain . or .."));
        assert!(message.contains("storage.config[0].path must not contain . or .."));
        assert!(message.contains("help: use a normalized absolute path"));
    }

    #[test]
    fn rejects_runtime_paths_outside_runtime_roots() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  runtime:
    - path: /tmp/demo
      access: read-write
"#,
        );

        let message = document
            .validate()
            .expect_err("runtime path outside /run should fail")
            .to_string();

        assert!(message.contains("storage.runtime[0].path must be under /run or /var/run"));
    }

    #[test]
    fn warns_for_unjustified_cache_and_state_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  cache:
    - path: /opt/demo/cache
      access: read-write
  state:
    - path: /srv/demo/state
      access: read-write
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        let message = report
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(message.contains("warning: storage.cache[0].path is outside /var/cache"));
        assert!(message.contains("warning: storage.state[0].path is outside /var/lib"));
    }

    #[test]
    fn accepts_justified_cache_and_state_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  cache:
    - path: /opt/demo/cache
      access: read-write
      justification: vendor package layout
  state:
    - path: /srv/demo/state
      access: read-write
      justification: shared service data
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        assert!(report.diagnostics.is_empty());
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
