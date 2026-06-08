//! Normalized intermediate representation for policy generation.

use std::fmt;

use crate::schema::{IntentDocument, NetworkProtocol, StorageAccess, StoragePath, UnixSocketMode};

/// Portable security policy intent consumed by compiler backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIr {
    pub application: ApplicationIdentity,
    pub read_only_paths: Vec<PathNeed>,
    pub read_write_paths: Vec<PathNeed>,
    pub runtime_paths: Vec<PathNeed>,
    pub unix_sockets: Vec<UnixSocketNeed>,
    pub dbus_ownership: Vec<DbusNameNeed>,
    pub dbus_communication: Vec<DbusNameNeed>,
    pub outbound_network: Vec<OutboundNetworkNeed>,
    pub capabilities: Vec<CapabilityNeed>,
    pub manual_extensions: ManualExtensions,
}

impl PolicyIr {
    /// Build normalized policy intent from a validated schema document.
    pub fn from_document(document: &IntentDocument) -> Self {
        let mut read_only_paths = Vec::new();
        let mut read_write_paths = Vec::new();
        let mut runtime_paths = Vec::new();

        push_storage_paths(
            &document.storage.config,
            PathPurpose::Config,
            &mut read_only_paths,
            &mut read_write_paths,
            &mut runtime_paths,
        );
        push_storage_paths(
            &document.storage.cache,
            PathPurpose::Cache,
            &mut read_only_paths,
            &mut read_write_paths,
            &mut runtime_paths,
        );
        push_storage_paths(
            &document.storage.state,
            PathPurpose::State,
            &mut read_only_paths,
            &mut read_write_paths,
            &mut runtime_paths,
        );
        push_storage_paths(
            &document.storage.runtime,
            PathPurpose::Runtime,
            &mut read_only_paths,
            &mut read_write_paths,
            &mut runtime_paths,
        );

        read_only_paths.sort();
        read_only_paths.dedup();
        read_write_paths.sort();
        read_write_paths.dedup();
        runtime_paths.sort();
        runtime_paths.dedup();

        let mut unix_sockets = document
            .ipc
            .unix_sockets
            .iter()
            .map(|socket| UnixSocketNeed {
                path: normalize_path(&socket.path),
                role: match socket.mode {
                    UnixSocketMode::Server => UnixSocketRole::Server,
                    UnixSocketMode::Client => UnixSocketRole::Client,
                },
            })
            .collect::<Vec<_>>();
        unix_sockets.sort();
        unix_sockets.dedup();

        let mut dbus_ownership = document
            .ipc
            .dbus
            .system
            .owns
            .iter()
            .map(|name| DbusNameNeed {
                bus: DbusBus::System,
                name: name.clone(),
            })
            .collect::<Vec<_>>();
        dbus_ownership.sort();
        dbus_ownership.dedup();

        let mut dbus_communication = document
            .ipc
            .dbus
            .system
            .talks_to
            .iter()
            .map(|name| DbusNameNeed {
                bus: DbusBus::System,
                name: name.clone(),
            })
            .collect::<Vec<_>>();
        dbus_communication.sort();
        dbus_communication.dedup();

        let mut outbound_network = document
            .network
            .outbound
            .iter()
            .map(|outbound| {
                let protocol = NetworkProtocolNeed::from(outbound.protocol);
                OutboundNetworkNeed {
                    to: outbound.to.clone(),
                    protocol,
                    port: outbound.port.unwrap_or_else(|| protocol.default_port()),
                }
            })
            .collect::<Vec<_>>();
        outbound_network.sort();
        outbound_network.dedup();

        let mut capabilities = document
            .capabilities
            .iter()
            .map(|name| CapabilityNeed {
                name: name.clone(),
                linux_name: name.replace('-', "_"),
            })
            .collect::<Vec<_>>();
        capabilities.sort();
        capabilities.dedup();

        Self {
            application: ApplicationIdentity {
                name: document.application.name.clone(),
                description: document.application.description.clone(),
                executable: document.application.executable.clone(),
                user: document.application.user.clone(),
                group: document.application.group.clone(),
            },
            read_only_paths,
            read_write_paths,
            runtime_paths,
            unix_sockets,
            dbus_ownership,
            dbus_communication,
            outbound_network,
            capabilities,
            manual_extensions: ManualExtensions {
                selinux_policy: document.extensions.selinux.policy.clone(),
                selinux_file_contexts: document.extensions.selinux.file_contexts.clone(),
                apparmor_rules: document.extensions.apparmor.rules.clone(),
            },
        }
    }

    /// Render this IR for `intent explain`.
    pub fn explain(&self) -> String {
        let mut output = String::new();

        push_line(&mut output, "Intent IR");
        push_line(&mut output, "");
        push_line(&mut output, "Application:");
        push_line(&mut output, &format!("  name: {}", self.application.name));
        push_line(
            &mut output,
            &format!("  executable: {}", self.application.executable),
        );
        if let Some(description) = &self.application.description {
            push_line(&mut output, &format!("  description: {description}"));
        }
        if let Some(user) = &self.application.user {
            push_line(&mut output, &format!("  user: {user}"));
        }
        if let Some(group) = &self.application.group {
            push_line(&mut output, &format!("  group: {group}"));
        }

        push_path_section(&mut output, "Read-only paths", &self.read_only_paths);
        push_path_section(&mut output, "Read-write paths", &self.read_write_paths);
        push_path_section(&mut output, "Runtime paths", &self.runtime_paths);
        push_socket_section(&mut output, &self.unix_sockets);
        push_dbus_section(&mut output, "D-Bus ownership", &self.dbus_ownership);
        push_dbus_section(&mut output, "D-Bus communication", &self.dbus_communication);
        push_network_section(&mut output, &self.outbound_network);
        push_capability_section(&mut output, &self.capabilities);
        push_manual_extension_section(&mut output, &self.manual_extensions);

        output
    }
}

/// Application identity and executable entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationIdentity {
    pub name: String,
    pub description: Option<String>,
    pub executable: String,
    pub user: Option<String>,
    pub group: Option<String>,
}

/// Backend-specific raw policy fragments carried through normalization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManualExtensions {
    pub selinux_policy: Vec<String>,
    pub selinux_file_contexts: Vec<String>,
    pub apparmor_rules: Vec<String>,
}

/// A normalized filesystem need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathNeed {
    pub path: String,
    pub purpose: PathPurpose,
    pub access: PathAccess,
}

/// High-level filesystem purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathPurpose {
    Config,
    Cache,
    State,
    Runtime,
}

impl PathPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Cache => "cache",
            Self::State => "state",
            Self::Runtime => "runtime",
        }
    }
}

impl fmt::Display for PathPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalized filesystem access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathAccess {
    Read,
    ReadWrite,
}

impl PathAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read-write",
        }
    }
}

impl fmt::Display for PathAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Unix domain socket need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixSocketNeed {
    pub path: String,
    pub role: UnixSocketRole,
}

/// Whether the application creates or connects to a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixSocketRole {
    Server,
    Client,
}

impl UnixSocketRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

impl fmt::Display for UnixSocketRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A D-Bus bus/name need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DbusNameNeed {
    pub bus: DbusBus,
    pub name: String,
}

/// D-Bus bus kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DbusBus {
    System,
}

impl DbusBus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
        }
    }
}

impl fmt::Display for DbusBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A normalized outbound network need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutboundNetworkNeed {
    pub to: String,
    pub protocol: NetworkProtocolNeed,
    pub port: u16,
}

/// Developer-facing outbound network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkProtocolNeed {
    Http,
    Https,
    Tcp,
    Udp,
}

impl NetworkProtocolNeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
            Self::Tcp | Self::Udp => {
                unreachable!("validated tcp and udp network needs include a port")
            }
        }
    }
}

impl From<NetworkProtocol> for NetworkProtocolNeed {
    fn from(value: NetworkProtocol) -> Self {
        match value {
            NetworkProtocol::Http => Self::Http,
            NetworkProtocol::Https => Self::Https,
            NetworkProtocol::Tcp => Self::Tcp,
            NetworkProtocol::Udp => Self::Udp,
        }
    }
}

impl fmt::Display for NetworkProtocolNeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A normalized Linux capability need.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapabilityNeed {
    pub name: String,
    pub linux_name: String,
}

fn push_storage_paths(
    paths: &[StoragePath],
    purpose: PathPurpose,
    read_only_paths: &mut Vec<PathNeed>,
    read_write_paths: &mut Vec<PathNeed>,
    runtime_paths: &mut Vec<PathNeed>,
) {
    for path in paths {
        let access = match path.access {
            StorageAccess::Read => PathAccess::Read,
            StorageAccess::ReadWrite => PathAccess::ReadWrite,
        };
        let need = PathNeed {
            path: normalize_path(&path.path),
            purpose,
            access,
        };

        if purpose == PathPurpose::Runtime {
            runtime_paths.push(need);
        } else if access == PathAccess::Read {
            read_only_paths.push(need);
        } else {
            read_write_paths.push(need);
        }
    }
}

fn push_path_section(output: &mut String, title: &str, paths: &[PathNeed]) {
    push_line(output, "");
    push_line(output, &format!("{title}:"));
    if paths.is_empty() {
        push_line(output, "  none");
        return;
    }

    for path in paths {
        push_line(
            output,
            &format!("  - {} ({}, {})", path.path, path.purpose, path.access),
        );
    }
}

fn push_socket_section(output: &mut String, sockets: &[UnixSocketNeed]) {
    push_line(output, "");
    push_line(output, "Unix sockets:");
    if sockets.is_empty() {
        push_line(output, "  none");
        return;
    }

    for socket in sockets {
        push_line(output, &format!("  - {} ({})", socket.path, socket.role));
    }
}

fn push_dbus_section(output: &mut String, title: &str, names: &[DbusNameNeed]) {
    push_line(output, "");
    push_line(output, &format!("{title}:"));
    if names.is_empty() {
        push_line(output, "  none");
        return;
    }

    for name in names {
        push_line(output, &format!("  - {} ({})", name.name, name.bus));
    }
}

fn push_network_section(output: &mut String, outbound: &[OutboundNetworkNeed]) {
    push_line(output, "");
    push_line(output, "Outbound network:");
    if outbound.is_empty() {
        push_line(output, "  none");
        return;
    }

    for need in outbound {
        push_line(
            output,
            &format!("  - {} {}:{}", need.protocol, need.to, need.port),
        );
    }
}

fn push_capability_section(output: &mut String, capabilities: &[CapabilityNeed]) {
    push_line(output, "");
    push_line(output, "Capabilities:");
    if capabilities.is_empty() {
        push_line(output, "  none");
        return;
    }

    for capability in capabilities {
        push_line(output, &format!("  - {}", capability.name));
    }
}

fn push_manual_extension_section(output: &mut String, extensions: &ManualExtensions) {
    push_line(output, "");
    push_line(output, "Manual extensions:");
    if extensions.selinux_policy.is_empty()
        && extensions.selinux_file_contexts.is_empty()
        && extensions.apparmor_rules.is_empty()
    {
        push_line(output, "  none");
        return;
    }

    if !extensions.selinux_policy.is_empty() {
        push_line(
            output,
            &format!(
                "  - SELinux policy fragments: {}",
                extensions.selinux_policy.len()
            ),
        );
    }

    if !extensions.selinux_file_contexts.is_empty() {
        push_line(
            output,
            &format!(
                "  - SELinux file-context fragments: {}",
                extensions.selinux_file_contexts.len()
            ),
        );
    }

    if !extensions.apparmor_rules.is_empty() {
        push_line(
            output,
            &format!(
                "  - AppArmor rule fragments: {}",
                extensions.apparmor_rules.len()
            ),
        );
    }
}

fn normalize_path(path: &str) -> String {
    if path == "/" {
        path.to_string()
    } else {
        path.trim_end_matches('/').to_string()
    }
}

fn push_line(buffer: &mut String, line: &str) {
    buffer.push_str(line);
    buffer.push('\n');
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::IntentConfig;

    use super::*;

    fn ir(contents: &str) -> PolicyIr {
        IntentConfig::from_yaml(PathBuf::from("intent.yaml"), contents)
            .expect("intent yaml should load")
            .ir
    }

    #[test]
    fn omitted_and_explicit_empty_sections_produce_equivalent_ir() {
        let minimal = ir(r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
"#);
        let explicit_empty = ir(r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage: {}
network: {}
ipc:
  dbus:
    system: {}
"#);

        assert_eq!(minimal, explicit_empty);
    }

    #[test]
    fn trailing_slashes_and_default_https_port_produce_equivalent_ir() {
        let compact = ir(r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config:
    - path: /etc/demo
      access: read
network:
  outbound:
    - to: example.com
      protocol: https
"#);
        let explicit = ir(r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config:
    - path: /etc/demo/
      access: read
network:
  outbound:
    - to: example.com
      protocol: https
      port: 443
"#);

        assert_eq!(compact, explicit);
    }
}
