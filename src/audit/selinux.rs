//! SELinux audit log analysis.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

/// One normalized SELinux AVC denial from the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialEvent {
    pub audit_id: Option<String>,
    pub process: Option<String>,
    pub executable: Option<String>,
    pub path: Option<String>,
    pub access: Vec<String>,
    pub object_class: String,
    pub source_context: Option<String>,
    pub target_context: Option<String>,
    pub target: DenialTarget,
}

/// Denied object category inferred from SELinux class and audit fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialTarget {
    File,
    Directory,
    UnixSocket,
    Network {
        protocol: NetworkProtocol,
        port: Option<u16>,
    },
    Capability,
    Dbus {
        bus: Option<String>,
        name: Option<String>,
    },
    Other,
}

/// Network protocol inferred from a socket class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Other,
}

impl NetworkProtocol {
    fn as_intent_value(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Other => "tcp",
        }
    }
}

/// A high-level intent suggestion inferred from an AVC denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSuggestion {
    pub summary: String,
    pub yaml: String,
}

/// Parse a SELinux audit log and render reviewable intent suggestions.
pub fn observe_path(source: &Path) -> Result<String, std::io::Error> {
    let contents = fs::read_to_string(source)?;
    Ok(observe(&contents))
}

/// Parse a SELinux audit log and render reviewable intent suggestions.
pub fn observe(contents: &str) -> String {
    let events = parse_audit_log(contents);

    if events.is_empty() {
        return "No SELinux AVC denials detected.".to_string();
    }

    let mut output = String::new();
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            push_line(&mut output, "");
        }

        push_event(&mut output, event);
        if let Some(suggestion) = infer_intent(event) {
            push_line(&mut output, "");
            push_line(&mut output, "Likely intent:");
            push_line(&mut output, &format!("  {}", suggestion.summary));
            push_line(&mut output, "");
            push_line(&mut output, "Suggested intent.yaml addition:");
            for line in suggestion.yaml.lines() {
                push_line(&mut output, &format!("  {line}"));
            }
        } else {
            push_line(&mut output, "");
            push_line(&mut output, "Likely intent:");
            push_line(
                &mut output,
                "  No high-level Intent mapping inferred yet; review manually.",
            );
        }
    }

    output
}

/// Parse SELinux AVC denials into structured events.
pub fn parse_audit_log(contents: &str) -> Vec<DenialEvent> {
    let mut avcs = Vec::new();
    let mut paths_by_audit_id: HashMap<String, Vec<String>> = HashMap::new();

    for line in contents.lines() {
        if !line.contains("type=") {
            continue;
        }

        let fields = parse_fields(line);
        let audit_id = parse_audit_id(line).or_else(|| fields.get("msg").cloned());

        if line.contains("type=PATH") {
            if let (Some(audit_id), Some(path)) = (
                audit_id,
                fields.get("name").and_then(|name| absolute_path(name)),
            ) {
                paths_by_audit_id.entry(audit_id).or_default().push(path);
            }
            continue;
        }

        if line.contains("type=AVC") && line.contains("avc:") && line.contains("denied") {
            avcs.push(AvcRecord {
                audit_id,
                fields,
                access: parse_denied_access(line),
            });
        }
    }

    avcs.into_iter()
        .map(|avc| {
            let path = path_from_avc(&avc).or_else(|| {
                avc.audit_id
                    .as_ref()
                    .and_then(|id| paths_by_audit_id.get(id))
                    .and_then(|paths| paths.first().cloned())
            });
            let object_class = avc
                .fields
                .get("tclass")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let target = classify_target(&object_class, &avc.fields);

            DenialEvent {
                audit_id: avc.audit_id,
                process: avc.fields.get("comm").cloned(),
                executable: avc.fields.get("exe").cloned(),
                path,
                access: avc.access,
                object_class,
                source_context: avc.fields.get("scontext").cloned(),
                target_context: avc.fields.get("tcontext").cloned(),
                target,
            }
        })
        .collect()
}

/// Infer a first-pass high-level Intent suggestion from a denial.
pub fn infer_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    match &event.target {
        DenialTarget::File | DenialTarget::Directory => infer_storage_intent(event),
        DenialTarget::UnixSocket => infer_unix_socket_intent(event),
        DenialTarget::Network { protocol, port } => Some(IntentSuggestion {
            summary: "outbound network access".to_string(),
            yaml: network_yaml(*protocol, *port),
        }),
        DenialTarget::Capability => infer_capability_intent(event),
        DenialTarget::Dbus { bus, name } => {
            infer_dbus_intent(event, bus.as_deref(), name.as_deref())
        }
        DenialTarget::Other => None,
    }
}

#[derive(Debug)]
struct AvcRecord {
    audit_id: Option<String>,
    fields: HashMap<String, String>,
    access: Vec<String>,
}

fn push_event(output: &mut String, event: &DenialEvent) {
    push_line(output, "Detected SELinux denial:");
    if let Some(process) = &event.process {
        push_line(output, &format!("  process: {process}"));
    }
    if let Some(path) = &event.path {
        push_line(output, &format!("  path: {path}"));
    }
    if !event.access.is_empty() {
        push_line(output, &format!("  access: {}", event.access.join(", ")));
    }
    push_line(output, &format!("  class: {}", event.object_class));
}

fn infer_storage_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    let path = event.path.as_deref()?;
    let access = storage_access(&event.access);
    let (purpose, base_path) = storage_purpose_and_path(path)?;

    Some(IntentSuggestion {
        summary: format!("persistent {purpose} storage"),
        yaml: format!(
            "storage:\n  {purpose}:\n    - path: {base_path}\n      access: {}",
            access.as_str()
        ),
    })
}

fn infer_unix_socket_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    let path = event
        .path
        .as_deref()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "/run/<service>/<socket>".to_string());
    let mode = if has_any_access(&event.access, &["create", "listen", "bind", "accept"]) {
        "server"
    } else {
        "client"
    };

    Some(IntentSuggestion {
        summary: "Unix domain socket IPC".to_string(),
        yaml: format!("ipc:\n  unix_sockets:\n    - path: {path}\n      mode: {mode}"),
    })
}

fn infer_capability_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    let capabilities = event
        .access
        .iter()
        .map(|access| access.replace('_', "-"))
        .collect::<Vec<_>>();
    if capabilities.is_empty() {
        return None;
    }

    let mut yaml = "capabilities:".to_string();
    for capability in capabilities {
        if !yaml.ends_with('\n') {
            yaml.push('\n');
        }
        push_line(&mut yaml, &format!("  - {capability}"));
    }

    Some(IntentSuggestion {
        summary: "Linux capability".to_string(),
        yaml,
    })
}

fn infer_dbus_intent(
    event: &DenialEvent,
    bus: Option<&str>,
    name: Option<&str>,
) -> Option<IntentSuggestion> {
    let bus = bus.unwrap_or("system");
    let name = name.unwrap_or("<bus.name>");
    let action = if has_any_access(&event.access, &["acquire_svc"]) {
        "owns"
    } else {
        "talks_to"
    };
    let summary = if action == "owns" {
        "D-Bus service ownership"
    } else {
        "D-Bus system bus communication"
    };

    Some(IntentSuggestion {
        summary: summary.to_string(),
        yaml: format!("ipc:\n  dbus:\n    {bus}:\n      {action}:\n        - {name}"),
    })
}

fn network_yaml(protocol: NetworkProtocol, port: Option<u16>) -> String {
    let protocol = protocol.as_intent_value();
    let mut yaml =
        format!("network:\n  outbound:\n    - to: <destination>\n      protocol: {protocol}");
    if let Some(port) = port {
        yaml.push('\n');
        push_line(&mut yaml, &format!("      port: {port}"));
    }
    yaml
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuggestedAccess {
    Read,
    ReadWrite,
}

impl SuggestedAccess {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ReadWrite => "read-write",
        }
    }
}

fn storage_access(access: &[String]) -> SuggestedAccess {
    if has_any_access(
        access,
        &[
            "write",
            "append",
            "create",
            "add_name",
            "remove_name",
            "unlink",
            "rename",
            "rmdir",
            "setattr",
            "lock",
        ],
    ) {
        SuggestedAccess::ReadWrite
    } else {
        SuggestedAccess::Read
    }
}

fn storage_purpose_and_path(path: &str) -> Option<(&'static str, String)> {
    for (root, purpose) in [
        ("/var/cache", "cache"),
        ("/var/lib", "state"),
        ("/run", "runtime"),
        ("/var/run", "runtime"),
        ("/etc", "config"),
    ] {
        if let Some(base) = root_plus_one_component(path, root) {
            return Some((purpose, base));
        }
    }

    None
}

fn root_plus_one_component(path: &str, root: &str) -> Option<String> {
    if path == root {
        return Some(root.to_string());
    }

    let remainder = path.strip_prefix(root)?.strip_prefix('/')?;
    let component = remainder.split('/').next()?.trim();
    if component.is_empty() {
        None
    } else {
        Some(format!("{root}/{component}"))
    }
}

fn classify_target(object_class: &str, fields: &HashMap<String, String>) -> DenialTarget {
    match object_class {
        "file" | "lnk_file" | "chr_file" | "blk_file" | "fifo_file" | "sock_file" => {
            DenialTarget::File
        }
        "dir" => DenialTarget::Directory,
        "unix_stream_socket" | "unix_dgram_socket" => DenialTarget::UnixSocket,
        "tcp_socket" => DenialTarget::Network {
            protocol: NetworkProtocol::Tcp,
            port: parse_port(fields),
        },
        "udp_socket" => DenialTarget::Network {
            protocol: NetworkProtocol::Udp,
            port: parse_port(fields),
        },
        "capability" | "capability2" => DenialTarget::Capability,
        "dbus" => DenialTarget::Dbus {
            bus: fields.get("bus").cloned(),
            name: fields
                .get("name")
                .or_else(|| fields.get("dest"))
                .or_else(|| fields.get("destination"))
                .cloned(),
        },
        _ => DenialTarget::Other,
    }
}

fn parse_port(fields: &HashMap<String, String>) -> Option<u16> {
    ["dport", "dest", "port"]
        .into_iter()
        .find_map(|key| fields.get(key).and_then(|value| value.parse::<u16>().ok()))
}

fn path_from_avc(avc: &AvcRecord) -> Option<String> {
    avc.fields
        .get("path")
        .or_else(|| avc.fields.get("name"))
        .and_then(|value| absolute_path(value))
}

fn absolute_path(value: &str) -> Option<String> {
    if value.starts_with('/') {
        Some(value.to_string())
    } else {
        None
    }
}

fn parse_denied_access(line: &str) -> Vec<String> {
    let Some(denied) = line.find("denied") else {
        return Vec::new();
    };
    let after_denied = &line[denied..];
    let Some(open) = after_denied.find('{') else {
        return Vec::new();
    };
    let after_open = &after_denied[open + 1..];
    let Some(close) = after_open.find('}') else {
        return Vec::new();
    };

    after_open[..close]
        .split_whitespace()
        .map(str::trim)
        .filter(|access| !access.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_audit_id(line: &str) -> Option<String> {
    let start = line.find("msg=audit(")? + "msg=audit(".len();
    let end = line[start..].find(')')? + start;
    Some(line[start..end].to_string())
}

fn parse_fields(line: &str) -> HashMap<String, String> {
    split_tokens(line)
        .into_iter()
        .filter_map(|token| {
            let (key, value) = token.split_once('=')?;
            Some((key.to_string(), clean_value(value)))
        })
        .collect()
}

fn split_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for character in line.chars() {
        match character {
            '\\' if in_quotes && !escaped => {
                escaped = true;
                token.push(character);
            }
            '"' if !escaped => {
                in_quotes = !in_quotes;
                token.push(character);
            }
            ' ' | '\t' if !in_quotes => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => {
                escaped = false;
                token.push(character);
            }
        }
    }

    if !token.is_empty() {
        tokens.push(token);
    }

    tokens
}

fn clean_value(value: &str) -> String {
    let value = value.trim_end_matches(':');
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn has_any_access(access: &[String], values: &[&str]) -> bool {
    access
        .iter()
        .any(|access| values.iter().any(|value| access == value))
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

impl fmt::Display for DenialTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Directory => f.write_str("directory"),
            Self::UnixSocket => f.write_str("unix socket"),
            Self::Network { .. } => f.write_str("network"),
            Self::Capability => f.write_str("capability"),
            Self::Dbus { .. } => f.write_str("dbus"),
            Self::Other => f.write_str("other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"type=AVC msg=audit(1718123810.015:420): avc:  denied  { write } for  pid=1234 comm="himmelblaud" name="tokens.db" dev="dm-0" ino=100 scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:object_r:var_cache_t:s0 tclass=file permissive=0
type=SYSCALL msg=audit(1718123810.015:420): arch=c000003e syscall=2 success=no exit=-13 a0=7ffd9dd comm="himmelblaud" exe="/usr/libexec/himmelblaud"
type=PATH msg=audit(1718123810.015:420): item=0 name="/var/cache/himmelblaud/tokens.db" inode=100 dev=fd:00 mode=0100600 ouid=0 ogid=0
type=AVC msg=audit(1718123811.055:421): avc:  denied  { name_connect } for  pid=1234 comm="himmelblaud" dest=443 scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0
type=AVC msg=audit(1718123812.055:422): avc:  denied  { net_bind_service } for  pid=1234 comm="himmelblaud" capability=10 scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:system_r:himmelblaud_t:s0 tclass=capability permissive=0
type=AVC msg=audit(1718123813.055:423): avc:  denied  { connectto } for  pid=1234 comm="himmelblaud" path="/run/systemd/resolve/io.systemd.Resolve" scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:system_r:systemd_resolved_t:s0 tclass=unix_stream_socket permissive=0
type=AVC msg=audit(1718123814.055:424): avc:  denied  { send_msg } for  pid=1234 comm="himmelblaud" bus=system dest="org.freedesktop.resolve1" scontext=system_u:system_r:himmelblaud_t:s0 tcontext=system_u:system_r:system_dbusd_t:s0 tclass=dbus permissive=0"#;

    #[test]
    fn parses_avc_denials_and_correlates_path_records() {
        let events = parse_audit_log(SAMPLE);

        assert_eq!(events.len(), 5);
        assert_eq!(events[0].process.as_deref(), Some("himmelblaud"));
        assert_eq!(
            events[0].path.as_deref(),
            Some("/var/cache/himmelblaud/tokens.db")
        );
        assert_eq!(events[0].access, vec!["write"]);
        assert_eq!(events[0].target, DenialTarget::File);
        assert_eq!(
            events[1].target,
            DenialTarget::Network {
                protocol: NetworkProtocol::Tcp,
                port: Some(443)
            }
        );
        assert_eq!(events[2].target, DenialTarget::Capability);
        assert_eq!(events[3].target, DenialTarget::UnixSocket);
        assert_eq!(
            events[4].target,
            DenialTarget::Dbus {
                bus: Some("system".to_string()),
                name: Some("org.freedesktop.resolve1".to_string())
            }
        );
    }

    #[test]
    fn infers_cache_storage_from_file_write_denial() {
        let events = parse_audit_log(SAMPLE);
        let suggestion = infer_intent(&events[0]).expect("storage should be inferred");

        assert_eq!(suggestion.summary, "persistent cache storage");
        assert_eq!(
            suggestion.yaml,
            "storage:\n  cache:\n    - path: /var/cache/himmelblaud\n      access: read-write"
        );
    }

    #[test]
    fn renders_observe_output_with_suggestions() {
        let output = observe(SAMPLE);

        assert!(output.contains("Detected SELinux denial:"));
        assert!(output.contains("process: himmelblaud"));
        assert!(output.contains("path: /var/cache/himmelblaud/tokens.db"));
        assert!(output.contains("Likely intent:"));
        assert!(output.contains("persistent cache storage"));
        assert!(output.contains("storage:\n    cache:\n      - path: /var/cache/himmelblaud"));
        assert!(output.contains("network:\n    outbound:"));
        assert!(output.contains("capabilities:\n    - net-bind-service"));
        assert!(output.contains("ipc:\n    unix_sockets:"));
        assert!(output.contains("ipc:\n    dbus:"));
    }
}
