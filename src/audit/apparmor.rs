//! AppArmor audit log analysis.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::{render_review_suggestions, ReviewDenial, ReviewSuggestion};

/// One normalized AppArmor denial from the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialEvent {
    pub raw: String,
    pub profile: Option<String>,
    pub operation: Option<String>,
    pub requested_mask: Option<String>,
    pub denied_mask: Option<String>,
    pub name: Option<String>,
    pub peer_profile: Option<String>,
    pub target: DenialTarget,
}

/// Denied object category inferred from AppArmor audit fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialTarget {
    File,
    UnixSocket,
    Network {
        family: Option<String>,
        sock_type: Option<String>,
        protocol: Option<String>,
    },
    Other,
}

/// A high-level intent suggestion inferred from an AppArmor denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentSuggestion {
    pub summary: String,
    pub reason: String,
    pub yaml: String,
}

/// Parse an AppArmor audit log and render reviewable intent suggestions.
pub fn observe_path(source: &Path) -> Result<String, std::io::Error> {
    let contents = fs::read_to_string(source)?;
    Ok(observe(&contents))
}

/// Parse an AppArmor audit log and render reviewable intent suggestions.
pub fn observe(contents: &str) -> String {
    render_review_suggestions("AppArmor", &review_suggestions(contents))
}

/// Parse an AppArmor audit log and return grouped high-level suggestions.
pub fn review_suggestions(contents: &str) -> Vec<ReviewSuggestion> {
    group_suggestions(parse_audit_log(contents))
}

/// Parse AppArmor denials into structured events.
pub fn parse_audit_log(contents: &str) -> Vec<DenialEvent> {
    contents
        .lines()
        .filter(|line| line.contains("apparmor=\"DENIED\""))
        .map(parse_denial_line)
        .collect()
}

/// Infer a first-pass high-level Intent suggestion from an AppArmor denial.
pub fn infer_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    match &event.target {
        DenialTarget::File => infer_storage_intent(event),
        DenialTarget::UnixSocket => infer_unix_socket_intent(event),
        DenialTarget::Network { .. } if is_connect_operation(event) => Some(IntentSuggestion {
            summary: "outbound network access".to_string(),
            reason: "an AppArmor network connect denial maps to portable outbound network intent instead of a profile-specific rule".to_string(),
            yaml: network_yaml(event),
        }),
        DenialTarget::Network { .. } => None,
        DenialTarget::Other => None,
    }
}

fn parse_denial_line(line: &str) -> DenialEvent {
    let fields = parse_fields(line);
    let family = fields.get("family").cloned();
    let sock_type = fields.get("sock_type").cloned();
    let protocol = fields.get("protocol").cloned();

    let target = classify_target(&fields, family.clone(), sock_type.clone(), protocol.clone());

    DenialEvent {
        raw: line.to_string(),
        profile: fields.get("profile").cloned(),
        operation: fields.get("operation").cloned(),
        requested_mask: fields.get("requested_mask").cloned(),
        denied_mask: fields.get("denied_mask").cloned(),
        name: fields.get("name").cloned(),
        peer_profile: fields
            .get("peer_profile")
            .or_else(|| fields.get("peer"))
            .cloned(),
        target,
    }
}

fn group_suggestions(events: Vec<DenialEvent>) -> Vec<ReviewSuggestion> {
    let mut suggestions = Vec::<ReviewSuggestion>::new();

    for event in events {
        let Some(suggestion) = infer_intent(&event) else {
            continue;
        };
        let denial = review_denial(&event);
        if let Some(existing) = suggestions
            .iter_mut()
            .find(|existing| existing.yaml == suggestion.yaml)
        {
            existing.denials.push(denial);
        } else {
            suggestions.push(ReviewSuggestion {
                summary: suggestion.summary,
                reason: suggestion.reason,
                yaml: suggestion.yaml,
                denials: vec![denial],
            });
        }
    }

    suggestions
}

fn review_denial(event: &DenialEvent) -> ReviewDenial {
    let mut description = Vec::new();
    if let Some(profile) = &event.profile {
        description.push(("profile".to_string(), profile.clone()));
    }
    if let Some(operation) = &event.operation {
        description.push(("operation".to_string(), operation.clone()));
    }
    if let Some(mask) = &event.requested_mask {
        description.push(("requested_mask".to_string(), mask.clone()));
    }
    if let Some(mask) = &event.denied_mask {
        description.push(("denied_mask".to_string(), mask.clone()));
    }
    if let Some(name) = &event.name {
        description.push(("name".to_string(), name.clone()));
    }
    if let Some(peer_profile) = &event.peer_profile {
        description.push(("peer_profile".to_string(), peer_profile.clone()));
    }
    if let DenialTarget::Network {
        family,
        sock_type,
        protocol,
    } = &event.target
    {
        let mut values = Vec::new();
        if let Some(family) = family {
            values.push(format!("family={family}"));
        }
        if let Some(sock_type) = sock_type {
            values.push(format!("sock_type={sock_type}"));
        }
        if let Some(protocol) = protocol {
            values.push(format!("protocol={protocol}"));
        }
        if !values.is_empty() {
            description.push(("socket".to_string(), values.join(", ")));
        }
    }

    ReviewDenial {
        description,
        raw: event.raw.clone(),
    }
}

fn infer_storage_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    let path = event.name.as_deref()?;
    let (purpose, base_path) = storage_purpose_and_path(path)?;

    Some(IntentSuggestion {
        summary: format!("persistent {purpose} storage"),
        reason: format!(
            "the denied path is under {base_path}, which matches Intent's {purpose} storage convention"
        ),
        yaml: format!(
            "storage:\n  {purpose}:\n    - path: {base_path}\n      access: {}",
            storage_access(event).as_str()
        ),
    })
}

fn infer_unix_socket_intent(event: &DenialEvent) -> Option<IntentSuggestion> {
    let path = event.name.as_deref().unwrap_or("/run/<service>/<socket>");
    let mode = if has_any_value(
        event,
        &["create", "listen", "bind", "accept", "rw", "wr", "w"],
    ) {
        "server"
    } else {
        "client"
    };

    Some(IntentSuggestion {
        summary: "Unix domain socket IPC".to_string(),
        reason: "an AppArmor Unix socket denial maps to ipc.unix_sockets with client/server mode inferred from the denied operation or mask".to_string(),
        yaml: format!("ipc:\n  unix_sockets:\n    - path: {path}\n      mode: {mode}"),
    })
}

fn network_yaml(event: &DenialEvent) -> String {
    let protocol = network_protocol(event);
    let mut yaml =
        format!("network:\n  outbound:\n    - to: <destination>\n      protocol: {protocol}");
    if let Some(port) = event.name.as_deref().and_then(parse_port_from_name) {
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

fn storage_access(event: &DenialEvent) -> SuggestedAccess {
    let mask = event
        .denied_mask
        .as_deref()
        .or(event.requested_mask.as_deref())
        .unwrap_or("");

    if field_has_any_value(
        mask,
        &[
            "w", "a", "c", "d", "k", "l", "rw", "wr", "write", "append", "create", "delete",
            "rename", "setattr", "unlink",
        ],
    ) || operation_is_any(
        event,
        &[
            "write", "append", "create", "delete", "rename", "setattr", "unlink",
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

fn classify_target(
    fields: &HashMap<String, String>,
    family: Option<String>,
    sock_type: Option<String>,
    protocol: Option<String>,
) -> DenialTarget {
    if is_unix_socket(fields) {
        return DenialTarget::UnixSocket;
    }

    if family.is_some() || fields.get("class").is_some_and(|class| class == "net") {
        return DenialTarget::Network {
            family,
            sock_type,
            protocol,
        };
    }

    if fields.get("class").is_none_or(|class| class == "file") && fields.contains_key("name") {
        return DenialTarget::File;
    }

    DenialTarget::Other
}

fn is_unix_socket(fields: &HashMap<String, String>) -> bool {
    fields
        .get("family")
        .is_some_and(|family| family == "unix" || family == "AF_UNIX")
        || fields
            .get("class")
            .is_some_and(|class| class == "unix" || class == "unix_socket")
        || fields
            .get("operation")
            .is_some_and(|operation| operation.starts_with("unix_"))
}

fn is_connect_operation(event: &DenialEvent) -> bool {
    has_any_value(event, &["connect"])
}

fn network_protocol(event: &DenialEvent) -> &'static str {
    match &event.target {
        DenialTarget::Network {
            sock_type,
            protocol,
            ..
        } if sock_type.as_deref() == Some("dgram") || protocol.as_deref() == Some("17") => "udp",
        _ => "tcp",
    }
}

fn parse_port_from_name(name: &str) -> Option<u16> {
    name.rsplit_once(':')
        .and_then(|(_address, port)| port.parse::<u16>().ok())
}

fn has_any_value(event: &DenialEvent, values: &[&str]) -> bool {
    operation_is_any(event, values)
        || [
            event.requested_mask.as_deref(),
            event.denied_mask.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|field| field_has_any_value(field, values))
}

fn operation_is_any(event: &DenialEvent, values: &[&str]) -> bool {
    event
        .operation
        .as_deref()
        .is_some_and(|operation| values.iter().any(|value| operation == *value))
}

fn field_has_any_value(field: &str, values: &[&str]) -> bool {
    values.iter().any(|value| {
        field == *value
            || field
                .split([' ', ','])
                .any(|part| !part.is_empty() && part == *value)
            || (value.len() == 1 && field.contains(value))
    })
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

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"type=1400 audit(1718123810.015:420): apparmor="DENIED" operation="open" class="file" profile="himmelblaud" name="/etc/himmelblaud/config.yaml" pid=1234 comm="himmelblaud" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
type=1400 audit(1718123811.055:421): apparmor="DENIED" operation="open" class="file" profile="himmelblaud" name="/var/cache/himmelblaud/tokens.db" pid=1234 comm="himmelblaud" requested_mask="rw" denied_mask="w" fsuid=0 ouid=0
type=1400 audit(1718123812.055:422): apparmor="DENIED" operation="connect" class="net" profile="himmelblaud" name="203.0.113.10:443" family="inet" sock_type="stream" protocol=6 requested_mask="connect" denied_mask="connect"
type=1400 audit(1718123813.055:423): apparmor="DENIED" operation="connect" class="unix" profile="himmelblaud" name="/run/dbus/system_bus_socket" requested_mask="wr" denied_mask="wr" peer_profile="unconfined""#;

    #[test]
    fn parses_apparmor_denials() {
        let events = parse_audit_log(SAMPLE);

        assert_eq!(events.len(), 4);
        assert_eq!(events[0].profile.as_deref(), Some("himmelblaud"));
        assert_eq!(events[0].operation.as_deref(), Some("open"));
        assert_eq!(events[0].requested_mask.as_deref(), Some("r"));
        assert_eq!(events[0].denied_mask.as_deref(), Some("r"));
        assert_eq!(
            events[0].name.as_deref(),
            Some("/etc/himmelblaud/config.yaml")
        );
        assert_eq!(events[0].target, DenialTarget::File);
        assert_eq!(
            events[2].target,
            DenialTarget::Network {
                family: Some("inet".to_string()),
                sock_type: Some("stream".to_string()),
                protocol: Some("6".to_string())
            }
        );
        assert_eq!(events[3].target, DenialTarget::UnixSocket);
        assert_eq!(events[3].peer_profile.as_deref(), Some("unconfined"));
    }

    #[test]
    fn infers_storage_purposes_from_file_denials() {
        let events = parse_audit_log(SAMPLE);
        let config = infer_intent(&events[0]).expect("config should be inferred");
        let cache = infer_intent(&events[1]).expect("cache should be inferred");

        assert_eq!(config.summary, "persistent config storage");
        assert_eq!(
            config.yaml,
            "storage:\n  config:\n    - path: /etc/himmelblaud\n      access: read"
        );
        assert_eq!(cache.summary, "persistent cache storage");
        assert_eq!(
            cache.yaml,
            "storage:\n  cache:\n    - path: /var/cache/himmelblaud\n      access: read-write"
        );
    }

    #[test]
    fn uses_denied_mask_for_storage_access() {
        let events = parse_audit_log(
            r#"type=1400 audit(1718123810.015:420): apparmor="DENIED" operation="open" class="file" profile="himmelblaud" name="/var/lib/himmelblaud/state.db" requested_mask="rw" denied_mask="r""#,
        );
        let suggestion = infer_intent(&events[0]).expect("state should be inferred");

        assert_eq!(
            suggestion.yaml,
            "storage:\n  state:\n    - path: /var/lib/himmelblaud\n      access: read"
        );
    }

    #[test]
    fn renders_observe_output_with_suggestions() {
        let output = observe(SAMPLE);

        assert!(output.contains("Suggestion 1 of 4:"));
        assert!(output.contains("What was denied:"));
        assert!(output.contains("profile: himmelblaud"));
        assert!(output.contains("operation: open"));
        assert!(output.contains("requested_mask: r"));
        assert!(output.contains("denied_mask: r"));
        assert!(output.contains("name: /etc/himmelblaud/config.yaml"));
        assert!(output.contains("Why Intent mapped it this way:"));
        assert!(output.contains("persistent config storage"));
        assert!(output.contains("storage:\n    config:\n      - path: /etc/himmelblaud"));
        assert!(output.contains("socket: family=inet, sock_type=stream, protocol=6"));
        assert!(output.contains("network:\n    outbound:"));
        assert!(output.contains("ipc:\n    unix_sockets:"));
        assert!(output.contains("peer_profile: unconfined"));
    }

    #[test]
    fn groups_similar_denials_into_one_suggestion() {
        let input = r#"type=1400 audit(1718123810.015:420): apparmor="DENIED" operation="open" class="file" profile="himmelblaud" name="/var/cache/himmelblaud/tokens.db" requested_mask="rw" denied_mask="w"
type=1400 audit(1718123811.015:421): apparmor="DENIED" operation="open" class="file" profile="himmelblaud" name="/var/cache/himmelblaud/other.db" requested_mask="rw" denied_mask="w""#;

        let suggestions = review_suggestions(input);

        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].summary, "persistent cache storage");
        assert_eq!(suggestions[0].denials.len(), 2);
    }

    #[test]
    fn generates_non_interactive_grouped_suggestions() {
        let output = observe(SAMPLE);

        assert!(output.contains("Grouped denials: 1"));
        assert!(output.contains("Proposed YAML fragment:"));
        assert!(output.contains("port: 443"));
    }
}
