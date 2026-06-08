//! Reverse compilation from backend policy into high-level intent.yaml.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::config::IntentConfig;
use crate::schema::{
    AppArmorExtensions, Application, Extensions, IntentDocument, Ipc, Network, NetworkProtocol,
    OutboundNetwork, Process, SelinuxAllow, SelinuxExtensions, SelinuxFileContext,
    SelinuxFilesystemAssociation, SelinuxMacroCall, SelinuxPolicy, SelinuxRole, SelinuxTransition,
    SelinuxType, Storage, StorageAccess, StoragePath, UnixSocket, UnixSocketMode,
    CURRENT_SCHEMA_VERSION,
};

/// Supported policy import formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Selinux,
    AppArmor,
}

impl FromStr for ImportFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "selinux" => Ok(Self::Selinux),
            "apparmor" => Ok(Self::AppArmor),
            other => Err(format!(
                "unknown import format '{other}'; expected selinux or apparmor"
            )),
        }
    }
}

impl ImportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selinux => "selinux",
            Self::AppArmor => "apparmor",
        }
    }
}

/// Result of importing backend policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub document: IntentDocument,
    pub warnings: Vec<String>,
    pub explanations: Vec<ImportExplanation>,
}

impl ImportResult {
    /// Render a validated `intent.yaml` document.
    pub fn to_yaml(&self) -> Result<String, ImportError> {
        let yaml = serde_yaml::to_string(&self.document).map_err(ImportError::Render)?;
        IntentConfig::from_yaml(std::path::PathBuf::from("imported.intent.yaml"), &yaml)
            .map_err(|err| ImportError::InvalidOutput(err.to_string()))?;
        Ok(yaml)
    }

    /// Render a human-readable import explanation for review.
    pub fn explain(&self) -> String {
        let mut output = String::new();
        output.push_str("Import explanation\n");
        output.push_str("==================\n\n");

        let mapped = self
            .explanations
            .iter()
            .filter(|entry| entry.disposition == ImportDisposition::Mapped)
            .collect::<Vec<_>>();
        let preserved = self
            .explanations
            .iter()
            .filter(|entry| entry.disposition == ImportDisposition::Preserved)
            .collect::<Vec<_>>();

        output.push_str("Mapped:\n");
        push_explanation_entries(&mut output, &mapped, false);
        output.push('\n');

        output.push_str("Unmapped:\n");
        push_explanation_entries(&mut output, &preserved, true);
        output.push('\n');

        output.push_str("Warnings:\n");
        if self.warnings.is_empty()
            && self
                .explanations
                .iter()
                .all(|entry| entry.warning.is_none())
        {
            output.push_str("  (none)\n");
        } else {
            for warning in &self.warnings {
                output.push_str(&format!("  - {warning}\n"));
            }
            let mut inline_warnings = BTreeSet::new();
            for entry in &self.explanations {
                if let Some(warning) = &entry.warning {
                    inline_warnings.insert(warning);
                }
            }
            for warning in inline_warnings {
                output.push_str(&format!("  - {warning}\n"));
            }
        }

        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportExplanation {
    pub disposition: ImportDisposition,
    pub source: String,
    pub target: String,
    pub confidence: u8,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDisposition {
    Mapped,
    Preserved,
}

/// Import a policy file. SELinux import also reads a sibling `.fc` file when one exists.
pub fn import_path(
    path: impl AsRef<Path>,
    format: ImportFormat,
) -> Result<ImportResult, ImportError> {
    let path = path.as_ref();
    let policy = fs::read_to_string(path).map_err(|source| ImportError::Read {
        path: path.display().to_string(),
        source,
    })?;

    match format {
        ImportFormat::Selinux => {
            let file_contexts = sibling_file_contexts(path)?;
            Ok(import_selinux(&policy, file_contexts.as_deref()))
        }
        ImportFormat::AppArmor => Ok(import_apparmor(&policy)),
    }
}

/// Import SELinux type-enforcement policy, optionally with file contexts.
pub fn import_selinux(policy: &str, file_contexts: Option<&str>) -> ImportResult {
    let module = parse_policy_module(policy).unwrap_or_else(|| "imported".to_string());
    let fc_entries = file_contexts.map(parse_file_contexts).unwrap_or_default();
    let type_paths = paths_by_type(&fc_entries);
    let exec_types = exec_types(policy);
    let domain_exec = domain_exec_pairs(policy);
    let primary_domain = choose_primary_domain(&module, &domain_exec);
    let primary_exec_type = domain_exec
        .iter()
        .find(|(domain, _)| domain == &primary_domain)
        .map(|(_, exec)| exec.clone())
        .or_else(|| exec_types.iter().next().cloned())
        .unwrap_or_else(|| format!("{module}_exec_t"));
    let executable = type_paths
        .get(&primary_exec_type)
        .and_then(|paths| paths.iter().next())
        .cloned()
        .unwrap_or_else(|| format!("/usr/bin/{module}"));

    let mut storage_by_type = BTreeMap::<String, (StorageKind, StorageAccess)>::new();
    let mut capabilities = BTreeSet::new();
    let mut has_http_network = false;
    let mut selinux = SelinuxPolicy::default();
    let mut process_by_domain = BTreeMap::<String, Process>::new();
    let mut extensions = Vec::new();
    let mut explanations = Vec::new();
    let mut consumed = 0usize;

    for fragment in selinux_fragments(policy) {
        let trimmed = fragment.body.trim();
        if trimmed.is_empty() || trimmed.starts_with("policy_module(") {
            continue;
        }

        if trimmed.contains("ifdef(") {
            selinux
                .compatibility
                .get_or_insert_with(|| "portable".to_string());
        }

        if let Some((domain, exec_type)) = parse_domain_macro(trimmed) {
            upsert_process(
                &mut process_by_domain,
                &domain,
                &exec_type,
                &type_paths,
                &module,
            );
            explanations.push(mapped_explanation(&fragment.raw, "processes", 95, None));
            consumed += 1;
            continue;
        }

        if should_skip_primary_declaration(trimmed, &primary_domain, &primary_exec_type) {
            explanations.push(mapped_explanation(
                &fragment.raw,
                "application domain bootstrap",
                99,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(type_name) = parse_type_declaration(trimmed) {
            if type_name.ends_with("_exec_t") {
                let domain = matching_domain_for_exec(&domain_exec, &type_name)
                    .unwrap_or_else(|| type_name.trim_end_matches("_exec_t").to_string() + "_t");
                upsert_process(
                    &mut process_by_domain,
                    &domain,
                    &type_name,
                    &type_paths,
                    &module,
                );
                explanations.push(mapped_explanation(&fragment.raw, "processes", 90, None));
            } else if type_name.ends_with("_t")
                && domain_exec.iter().any(|(domain, _)| domain == &type_name)
            {
                let exec_type = domain_exec
                    .iter()
                    .find(|(domain, _)| domain == &type_name)
                    .map(|(_, exec)| exec.clone())
                    .unwrap_or_else(|| format!("{}_exec_t", type_name.trim_end_matches("_t")));
                upsert_process(
                    &mut process_by_domain,
                    &type_name,
                    &exec_type,
                    &type_paths,
                    &module,
                );
                explanations.push(mapped_explanation(&fragment.raw, "processes", 90, None));
            } else {
                push_unique_type(
                    &mut selinux.types,
                    SelinuxType {
                        name: type_name,
                        kind: None,
                        optional: false,
                    },
                );
                explanations.push(mapped_explanation(&fragment.raw, "selinux.types", 90, None));
            }
            consumed += 1;
            continue;
        }

        if let Some((kind, type_name)) = parse_type_macro(trimmed) {
            if type_name == primary_exec_type || type_name == primary_domain {
                explanations.push(mapped_explanation(
                    &fragment.raw,
                    "application domain bootstrap",
                    90,
                    None,
                ));
            } else {
                push_unique_type(
                    &mut selinux.types,
                    SelinuxType {
                        name: type_name,
                        kind: Some(kind),
                        optional: trimmed.starts_with("ifdef(")
                            || trimmed.starts_with("optional {"),
                    },
                );
                explanations.push(mapped_explanation(&fragment.raw, "selinux.types", 86, None));
            }
            consumed += 1;
            continue;
        }

        if let Some((role, domain)) = parse_role(trimmed) {
            push_unique_role(
                &mut selinux.roles,
                SelinuxRole {
                    role: role.clone(),
                    domain: domain.clone(),
                    optional: false,
                },
            );
            if let Some(process) = process_by_domain.get_mut(&domain) {
                process.role = Some(role);
            }
            explanations.push(mapped_explanation(&fragment.raw, "selinux.roles", 94, None));
            consumed += 1;
            continue;
        }

        if let Some((source, exec_type, target)) = parse_type_transition(trimmed) {
            push_unique_transition(
                &mut selinux.transitions,
                SelinuxTransition {
                    source,
                    exec_type,
                    target,
                    optional: false,
                },
            );
            explanations.push(mapped_explanation(
                &fragment.raw,
                "selinux.transitions",
                95,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(domain) = parse_permissive(trimmed) {
            if !selinux.permissive.contains(&domain) {
                selinux.permissive.push(domain.clone());
            }
            if let Some(process) = process_by_domain.get_mut(&domain) {
                process.permissive = true;
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                "selinux.permissive",
                99,
                None,
            ));
            consumed += 1;
            continue;
        }

        if is_http_connect_macro(trimmed, &primary_domain) {
            has_http_network = true;
            explanations.push(mapped_explanation(
                &fragment.raw,
                "network.outbound:https",
                82,
                Some("SELinux HTTP port macro does not identify a destination; Intent inferred outbound internet HTTPS".to_string()),
            ));
            consumed += 1;
            continue;
        }

        if let Some((name, args)) = parse_macro_call(trimmed) {
            selinux.macro_calls.push(SelinuxMacroCall {
                name: name.clone(),
                args,
                optional: false,
                condition: None,
            });
            explanations.push(mapped_explanation(
                &fragment.raw,
                "selinux.macro_calls",
                82,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(mapped_block) = parse_structured_block(trimmed) {
            merge_structured_block(&mut selinux, mapped_block);
            explanations.push(mapped_explanation(
                &fragment.raw,
                "selinux structured policy",
                78,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(rule) = parse_allow(trimmed) {
            if rule.source == primary_domain {
                if rule.target == "self" && rule.class == "capability" {
                    let mapped_capabilities = rule
                        .permissions
                        .iter()
                        .map(|permission| permission.replace('_', "-"))
                        .collect::<Vec<_>>();
                    for permission in rule.permissions {
                        capabilities.insert(permission.replace('_', "-"));
                    }
                    explanations.push(mapped_explanation(
                        &fragment.raw,
                        &format!("capabilities: {}", mapped_capabilities.join(", ")),
                        97,
                        None,
                    ));
                    consumed += 1;
                    continue;
                }

                if let Some(kind) = storage_kind_for_type(&rule.target) {
                    if matches!(
                        rule.class.as_str(),
                        "dir" | "file" | "lnk_file" | "sock_file"
                    ) && should_infer_storage_type(&rule.target, &module, &type_paths)
                    {
                        let access = if permissions_write(&rule.permissions) {
                            StorageAccess::ReadWrite
                        } else {
                            StorageAccess::Read
                        };
                        let has_file_context = type_paths.contains_key(&rule.target);
                        let entry = storage_by_type
                            .entry(rule.target.clone())
                            .or_insert((kind, StorageAccess::Read));
                        if access == StorageAccess::ReadWrite {
                            entry.1 = StorageAccess::ReadWrite;
                        }
                        explanations.push(mapped_explanation(
                            &fragment.raw,
                            storage_concept(kind),
                            if has_file_context { 97 } else { 78 },
                            if has_file_context {
                                None
                            } else {
                                Some(format!(
                                    "SELinux type {} had no file-context path; Intent inferred a {} path from naming conventions",
                                    rule.target,
                                    storage_kind_name(kind)
                                ))
                            },
                        ));
                        consumed += 1;
                        continue;
                    }
                }
            }
            if rule.class == "filesystem" && rule.permissions.iter().any(|p| p == "associate") {
                selinux
                    .filesystem_associations
                    .push(SelinuxFilesystemAssociation {
                        type_name: rule.source,
                        filesystem_type: rule.target,
                        optional: false,
                    });
                explanations.push(mapped_explanation(
                    &fragment.raw,
                    "selinux.filesystem_associations",
                    92,
                    None,
                ));
                consumed += 1;
                continue;
            }

            push_unique_allow(
                &mut selinux.allows,
                SelinuxAllow {
                    source: rule.source,
                    target: rule.target,
                    class: rule.class,
                    permissions: rule.permissions,
                    optional: false,
                },
            );
            explanations.push(mapped_explanation(
                &fragment.raw,
                "selinux.allows",
                88,
                None,
            ));
            consumed += 1;
            continue;
        }

        explanations.push(preserved_explanation(
            &fragment.raw,
            "extensions.selinux.policy",
            Some("no native Intent concept currently represents this SELinux fragment".to_string()),
        ));
        extensions.push(fragment.raw);
    }

    let mut storage = Storage::default();
    for (type_name, (kind, access)) in storage_by_type {
        let paths = type_paths
            .get(&type_name)
            .cloned()
            .unwrap_or_else(|| vec![infer_path_from_type(&module, &type_name, kind)]);
        for path in paths {
            push_storage(&mut storage, kind, path, access);
        }
    }
    dedup_storage(&mut storage);

    let mut network = Network::default();
    if has_http_network {
        network.outbound.push(OutboundNetwork {
            to: "internet".to_string(),
            protocol: NetworkProtocol::Https,
            port: None,
            processes: Vec::new(),
        });
    }

    let policy_extensions = join_policy_extensions(extensions);
    let fc_extension = file_contexts
        .map(|contents| {
            contents
                .lines()
                .map(str::trim_end)
                .filter(|line| !line.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|contents| !contents.is_empty());

    for entry in fc_entries {
        if entry.type_name == primary_exec_type {
            continue;
        }
        if let Some(process) = process_by_domain
            .values_mut()
            .find(|process| process.exec_type.as_deref() == Some(entry.type_name.as_str()))
        {
            if process.executable != entry.path
                && !process.additional_executables.contains(&entry.path)
            {
                process.additional_executables.push(entry.path);
            }
        } else {
            selinux.file_contexts.push(SelinuxFileContext {
                path: entry.path,
                type_name: entry.type_name,
                file_type: None,
            });
        }
    }

    let mut warnings = Vec::new();
    if !policy_extensions.is_empty() {
        warnings.push(format!(
            "preserved {} SELinux policy fragment(s) under extensions.selinux.policy",
            policy_extensions.len()
        ));
    }
    if fc_extension.is_some() {
        explanations.push(mapped_explanation(
            "SELinux file contexts",
            "selinux.file_contexts",
            90,
            Some(
                "file contexts were parsed into structured SELinux entries where possible"
                    .to_string(),
            ),
        ));
    }
    if consumed == 0 {
        warnings.push("no high-confidence SELinux rules were mapped to native intent".to_string());
    }

    let document = IntentDocument {
        version: CURRENT_SCHEMA_VERSION,
        application: Application {
            name: module,
            description: Some("Imported from SELinux policy".to_string()),
            executable,
            user: None,
            group: None,
        },
        processes: sorted_processes(process_by_domain, &primary_domain),
        storage,
        network,
        ipc: Ipc::default(),
        capabilities: capabilities.into_iter().collect(),
        extensions: Extensions {
            selinux: SelinuxExtensions {
                policy: policy_extensions,
                file_contexts: Vec::new(),
                unknown: BTreeMap::new(),
            },
            apparmor: AppArmorExtensions::default(),
            unknown: BTreeMap::new(),
        },
        selinux,
        notes: vec![
            "Imported policy should be reviewed before replacing the source policy.".to_string(),
        ],
    };

    ImportResult {
        document,
        warnings,
        explanations,
    }
}

/// Import an AppArmor profile.
pub fn import_apparmor(profile: &str) -> ImportResult {
    let (name, executable) = parse_profile_header(profile)
        .unwrap_or_else(|| ("imported".to_string(), "/usr/bin/imported".to_string()));

    let mut storage = Storage::default();
    let mut network = Network::default();
    let mut ipc = Ipc::default();
    let mut capabilities = BTreeSet::new();
    let mut extensions = Vec::new();
    let mut explanations = Vec::new();
    let mut consumed_paths = BTreeSet::new();
    let mut consumed = 0usize;

    for fragment in apparmor_body_fragments(profile) {
        let line = fragment.body.trim();
        if line.is_empty()
            || line == "{"
            || line == "}"
            || line.starts_with("#include")
            || line.starts_with("profile ")
        {
            continue;
        }

        if let Some((path, access)) = parse_apparmor_path_rule(line) {
            if path == executable {
                explanations.push(mapped_explanation(
                    &fragment.raw,
                    "application.executable",
                    99,
                    None,
                ));
                consumed += 1;
                continue;
            }

            let base = trim_apparmor_glob(&path);
            let kind = kind_for_path(&base);
            let standard_path = is_standard_storage_path(&base);
            let base_for_warning = base.clone();
            if consumed_paths.insert(base.clone()) {
                push_storage(&mut storage, kind, base, access);
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                storage_concept(kind),
                if standard_path { 95 } else { 72 },
                if standard_path {
                    None
                } else {
                    Some(format!(
                        "AppArmor path {} is outside standard state/cache/runtime prefixes; Intent classified it as config storage",
                        base_for_warning
                    ))
                },
            ));
            consumed += 1;
            continue;
        }

        if line == "network inet stream," || line == "network inet6 stream," {
            if network.outbound.is_empty() {
                network.outbound.push(OutboundNetwork {
                    to: "network".to_string(),
                    protocol: NetworkProtocol::Https,
                    port: None,
                    processes: Vec::new(),
                });
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                "network.outbound:https",
                82,
                Some("AppArmor stream network rule is protocol-family scoped; Intent inferred outbound HTTPS without a destination".to_string()),
            ));
            consumed += 1;
            continue;
        }

        if let Some(socket) = parse_apparmor_unix_rule(line) {
            if !ipc.unix_sockets.contains(&socket) {
                ipc.unix_sockets.push(socket);
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                "ipc.unix_sockets",
                93,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(name) = parse_dbus_bind(line) {
            if !ipc.dbus.system.owns.contains(&name) {
                ipc.dbus.system.owns.push(name);
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                "ipc.dbus.system.owns",
                90,
                None,
            ));
            consumed += 1;
            continue;
        }

        if let Some(name) = parse_dbus_peer(line) {
            if !ipc.dbus.system.talks_to.contains(&name) {
                ipc.dbus.system.talks_to.push(name);
            }
            explanations.push(mapped_explanation(
                &fragment.raw,
                "ipc.dbus.system.talks_to",
                88,
                Some("AppArmor D-Bus send/receive direction is collapsed into Intent's talks_to concept".to_string()),
            ));
            consumed += 1;
            continue;
        }

        if let Some(capability) = line
            .strip_prefix("capability ")
            .and_then(|value| value.strip_suffix(','))
        {
            let capability = capability.trim().replace('_', "-");
            capabilities.insert(capability.clone());
            explanations.push(mapped_explanation(
                &fragment.raw,
                &format!("capabilities: {capability}"),
                97,
                None,
            ));
            consumed += 1;
            continue;
        }

        if !line.starts_with('}') {
            explanations.push(preserved_explanation(
                &fragment.raw,
                "extensions.apparmor.rules",
                Some(
                    "no native Intent concept currently represents this AppArmor rule".to_string(),
                ),
            ));
            extensions.push(fragment.raw);
        }
    }

    dedup_storage(&mut storage);
    ipc.unix_sockets.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(mode_key(left.mode).cmp(&mode_key(right.mode)))
    });
    ipc.dbus.system.owns.sort();
    ipc.dbus.system.talks_to.sort();

    let mut warnings = Vec::new();
    if !extensions.is_empty() {
        warnings.push(format!(
            "preserved {} AppArmor rule fragment(s) under extensions.apparmor.rules",
            extensions.len()
        ));
    }
    if consumed == 0 {
        warnings.push("no high-confidence AppArmor rules were mapped to native intent".to_string());
    }

    let document = IntentDocument {
        version: CURRENT_SCHEMA_VERSION,
        application: Application {
            name,
            description: Some("Imported from AppArmor profile".to_string()),
            executable,
            user: None,
            group: None,
        },
        processes: Vec::new(),
        storage,
        network,
        ipc,
        capabilities: capabilities.into_iter().collect(),
        extensions: Extensions {
            selinux: SelinuxExtensions::default(),
            apparmor: AppArmorExtensions {
                rules: extensions,
                unknown: BTreeMap::new(),
            },
            unknown: BTreeMap::new(),
        },
        selinux: SelinuxPolicy::default(),
        notes: vec![
            "Imported policy should be reviewed before replacing the source policy.".to_string(),
        ],
    };

    ImportResult {
        document,
        warnings,
        explanations,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDiff {
    pub format: ImportFormat,
    pub matched: Vec<String>,
    pub only_original: Vec<String>,
    pub only_regenerated: Vec<String>,
}

impl PolicyDiff {
    pub fn render(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Policy diff ({})\n", self.format.as_str()));
        output.push_str("====================\n\n");
        output.push_str(&format!("Matched statements: {}\n", self.matched.len()));
        let coverage = if self.matched.is_empty() && self.only_original.is_empty() {
            100
        } else {
            (self.matched.len() * 100) / (self.matched.len() + self.only_original.len())
        };
        output.push_str(&format!("Original coverage: {coverage}%\n"));
        output.push_str(&format!(
            "Regenerated extra statements: {}\n\n",
            self.only_regenerated.len()
        ));

        output.push_str("Only in original:\n");
        push_diff_entries(&mut output, &self.only_original);
        output.push('\n');
        output.push_str("Only in regenerated:\n");
        push_diff_entries(&mut output, &self.only_regenerated);
        output
    }
}

pub fn diff_policy_contents(original: &str, regenerated: &str, format: ImportFormat) -> PolicyDiff {
    let original = normalized_statements(original, format);
    let regenerated = normalized_statements(regenerated, format);
    let (matched, only_original, only_regenerated) = multiset_diff(original, regenerated);
    PolicyDiff {
        format,
        matched,
        only_original,
        only_regenerated,
    }
}

#[derive(Debug)]
pub enum ImportError {
    Read {
        path: String,
        source: std::io::Error,
    },
    Render(serde_yaml::Error),
    InvalidOutput(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "failed to read {path}: {source}"),
            Self::Render(source) => write!(f, "failed to render imported intent.yaml: {source}"),
            Self::InvalidOutput(source) => {
                write!(f, "importer produced invalid intent.yaml: {source}")
            }
        }
    }
}

impl std::error::Error for ImportError {}

#[derive(Debug, Clone)]
struct Fragment {
    raw: String,
    body: String,
}

#[derive(Debug, Clone)]
struct AllowRule {
    source: String,
    target: String,
    class: String,
    permissions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageKind {
    Config,
    Cache,
    State,
    Runtime,
}

#[derive(Debug, Clone)]
struct FileContextEntry {
    path: String,
    type_name: String,
}

fn sibling_file_contexts(path: &Path) -> Result<Option<String>, ImportError> {
    let mut fc_path = path.to_path_buf();
    fc_path.set_extension("fc");
    if !fc_path.exists() {
        return Ok(None);
    }
    fs::read_to_string(&fc_path)
        .map(Some)
        .map_err(|source| ImportError::Read {
            path: fc_path.display().to_string(),
            source,
        })
}

fn parse_policy_module(policy: &str) -> Option<String> {
    for line in policy.lines().map(str::trim) {
        if let Some(body) = line.strip_prefix("policy_module(") {
            let name = body.split(',').next()?.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn exec_types(policy: &str) -> BTreeSet<String> {
    policy
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("type "))
        .filter_map(|line| line.strip_suffix(';'))
        .map(str::trim)
        .filter(|name| name.ends_with("_exec_t"))
        .map(ToOwned::to_owned)
        .collect()
}

fn domain_exec_pairs(policy: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in policy.lines().map(str::trim) {
        for macro_name in [
            "init_daemon_domain(",
            "init_nnp_daemon_domain(",
            "domain_entry_file(",
        ] {
            if let Some(body) = line
                .strip_prefix(macro_name)
                .and_then(|body| body.strip_suffix(')'))
            {
                let args = body.split(',').map(str::trim).collect::<Vec<_>>();
                if args.len() >= 2 {
                    pairs.push((args[0].to_string(), args[1].to_string()));
                }
            }
        }

        if let Some(body) = line.strip_prefix("type_transition init_t ") {
            let parts = body.split_whitespace().collect::<Vec<_>>();
            if parts.len() >= 2 && parts[0].ends_with(":process") {
                pairs.push((
                    parts[1].trim_end_matches(';').to_string(),
                    parts[0].trim_end_matches(":process").to_string(),
                ));
            }
        }
    }
    pairs.sort();
    pairs.dedup();
    pairs
}

fn choose_primary_domain(module: &str, pairs: &[(String, String)]) -> String {
    let expected = format!("{module}_t");
    if pairs.iter().any(|(domain, _)| domain == &expected) {
        return expected;
    }
    pairs
        .first()
        .map(|(domain, _)| domain.clone())
        .unwrap_or(expected)
}

fn selinux_fragments(policy: &str) -> Vec<Fragment> {
    let mut fragments = Vec::new();
    let mut comments = Vec::<String>::new();
    let mut block = Vec::<String>::new();
    let mut block_depth = 0i32;
    let mut block_uses_parens = false;

    for line in policy.lines() {
        let trimmed = line.trim();
        if block_depth > 0 {
            block.push(line.to_string());
            block_depth += if block_uses_parens {
                paren_delta(trimmed)
            } else {
                brace_delta(trimmed)
            };
            if block_depth <= 0 {
                let raw = join_with_comments(&mut comments, &block.join("\n"));
                fragments.push(Fragment {
                    raw,
                    body: block.join("\n"),
                });
                block.clear();
            }
            continue;
        }

        if trimmed.is_empty() {
            comments.clear();
            continue;
        }
        if trimmed.starts_with('#') {
            comments.push(line.to_string());
            continue;
        }
        if trimmed.starts_with("ifdef(") {
            block.clear();
            block.push(line.to_string());
            block_uses_parens = true;
            block_depth = paren_delta(trimmed).max(1);
            if block_depth <= 0 {
                let raw = join_with_comments(&mut comments, &block.join("\n"));
                fragments.push(Fragment {
                    raw,
                    body: block.join("\n"),
                });
                block.clear();
            }
            continue;
        }
        if trimmed.starts_with("optional {") || trimmed.starts_with("require {") {
            block.clear();
            block.push(line.to_string());
            block_uses_parens = false;
            block_depth = brace_delta(trimmed).max(1);
            if block_depth <= 0 {
                let raw = join_with_comments(&mut comments, &block.join("\n"));
                fragments.push(Fragment {
                    raw,
                    body: block.join("\n"),
                });
                block.clear();
            }
            continue;
        }

        let raw = join_with_comments(&mut comments, line);
        fragments.push(Fragment {
            raw,
            body: line.to_string(),
        });
    }

    fragments
}

fn join_with_comments(comments: &mut Vec<String>, body: &str) -> String {
    if comments.is_empty() {
        body.to_string()
    } else {
        let mut raw = comments.join("\n");
        raw.push('\n');
        raw.push_str(body);
        comments.clear();
        raw
    }
}

fn brace_delta(line: &str) -> i32 {
    line.chars().filter(|ch| *ch == '{').count() as i32
        - line.chars().filter(|ch| *ch == '}').count() as i32
}

fn paren_delta(line: &str) -> i32 {
    line.chars().filter(|ch| *ch == '(').count() as i32
        - line.chars().filter(|ch| *ch == ')').count() as i32
}

fn parse_allow(line: &str) -> Option<AllowRule> {
    let body = line.strip_prefix("allow ")?.strip_suffix(';')?;
    let (left, permissions) = body.split_once(':')?;
    let mut left = left.split_whitespace();
    let source = left.next()?.to_string();
    let target = left.next()?.to_string();
    let (class, permissions) = permissions.split_once(' ')?;
    let permissions = permissions
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    Some(AllowRule {
        source,
        target,
        class: class.to_string(),
        permissions,
    })
}

fn should_skip_primary_declaration(line: &str, domain: &str, exec_type: &str) -> bool {
    line == format!("type {domain};")
        || line == format!("type {exec_type};")
        || line == format!("domain_type({domain})")
        || line == format!("files_type({exec_type})")
        || line == format!("domain_entry_file({domain}, {exec_type})")
        || line == format!("init_daemon_domain({domain}, {exec_type})")
        || line == format!("init_nnp_daemon_domain({domain}, {exec_type})")
}

fn parse_type_declaration(line: &str) -> Option<String> {
    line.strip_prefix("type ")
        .and_then(|body| body.strip_suffix(';'))
        .map(str::trim)
        .filter(|name| !name.contains(' '))
        .map(ToOwned::to_owned)
}

fn parse_domain_macro(line: &str) -> Option<(String, String)> {
    for macro_name in [
        "init_daemon_domain(",
        "init_nnp_daemon_domain(",
        "domain_entry_file(",
    ] {
        let Some(body) = line
            .strip_prefix(macro_name)
            .and_then(|body| body.strip_suffix(')'))
        else {
            continue;
        };
        let args = body.split(',').map(str::trim).collect::<Vec<_>>();
        if args.len() >= 2 {
            return Some((args[0].to_string(), args[1].to_string()));
        }
    }
    None
}

fn parse_type_macro(line: &str) -> Option<(String, String)> {
    for macro_name in [
        "files_type",
        "files_config_file",
        "files_pid_file",
        "domain_type",
        "domain_entry_file",
    ] {
        let prefix = format!("{macro_name}(");
        let Some(body) = line
            .strip_prefix(&prefix)
            .and_then(|body| body.strip_suffix(')'))
        else {
            continue;
        };
        let arg = body.split(',').next()?.trim();
        if !arg.is_empty() {
            return Some((macro_name.to_string(), arg.to_string()));
        }
    }

    if line.starts_with("ifdef(") {
        for macro_name in [
            "files_type",
            "files_config_file",
            "files_pid_file",
            "domain_type",
        ] {
            let needle = format!("{macro_name}(");
            let Some(start) = line.find(&needle) else {
                continue;
            };
            let rest = &line[start + needle.len()..];
            let Some(end) = rest.find(')') else {
                continue;
            };
            let arg = rest[..end].split(',').next()?.trim();
            if !arg.is_empty() {
                return Some((macro_name.to_string(), arg.to_string()));
            }
        }
    }
    None
}

fn parse_role(line: &str) -> Option<(String, String)> {
    let body = line.strip_prefix("role ")?.strip_suffix(';')?;
    let parts = body.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 3 && parts[1] == "types" {
        Some((parts[0].to_string(), parts[2].to_string()))
    } else {
        None
    }
}

fn parse_type_transition(line: &str) -> Option<(String, String, String)> {
    let body = line.strip_prefix("type_transition ")?.strip_suffix(';')?;
    let parts = body.split_whitespace().collect::<Vec<_>>();
    if parts.len() >= 3 && parts[1].ends_with(":process") {
        Some((
            parts[0].to_string(),
            parts[1].trim_end_matches(":process").to_string(),
            parts[2].to_string(),
        ))
    } else {
        None
    }
}

fn parse_permissive(line: &str) -> Option<String> {
    line.strip_prefix("permissive ")
        .and_then(|body| body.strip_suffix(';'))
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_macro_call(line: &str) -> Option<(String, Vec<String>)> {
    if line.contains('\n')
        || line.starts_with("allow ")
        || line.starts_with("type ")
        || line.starts_with("role ")
        || line.starts_with("ifdef(")
        || line.starts_with("optional ")
        || line.starts_with("require ")
    {
        return None;
    }
    let (name, rest) = line.split_once('(')?;
    let args = rest.strip_suffix(')')?;
    if name.trim().is_empty() {
        return None;
    }
    Some((
        name.trim().to_string(),
        args.split(',')
            .map(str::trim)
            .filter(|arg| !arg.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    ))
}

#[derive(Default)]
struct StructuredBlock {
    allows: Vec<SelinuxAllow>,
    transitions: Vec<SelinuxTransition>,
    roles: Vec<SelinuxRole>,
    macro_calls: Vec<SelinuxMacroCall>,
    filesystem_associations: Vec<SelinuxFilesystemAssociation>,
    permissive: Vec<String>,
}

fn parse_structured_block(block: &str) -> Option<StructuredBlock> {
    if !(block.starts_with("optional {")
        || block.starts_with("require {")
        || block.starts_with("ifdef("))
    {
        return None;
    }

    let optional = block.starts_with("optional {");
    let condition = block_ifdef_condition(block);
    let mut mapped = StructuredBlock::default();

    for line in block.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with('#')
            || line == "optional {"
            || line == "require {"
            || line == "}"
            || line.starts_with("type ")
            || line.starts_with("class ")
            || line.starts_with("attribute ")
            || line == "')"
        {
            continue;
        }

        if let Some(rule) = parse_allow(line) {
            if rule.class == "filesystem" && rule.permissions.iter().any(|p| p == "associate") {
                mapped
                    .filesystem_associations
                    .push(SelinuxFilesystemAssociation {
                        type_name: rule.source,
                        filesystem_type: rule.target,
                        optional,
                    });
            } else {
                mapped.allows.push(SelinuxAllow {
                    source: rule.source,
                    target: rule.target,
                    class: rule.class,
                    permissions: rule.permissions,
                    optional,
                });
            }
            continue;
        }

        if let Some((source, exec_type, target)) = parse_type_transition(line) {
            mapped.transitions.push(SelinuxTransition {
                source,
                exec_type,
                target,
                optional,
            });
            continue;
        }

        if let Some((role, domain)) = parse_role(line) {
            mapped.roles.push(SelinuxRole {
                role,
                domain,
                optional,
            });
            continue;
        }

        if let Some(domain) = parse_permissive(line) {
            mapped.permissive.push(domain);
            continue;
        }

        if let Some((name, args)) = parse_macro_call(line) {
            mapped.macro_calls.push(SelinuxMacroCall {
                name,
                args,
                optional,
                condition: condition.clone(),
            });
        }
    }

    if mapped.allows.is_empty()
        && mapped.transitions.is_empty()
        && mapped.roles.is_empty()
        && mapped.macro_calls.is_empty()
        && mapped.filesystem_associations.is_empty()
        && mapped.permissive.is_empty()
    {
        None
    } else {
        Some(mapped)
    }
}

fn merge_structured_block(selinux: &mut SelinuxPolicy, block: StructuredBlock) {
    for allow in block.allows {
        push_unique_allow(&mut selinux.allows, allow);
    }
    for transition in block.transitions {
        push_unique_transition(&mut selinux.transitions, transition);
    }
    for role in block.roles {
        push_unique_role(&mut selinux.roles, role);
    }
    for macro_call in block.macro_calls {
        selinux.macro_calls.push(macro_call);
    }
    for association in block.filesystem_associations {
        selinux.filesystem_associations.push(association);
    }
    for domain in block.permissive {
        if !selinux.permissive.contains(&domain) {
            selinux.permissive.push(domain);
        }
    }
}

fn block_ifdef_condition(block: &str) -> Option<String> {
    let first = block.lines().next()?.trim();
    let body = first.strip_prefix("ifdef(`")?;
    let condition = body.split('\'').next()?.trim();
    if condition.is_empty() {
        None
    } else {
        Some(condition.to_string())
    }
}

fn matching_domain_for_exec(pairs: &[(String, String)], exec_type: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(_, exec)| exec == exec_type)
        .map(|(domain, _)| domain.clone())
}

fn upsert_process(
    processes: &mut BTreeMap<String, Process>,
    domain: &str,
    exec_type: &str,
    type_paths: &BTreeMap<String, Vec<String>>,
    module: &str,
) {
    let id = process_id_from_domain(domain, module);
    let executable = type_paths
        .get(exec_type)
        .and_then(|paths| paths.iter().next())
        .cloned()
        .unwrap_or_else(|| format!("/usr/bin/{}", id.replace('-', "_")));

    processes.entry(domain.to_string()).or_insert(Process {
        id,
        name: domain.trim_end_matches("_t").replace('_', "-"),
        executable,
        additional_executables: Vec::new(),
        domain_type: Some(domain.to_string()),
        exec_type: Some(exec_type.to_string()),
        role: None,
        started_by: Some("init_t".to_string()),
        use_nnp_transition: false,
        permissive: false,
    });
}

fn process_id_from_domain(domain: &str, module: &str) -> String {
    let name = domain.trim_end_matches("_t");
    if name == module {
        "primary".to_string()
    } else {
        name.replace('_', "-")
    }
}

fn sorted_processes(processes: BTreeMap<String, Process>, primary_domain: &str) -> Vec<Process> {
    processes
        .into_iter()
        .filter(|(domain, _)| domain != primary_domain)
        .map(|(_, process)| process)
        .collect()
}

fn push_unique_type(types: &mut Vec<SelinuxType>, entry: SelinuxType) {
    if !types
        .iter()
        .any(|existing| existing.name == entry.name && existing.kind == entry.kind)
    {
        types.push(entry);
    }
}

fn push_unique_role(roles: &mut Vec<SelinuxRole>, entry: SelinuxRole) {
    if !roles
        .iter()
        .any(|existing| existing.role == entry.role && existing.domain == entry.domain)
    {
        roles.push(entry);
    }
}

fn push_unique_transition(transitions: &mut Vec<SelinuxTransition>, entry: SelinuxTransition) {
    if !transitions.iter().any(|existing| {
        existing.source == entry.source
            && existing.exec_type == entry.exec_type
            && existing.target == entry.target
    }) {
        transitions.push(entry);
    }
}

fn push_unique_allow(allows: &mut Vec<SelinuxAllow>, entry: SelinuxAllow) {
    if !allows.iter().any(|existing| {
        existing.source == entry.source
            && existing.target == entry.target
            && existing.class == entry.class
            && existing.permissions == entry.permissions
    }) {
        allows.push(entry);
    }
}

fn is_http_connect_macro(line: &str, domain: &str) -> bool {
    line == format!("corenet_tcp_connect_http_port({domain})")
        || (line.contains("corenet_tcp_connect_http_port") && line.contains(domain))
}

fn parse_file_contexts(contents: &str) -> Vec<FileContextEntry> {
    let mut entries = Vec::new();
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(type_start) = line.find("object_r:") else {
            continue;
        };
        let type_name = line[type_start + "object_r:".len()..]
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let path = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if !path.is_empty() && !type_name.is_empty() {
            entries.push(FileContextEntry {
                path: clean_file_context_path(&path),
                type_name,
            });
        }
    }
    entries
}

fn clean_file_context_path(path: &str) -> String {
    path.trim_end_matches("(/.*)?")
        .replace("\\ ", " ")
        .replace("\\.", ".")
}

fn paths_by_type(entries: &[FileContextEntry]) -> BTreeMap<String, Vec<String>> {
    let mut paths = BTreeMap::<String, Vec<String>>::new();
    for entry in entries {
        paths
            .entry(entry.type_name.clone())
            .or_default()
            .push(entry.path.clone());
    }
    for paths in paths.values_mut() {
        paths.sort();
        paths.dedup();
    }
    paths
}

fn storage_kind_for_type(type_name: &str) -> Option<StorageKind> {
    if type_name.contains("var_run") || type_name.contains("_run_") || type_name.ends_with("_run_t")
    {
        Some(StorageKind::Runtime)
    } else if type_name.contains("var_cache") || type_name.contains("cache") {
        Some(StorageKind::Cache)
    } else if type_name.contains("var_lib") || type_name.contains("state") {
        Some(StorageKind::State)
    } else if type_name.contains("etc") || type_name.contains("config") {
        Some(StorageKind::Config)
    } else {
        None
    }
}

fn should_infer_storage_type(
    type_name: &str,
    module: &str,
    type_paths: &BTreeMap<String, Vec<String>>,
) -> bool {
    if type_paths.contains_key(type_name) {
        return true;
    }

    let stem = module.trim_end_matches('d');
    type_name.contains(module)
        || type_name.contains(stem)
        || matches!(type_name, "var_cache_t" | "var_lib_t" | "var_run_t")
}

fn permissions_write(permissions: &[String]) -> bool {
    permissions.iter().any(|permission| {
        matches!(
            permission.as_str(),
            "write"
                | "append"
                | "create"
                | "add_name"
                | "remove_name"
                | "setattr"
                | "unlink"
                | "rename"
                | "rmdir"
                | "lock"
                | "relabelto"
                | "relabelfrom"
        )
    })
}

fn infer_path_from_type(module: &str, type_name: &str, kind: StorageKind) -> String {
    let app = module.trim_end_matches('d');
    if type_name.contains("nss") {
        "/var/cache/nss-himmelblau".to_string()
    } else {
        match kind {
            StorageKind::Config => format!("/etc/{app}"),
            StorageKind::Cache => format!("/var/cache/{module}"),
            StorageKind::State => format!("/var/lib/{module}"),
            StorageKind::Runtime => format!("/run/{module}"),
        }
    }
}

fn push_storage(storage: &mut Storage, kind: StorageKind, path: String, access: StorageAccess) {
    let entry = StoragePath {
        path,
        access,
        processes: Vec::new(),
        selinux_type: None,
        justification: None,
    };
    match kind {
        StorageKind::Config => storage.config.push(entry),
        StorageKind::Cache => storage.cache.push(entry),
        StorageKind::State => storage.state.push(entry),
        StorageKind::Runtime => storage.runtime.push(entry),
    }
}

fn dedup_storage(storage: &mut Storage) {
    dedup_storage_vec(&mut storage.config);
    dedup_storage_vec(&mut storage.cache);
    dedup_storage_vec(&mut storage.state);
    dedup_storage_vec(&mut storage.runtime);
}

fn dedup_storage_vec(paths: &mut Vec<StoragePath>) {
    paths.sort_by(|left, right| left.path.cmp(&right.path));
    paths.dedup_by(|left, right| left.path == right.path && left.access == right.access);
}

fn join_policy_extensions(fragments: Vec<String>) -> Vec<String> {
    fragments
        .into_iter()
        .map(|fragment| fragment.trim().to_string())
        .filter(|fragment| !fragment.is_empty())
        .collect()
}

fn parse_profile_header(profile: &str) -> Option<(String, String)> {
    for line in profile.lines().map(str::trim) {
        if let Some(body) = line.strip_prefix("profile ") {
            let body = body.strip_suffix('{').unwrap_or(body).trim();
            let mut parts = body.split_whitespace();
            let name = parts.next()?.to_string();
            let executable = unquote(parts.next()?).to_string();
            return Some((name, executable));
        }
    }
    None
}

fn apparmor_body_fragments(profile: &str) -> Vec<Fragment> {
    profile
        .lines()
        .map(|line| Fragment {
            raw: line.trim().to_string(),
            body: line.trim().to_string(),
        })
        .collect()
}

fn parse_apparmor_path_rule(line: &str) -> Option<(String, StorageAccess)> {
    if !line.starts_with('/') && !line.starts_with('"') {
        return None;
    }
    let line = line.strip_suffix(',')?;
    let (path, permissions) = split_apparmor_rule(line)?;
    let access = if permissions.contains('w')
        || permissions.contains('k')
        || permissions.contains('a')
        || permissions.contains('l')
    {
        StorageAccess::ReadWrite
    } else {
        StorageAccess::Read
    };
    Some((unquote(path).to_string(), access))
}

fn split_apparmor_rule(line: &str) -> Option<(&str, &str)> {
    if let Some(stripped) = line.strip_prefix('"') {
        let end = stripped.find('"')?;
        let path = &line[..end + 2];
        let permissions = line[end + 2..].trim();
        Some((path, permissions))
    } else {
        let mut parts = line.split_whitespace();
        Some((parts.next()?, parts.next()?))
    }
}

fn trim_apparmor_glob(path: &str) -> String {
    path.trim_end_matches("/**")
        .trim_end_matches('/')
        .to_string()
}

fn kind_for_path(path: &str) -> StorageKind {
    if path.starts_with("/run/") || path.starts_with("/var/run/") {
        StorageKind::Runtime
    } else if path.starts_with("/var/cache/") {
        StorageKind::Cache
    } else if path.starts_with("/var/lib/") {
        StorageKind::State
    } else {
        StorageKind::Config
    }
}

fn parse_apparmor_unix_rule(line: &str) -> Option<UnixSocket> {
    if !line.starts_with("unix ") {
        return None;
    }
    if line.contains("bind") || line.contains("listen") || line.contains("create") {
        let path = extract_after(line, "addr=")?;
        return Some(UnixSocket {
            path,
            mode: UnixSocketMode::Server,
            processes: Vec::new(),
        });
    }
    if line.contains("peer=(addr=") {
        let path = extract_after(line, "peer=(addr=")?;
        return Some(UnixSocket {
            path,
            mode: UnixSocketMode::Client,
            processes: Vec::new(),
        });
    }
    None
}

fn parse_dbus_bind(line: &str) -> Option<String> {
    if line.starts_with("dbus bind ") && line.contains("bus=system") {
        return extract_after(line, "name=");
    }
    None
}

fn parse_dbus_peer(line: &str) -> Option<String> {
    if (line.starts_with("dbus send ") || line.starts_with("dbus receive "))
        && line.contains("bus=system")
    {
        return extract_after(line, "peer=(name=");
    }
    None
}

fn extract_after(line: &str, marker: &str) -> Option<String> {
    let value = line.split(marker).nth(1)?.trim();
    let value = value.trim_end_matches(',').trim_end_matches(')').trim();
    Some(unquote(value).to_string())
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"')
}

fn mode_key(mode: UnixSocketMode) -> u8 {
    match mode {
        UnixSocketMode::Server => 0,
        UnixSocketMode::Client => 1,
    }
}

fn mapped_explanation(
    source: &str,
    target: &str,
    confidence: u8,
    warning: Option<String>,
) -> ImportExplanation {
    ImportExplanation {
        disposition: ImportDisposition::Mapped,
        source: source.trim().to_string(),
        target: target.to_string(),
        confidence,
        warning,
    }
}

fn preserved_explanation(source: &str, target: &str, warning: Option<String>) -> ImportExplanation {
    ImportExplanation {
        disposition: ImportDisposition::Preserved,
        source: source.trim().to_string(),
        target: target.to_string(),
        confidence: 100,
        warning,
    }
}

fn push_explanation_entries(output: &mut String, entries: &[&ImportExplanation], preserved: bool) {
    if entries.is_empty() {
        output.push_str("  (none)\n");
        return;
    }

    for entry in entries {
        for line in entry.source.lines() {
            output.push_str(&format!("  {line}\n"));
        }
        if preserved {
            output.push_str(&format!("    -> stored in {}\n", entry.target));
        } else {
            output.push_str(&format!("    -> {}\n", entry.target));
        }
        output.push_str(&format!("    confidence: {}%\n", entry.confidence));
        if let Some(warning) = &entry.warning {
            output.push_str(&format!("    warning: {warning}\n"));
        }
    }
}

fn storage_concept(kind: StorageKind) -> &'static str {
    match kind {
        StorageKind::Config => "storage.config",
        StorageKind::Cache => "storage.cache",
        StorageKind::State => "storage.state",
        StorageKind::Runtime => "storage.runtime",
    }
}

fn storage_kind_name(kind: StorageKind) -> &'static str {
    match kind {
        StorageKind::Config => "config",
        StorageKind::Cache => "cache",
        StorageKind::State => "state",
        StorageKind::Runtime => "runtime",
    }
}

fn is_standard_storage_path(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.starts_with("/var/cache/")
        || path.starts_with("/var/lib/")
        || path.starts_with("/run/")
        || path.starts_with("/var/run/")
}

fn normalized_statements(policy: &str, format: ImportFormat) -> Vec<String> {
    match format {
        ImportFormat::Selinux => selinux_fragments(policy)
            .into_iter()
            .filter_map(|fragment| normalize_statement(&fragment.body, true))
            .collect(),
        ImportFormat::AppArmor => apparmor_body_fragments(policy)
            .into_iter()
            .filter_map(|fragment| normalize_statement(&fragment.body, false))
            .collect(),
    }
}

fn normalize_statement(statement: &str, selinux: bool) -> Option<String> {
    let lines = statement
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && *line != "{"
                && *line != "}"
                && if selinux {
                    !line.starts_with('#')
                } else {
                    !line.starts_with('#') || line.starts_with("#include")
                }
        })
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>();

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn multiset_diff(
    original: Vec<String>,
    regenerated: Vec<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut original_counts = counted_statements(original);
    let mut regenerated_counts = counted_statements(regenerated);
    let keys = original_counts
        .keys()
        .chain(regenerated_counts.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut matched = Vec::new();
    let mut only_original = Vec::new();
    let mut only_regenerated = Vec::new();

    for key in keys {
        let original_count = original_counts.remove(&key).unwrap_or(0);
        let regenerated_count = regenerated_counts.remove(&key).unwrap_or(0);
        for _ in 0..original_count.min(regenerated_count) {
            matched.push(key.clone());
        }
        for _ in 0..original_count.saturating_sub(regenerated_count) {
            only_original.push(key.clone());
        }
        for _ in 0..regenerated_count.saturating_sub(original_count) {
            only_regenerated.push(key.clone());
        }
    }

    (matched, only_original, only_regenerated)
}

fn counted_statements(statements: Vec<String>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for statement in statements {
        *counts.entry(statement).or_insert(0) += 1;
    }
    counts
}

fn push_diff_entries(output: &mut String, entries: &[String]) {
    if entries.is_empty() {
        output.push_str("  (none)\n");
        return;
    }

    for entry in entries {
        for line in entry.lines() {
            output.push_str(&format!("  {line}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selinux_import_maps_storage_and_preserves_raw_policy() {
        let result = import_selinux(
            r#"
policy_module(himmelblaud, 1.0)
type himmelblaud_t;
type himmelblaud_exec_t;
allow himmelblaud_t var_cache_t:file { read write create };
allow himmelblaud_t self:capability sys_ptrace;
"#,
            None,
        );

        assert_eq!(
            result.document.storage.cache[0].path,
            "/var/cache/himmelblaud"
        );
        assert_eq!(
            result.document.storage.cache[0].access,
            StorageAccess::ReadWrite
        );
        assert!(result
            .document
            .capabilities
            .contains(&"sys-ptrace".to_string()));
    }

    #[test]
    fn apparmor_import_maps_common_profile_body_rules() {
        let result = import_apparmor(
            r#"
#include <tunables/global>
profile demo /usr/bin/demo {
  /etc/demo r,
  /var/cache/demo/** rwk,
  network inet stream,
  unix (create, bind, listen) type=stream addr="/run/demo/socket",
  dbus bind bus=system name="org.example.Demo",
  capability net_bind_service,
}
"#,
        );

        assert_eq!(result.document.application.name, "demo");
        assert_eq!(result.document.storage.config[0].path, "/etc/demo");
        assert_eq!(result.document.storage.cache[0].path, "/var/cache/demo");
        assert_eq!(
            result.document.ipc.unix_sockets[0].mode,
            UnixSocketMode::Server
        );
        assert!(result
            .document
            .capabilities
            .contains(&"net-bind-service".to_string()));
    }
}
