//! Reverse compilation from backend policy into high-level intent.yaml.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::config::IntentConfig;
use crate::schema::{
    AppArmorExtensions, Application, Extensions, IntentDocument, Ipc, Network, NetworkProtocol,
    OutboundNetwork, SelinuxExtensions, Storage, StorageAccess, StoragePath, UnixSocket,
    UnixSocketMode, CURRENT_SCHEMA_VERSION,
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

/// Result of importing backend policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub document: IntentDocument,
    pub warnings: Vec<String>,
}

impl ImportResult {
    /// Render a validated `intent.yaml` document.
    pub fn to_yaml(&self) -> Result<String, ImportError> {
        let yaml = serde_yaml::to_string(&self.document).map_err(ImportError::Render)?;
        IntentConfig::from_yaml(std::path::PathBuf::from("imported.intent.yaml"), &yaml)
            .map_err(|err| ImportError::InvalidOutput(err.to_string()))?;
        Ok(yaml)
    }
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
    let mut extensions = Vec::new();
    let mut consumed = 0usize;

    for fragment in selinux_fragments(policy) {
        let trimmed = fragment.body.trim();
        if trimmed.is_empty() || trimmed.starts_with("policy_module(") {
            continue;
        }

        if should_skip_primary_declaration(trimmed, &primary_domain, &primary_exec_type) {
            consumed += 1;
            continue;
        }

        if let Some(rule) = parse_allow(trimmed) {
            if rule.source == primary_domain {
                if rule.target == "self" && rule.class == "capability" {
                    for permission in rule.permissions {
                        capabilities.insert(permission.replace('_', "-"));
                    }
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
                        let entry = storage_by_type
                            .entry(rule.target)
                            .or_insert((kind, StorageAccess::Read));
                        if access == StorageAccess::ReadWrite {
                            entry.1 = StorageAccess::ReadWrite;
                        }
                        consumed += 1;
                        continue;
                    }
                }
            }
        } else if is_http_connect_macro(trimmed, &primary_domain) {
            has_http_network = true;
            consumed += 1;
            continue;
        }

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

    let mut warnings = Vec::new();
    if !policy_extensions.is_empty() {
        warnings.push(format!(
            "preserved {} SELinux policy fragment(s) under extensions.selinux.policy",
            policy_extensions.len()
        ));
    }
    if fc_extension.is_some() {
        warnings.push(
            "preserved SELinux file contexts under extensions.selinux.file_contexts".to_string(),
        );
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
        storage,
        network,
        ipc: Ipc::default(),
        capabilities: capabilities.into_iter().collect(),
        extensions: Extensions {
            selinux: SelinuxExtensions {
                policy: policy_extensions,
                file_contexts: fc_extension.into_iter().collect(),
                unknown: BTreeMap::new(),
            },
            apparmor: AppArmorExtensions::default(),
            unknown: BTreeMap::new(),
        },
        notes: vec![
            "Imported policy should be reviewed before replacing the source policy.".to_string(),
        ],
    };

    ImportResult { document, warnings }
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
                consumed += 1;
                continue;
            }

            let base = trim_apparmor_glob(&path);
            if consumed_paths.insert(base.clone()) {
                push_storage(&mut storage, kind_for_path(&base), base, access);
            }
            consumed += 1;
            continue;
        }

        if line == "network inet stream," || line == "network inet6 stream," {
            if network.outbound.is_empty() {
                network.outbound.push(OutboundNetwork {
                    to: "network".to_string(),
                    protocol: NetworkProtocol::Https,
                    port: None,
                });
            }
            consumed += 1;
            continue;
        }

        if let Some(socket) = parse_apparmor_unix_rule(line) {
            if !ipc.unix_sockets.contains(&socket) {
                ipc.unix_sockets.push(socket);
            }
            consumed += 1;
            continue;
        }

        if let Some(name) = parse_dbus_bind(line) {
            if !ipc.dbus.system.owns.contains(&name) {
                ipc.dbus.system.owns.push(name);
            }
            consumed += 1;
            continue;
        }

        if let Some(name) = parse_dbus_peer(line) {
            if !ipc.dbus.system.talks_to.contains(&name) {
                ipc.dbus.system.talks_to.push(name);
            }
            consumed += 1;
            continue;
        }

        if let Some(capability) = line
            .strip_prefix("capability ")
            .and_then(|value| value.strip_suffix(','))
        {
            capabilities.insert(capability.trim().replace('_', "-"));
            consumed += 1;
            continue;
        }

        if !line.starts_with('}') {
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
        notes: vec![
            "Imported policy should be reviewed before replacing the source policy.".to_string(),
        ],
    };

    ImportResult { document, warnings }
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
        });
    }
    if line.contains("peer=(addr=") {
        let path = extract_after(line, "peer=(addr=")?;
        return Some(UnixSocket {
            path,
            mode: UnixSocketMode::Client,
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
