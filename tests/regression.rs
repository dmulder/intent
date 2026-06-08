use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use intent::audit::{apparmor as apparmor_audit, selinux as selinux_audit};
use intent::compiler::{apparmor, selinux};
use intent::config::{ConfigError, IntentConfig};
use intent::diagnostics::Diagnostic;
use intent::ir::{NetworkProtocolNeed, PathAccess, PathPurpose};
use intent::schema::{IntentDocument, NetworkProtocol, StorageAccess};

fn assert_snapshot(name: &str, actual: &str) {
    let path = Path::new("tests/snapshots").join(name);

    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::write(&path, actual)
            .unwrap_or_else(|error| panic!("failed to update {}: {error}", path.display()));
    }

    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    assert_eq!(actual, expected, "snapshot changed: {}", path.display());
}

fn regression_config() -> IntentConfig {
    IntentConfig::from_path("tests/fixtures/regression.intent.yaml")
        .expect("regression fixture should load")
}

fn render_diagnostics(diagnostics: &[Diagnostic]) -> String {
    let mut output = diagnostics
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n\n");
    output.push('\n');
    output
}

#[test]
fn yaml_parsing_accepts_supported_schema_surfaces() {
    let document =
        serde_yaml::from_str::<IntentDocument>(include_str!("fixtures/regression.intent.yaml"))
            .expect("fixture should parse as an IntentDocument");

    assert_eq!(document.version, 1);
    assert_eq!(document.application.name, "regression-service");
    assert_eq!(document.storage.config[0].access, StorageAccess::Read);
    assert_eq!(document.storage.cache[0].access, StorageAccess::ReadWrite);
    assert_eq!(
        document.network.outbound[0].protocol,
        NetworkProtocol::Https
    );
    assert_eq!(document.network.outbound[1].port, Some(8443));
    assert_eq!(document.ipc.dbus.system.owns[0], "org.example.Regression");
    assert_eq!(document.capabilities, ["net-bind-service", "dac-override"]);
}

#[test]
fn validation_diagnostics_match_snapshot() {
    let error = IntentConfig::from_yaml(
        PathBuf::from("invalid.intent.yaml"),
        r#"
version: 2
application:
  name: ""
  executable: usr/bin/demo
storage:
  config: []
  cache:
    - path: relative/cache
      access: read-write
  state:
    - path: /tmp/demo-state
      access: read-write
  runtime:
    - path: /var/lib/demo-runtime
      access: read-write
network:
  outbound:
    - to: ""
      protocol: tcp
ipc:
  unix_sockets:
    - path: run/demo.sock
      mode: server
  dbus:
    system:
      talks_to:
        - not-a-well-known-name
capabilities:
  - NET_ADMIN
notes:
  - ""
"#,
    )
    .expect_err("invalid fixture should fail validation");

    let ConfigError::Validation { source, .. } = error else {
        panic!("expected validation error, got {error}");
    };

    assert_snapshot(
        "validation-diagnostics.txt",
        &render_diagnostics(&source.diagnostics),
    );
}

#[test]
fn ir_normalization_matches_snapshot() {
    let config = regression_config();
    let ir = &config.ir;

    assert_eq!(ir.read_only_paths.len(), 1);
    assert_eq!(ir.read_only_paths[0].path, "/etc/regression-service");
    assert_eq!(ir.read_only_paths[0].purpose, PathPurpose::Config);
    assert_eq!(ir.read_only_paths[0].access, PathAccess::Read);
    assert_eq!(ir.outbound_network[0].protocol, NetworkProtocolNeed::Https);
    assert_eq!(ir.outbound_network[0].port, 443);
    assert_eq!(ir.capabilities[0].linux_name, "dac_override");

    assert_snapshot("regression.ir.txt", &ir.explain());
}

#[test]
fn apparmor_generated_output_matches_snapshot() {
    let config = regression_config();

    assert_snapshot("regression.apparmor", &apparmor::compile(&config.ir));
}

#[test]
fn selinux_generated_output_matches_snapshots() {
    let config = regression_config();

    assert_snapshot("regression.te", &selinux::compile(&config.ir));
    assert_snapshot("regression.fc", &selinux::file_contexts(&config.ir));
}

#[test]
fn manual_policy_extensions_round_trip_and_compile_into_backend_sections() {
    let config = IntentConfig::from_yaml(
        PathBuf::from("escape.intent.yaml"),
        r#"
version: 1

application:
  name: mydaemon
  executable: /usr/bin/mydaemon

extensions:
  selinux:
    policy:
      - |
        allow mydaemon_t self:capability sys_ptrace;
  apparmor:
    rules:
      - |
        capability sys_ptrace,
"#,
    )
    .expect("manual extensions should load");

    let rendered =
        serde_yaml::to_string(&config.document).expect("intent document should serialize");
    let reparsed =
        serde_yaml::from_str::<IntentDocument>(&rendered).expect("serialized document should load");
    assert_eq!(
        reparsed.extensions.selinux.policy[0].trim(),
        "allow mydaemon_t self:capability sys_ptrace;"
    );
    assert_eq!(
        reparsed.extensions.apparmor.rules[0].trim(),
        "capability sys_ptrace,"
    );

    let selinux_output = selinux::compile(&config.ir);
    assert!(selinux_output.contains("# Manual SELinux Policy Extensions"));
    assert!(selinux_output.contains("# extensions.selinux.policy[0]: manual policy."));
    assert!(selinux_output.contains("allow mydaemon_t self:capability sys_ptrace;"));

    let apparmor_output = apparmor::compile(&config.ir);
    assert!(apparmor_output.contains("  # Manual AppArmor rule extensions."));
    assert!(apparmor_output.contains("  # extensions.apparmor.rules[0]: manual policy."));
    assert!(apparmor_output.contains("  capability sys_ptrace,"));

    let manual_offset = apparmor_output
        .find("Manual AppArmor rule extensions")
        .expect("manual AppArmor section should be present");
    let closing_offset = apparmor_output
        .rfind("\n}")
        .expect("profile closing brace should be present");
    assert!(manual_offset < closing_offset);
}

#[test]
fn manual_policy_extensions_are_syntax_checked_when_possible() {
    let error = IntentConfig::from_yaml(
        PathBuf::from("invalid-escape.intent.yaml"),
        r#"
version: 1

application:
  name: mydaemon
  executable: /usr/bin/mydaemon

extensions:
  selinux:
    policy:
      - allow mydaemon_t self:capability sys_ptrace
  apparmor:
    rules:
      - capability sys_ptrace
"#,
    )
    .expect_err("invalid manual fragments should fail validation");

    let ConfigError::Validation { source, .. } = error else {
        panic!("expected validation error, got {error}");
    };
    let message = source.to_string();
    assert!(message.contains("extensions.selinux.policy[0] must contain complete SELinux"));
    assert!(message.contains("extensions.apparmor.rules[0] must contain complete AppArmor"));
}

#[test]
fn unknown_extension_blocks_warn_but_are_preserved() {
    let document = serde_yaml::from_str::<IntentDocument>(
        r#"
version: 1

application:
  name: demo
  executable: /usr/bin/demo

extensions:
  selinux:
    module_options:
      custom: true
  bpf:
    programs:
      - demo-filter
"#,
    )
    .expect("unknown extension blocks should parse");

    let report = document
        .validate_with_options(Default::default())
        .expect("unknown extensions should be warnings by default");
    let message = render_diagnostics(&report.diagnostics);
    assert!(message.contains("warning: extensions.bpf is not recognized"));
    assert!(message.contains("warning: extensions.selinux.module_options is not recognized"));

    let rendered = serde_yaml::to_string(&document).expect("document should serialize");
    assert!(rendered.contains("bpf:"));
    assert!(rendered.contains("module_options:"));
    assert!(document
        .validate_with_options(intent::schema::ValidationOptions {
            deny_warnings: true
        })
        .is_err());
}

#[test]
fn selinux_audit_parsing_matches_observe_snapshot() {
    let log = include_str!("fixtures/selinux_audit.log");
    let events = selinux_audit::parse_audit_log(log);

    assert_eq!(events.len(), 6);
    assert_eq!(events[0].process.as_deref(), Some("himmelblaud"));
    assert_eq!(
        events[0].path.as_deref(),
        Some("/var/cache/himmelblaud/tokens.db")
    );

    assert_snapshot("selinux-observe.txt", &selinux_audit::observe(log));
}

#[test]
fn apparmor_audit_parsing_matches_observe_snapshot() {
    let log = include_str!("fixtures/apparmor_audit.log");
    let events = apparmor_audit::parse_audit_log(log);

    assert_eq!(events.len(), 6);
    assert_eq!(events[0].profile.as_deref(), Some("himmelblaud"));
    assert_eq!(
        events[0].name.as_deref(),
        Some("/etc/himmelblaud/config.yaml")
    );

    assert_snapshot("apparmor-observe.txt", &apparmor_audit::observe(log));
}

#[test]
fn suggestion_grouping_combines_equivalent_denials() {
    let selinux_log = r#"type=AVC msg=audit(1718123810.015:420): avc:  denied  { write } for  pid=1234 comm="demo" name="tokens.db" tclass=file
type=PATH msg=audit(1718123810.015:420): item=0 name="/var/cache/demo/tokens.db"
type=AVC msg=audit(1718123811.015:421): avc:  denied  { append } for  pid=1234 comm="demo" name="other.db" tclass=file
type=PATH msg=audit(1718123811.015:421): item=0 name="/var/cache/demo/other.db""#;
    let selinux_suggestions = selinux_audit::review_suggestions(selinux_log);
    assert_eq!(selinux_suggestions.len(), 1);
    assert_eq!(selinux_suggestions[0].denials.len(), 2);
    assert_eq!(selinux_suggestions[0].summary, "persistent cache storage");

    let apparmor_log = r#"type=1400 audit(1718123810.015:420): apparmor="DENIED" operation="open" class="file" profile="demo" name="/var/cache/demo/tokens.db" requested_mask="rw" denied_mask="w"
type=1400 audit(1718123811.015:421): apparmor="DENIED" operation="open" class="file" profile="demo" name="/var/cache/demo/other.db" requested_mask="rw" denied_mask="w""#;
    let apparmor_suggestions = apparmor_audit::review_suggestions(apparmor_log);
    assert_eq!(apparmor_suggestions.len(), 1);
    assert_eq!(apparmor_suggestions[0].denials.len(), 2);
    assert_eq!(apparmor_suggestions[0].summary, "persistent cache storage");
}

#[test]
fn example_configs_parse_and_normalize() {
    for path in [
        "examples/minimal.intent.yaml",
        "examples/himmelblaud.intent.yaml",
        "examples/escape-hatches.intent.yaml",
        "examples/himmelblau/intent.yaml",
    ] {
        let config = IntentConfig::from_path(path)
            .unwrap_or_else(|error| panic!("{path} should load: {error}"));
        assert_eq!(config.document.version, 1);
        assert!(!config.ir.application.name.is_empty());
        assert!(config.ir.application.executable.starts_with('/'));
    }
}
