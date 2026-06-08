use std::path::PathBuf;

use intent::compiler::selinux;
use intent::config::IntentConfig;

#[test]
fn himmelblaud_selinux_module_matches_snapshot() {
    let config = IntentConfig::from_path("examples/himmelblaud.intent.yaml")
        .expect("example intent should load");
    let generated = selinux::compile(&config.ir);
    let expected = include_str!("snapshots/himmelblaud.te");

    assert_eq!(generated, expected);
}

#[test]
fn himmelblaud_selinux_file_contexts_match_snapshot() {
    let config = IntentConfig::from_path("examples/himmelblaud.intent.yaml")
        .expect("example intent should load");
    let generated = selinux::file_contexts(&config.ir);
    let expected = include_str!("snapshots/himmelblaud.fc");

    assert_eq!(generated, expected);
}

#[test]
fn minimal_selinux_module_matches_snapshot() {
    let config = IntentConfig::from_path(PathBuf::from("examples/minimal.intent.yaml"))
        .expect("example intent should load");
    let generated = selinux::compile(&config.ir);
    let expected = include_str!("snapshots/minimal.te");

    assert_eq!(generated, expected);
}

#[test]
fn minimal_selinux_file_contexts_match_snapshot() {
    let config = IntentConfig::from_path(PathBuf::from("examples/minimal.intent.yaml"))
        .expect("example intent should load");
    let generated = selinux::file_contexts(&config.ir);
    let expected = include_str!("snapshots/minimal.fc");

    assert_eq!(generated, expected);
}
