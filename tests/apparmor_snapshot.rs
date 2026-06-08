use std::path::PathBuf;

use intent::compiler::apparmor;
use intent::config::IntentConfig;

#[test]
fn himmelblaud_apparmor_profile_matches_snapshot() {
    let config = IntentConfig::from_path("examples/himmelblaud.intent.yaml")
        .expect("example intent should load");
    let generated = apparmor::compile(&config.ir);
    let expected = include_str!("snapshots/himmelblaud.apparmor");

    assert_eq!(generated, expected);
}

#[test]
fn minimal_apparmor_profile_matches_snapshot() {
    let config = IntentConfig::from_path(PathBuf::from("examples/minimal.intent.yaml"))
        .expect("example intent should load");
    let generated = apparmor::compile(&config.ir);
    let expected = include_str!("snapshots/minimal.apparmor");

    assert_eq!(generated, expected);
}
