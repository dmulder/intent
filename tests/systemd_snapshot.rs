use std::path::PathBuf;

use intent::compiler::systemd;
use intent::config::IntentConfig;

#[test]
fn himmelblau_example_systemd_dropin_matches_expected_output() {
    let config = IntentConfig::from_path("examples/himmelblau/intent.yaml")
        .expect("example intent should load");
    let generated = systemd::compile(&config.ir);
    let expected = include_str!("../examples/himmelblau/expected/systemd/10-intent-hardening.conf");

    assert_eq!(generated, expected);
}

#[test]
fn himmelblaud_systemd_dropin_matches_snapshot() {
    let config = IntentConfig::from_path("examples/himmelblaud.intent.yaml")
        .expect("example intent should load");
    let generated = systemd::compile(&config.ir);
    let expected = include_str!("snapshots/himmelblaud.systemd.conf");

    assert_eq!(generated, expected);
}

#[test]
fn minimal_systemd_dropin_matches_snapshot() {
    let config = IntentConfig::from_path(PathBuf::from("examples/minimal.intent.yaml"))
        .expect("example intent should load");
    let generated = systemd::compile(&config.ir);
    let expected = include_str!("snapshots/minimal.systemd.conf");

    assert_eq!(generated, expected);
}
