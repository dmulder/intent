use std::process::Command;
use std::{env, fs};

fn intent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_intent"))
}

fn valid_intent(name: &str) -> std::path::PathBuf {
    let path = env::temp_dir().join(format!("intent-{name}-{}.yaml", std::process::id()));
    fs::write(
        &path,
        r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
"#,
    )
    .expect("test intent file should be written");
    path
}

#[test]
fn starts_and_prints_help() {
    let output = intent().output().expect("intent command should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("intent validate <intent.yaml>"));
    assert!(stdout.contains("intent build <intent.yaml> --target selinux|apparmor|all"));
    assert!(stdout.contains("intent observe --source <audit.log> --format selinux|apparmor"));
    assert!(stdout.contains("intent explain <intent.yaml>"));
}

#[test]
fn recognizes_validate() {
    let path = valid_intent("validate");
    let output = intent()
        .arg("validate")
        .arg(&path)
        .output()
        .expect("intent validate should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Validated"));
    assert!(stdout.contains("demo"));
}

#[test]
fn recognizes_build_targets() {
    let path = valid_intent("build");
    for target in ["selinux", "apparmor", "all"] {
        let output = intent()
            .arg("build")
            .arg(&path)
            .args(["--target", target])
            .output()
            .expect("intent build should run");

        assert!(
            output.status.success(),
            "target {target} should be accepted"
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
        assert!(stdout.contains("Build placeholder"));
        assert!(stdout.contains(target));
        assert!(stdout.contains("demo (/usr/bin/demo)"));
    }
}

#[test]
fn recognizes_observe_formats() {
    for format in ["selinux", "apparmor"] {
        let output = intent()
            .args(["observe", "--source", "audit.log", "--format", format])
            .output()
            .expect("intent observe should run");

        assert!(
            output.status.success(),
            "format {format} should be accepted"
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
        assert!(stdout.contains("Observe placeholder"));
        assert!(stdout.contains(format));
    }
}

#[test]
fn recognizes_explain() {
    let path = valid_intent("explain");
    let output = intent()
        .arg("explain")
        .arg(&path)
        .output()
        .expect("intent explain should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Explain placeholder"));
    assert!(stdout.contains("demo"));
}

#[test]
fn validate_rejects_invalid_config() {
    let path = env::temp_dir().join(format!("intent-invalid-{}.yaml", std::process::id()));
    fs::write(
        &path,
        r#"
version: 1
application:
  name: ""
  executable: demo
"#,
    )
    .expect("test intent file should be written");

    let output = intent()
        .arg("validate")
        .arg(&path)
        .output()
        .expect("intent validate should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("application.name must not be empty"));
    assert!(stderr.contains("application.executable must be an absolute path"));
}

#[test]
fn rejects_unknown_command() {
    let output = intent()
        .arg("unknown")
        .output()
        .expect("intent unknown should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("unknown command 'unknown'"));
}
