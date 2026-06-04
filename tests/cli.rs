use std::process::Command;

fn intent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_intent"))
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
    let output = intent()
        .args(["validate", "intent.yaml"])
        .output()
        .expect("intent validate should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Validation placeholder"));
}

#[test]
fn recognizes_build_targets() {
    for target in ["selinux", "apparmor", "all"] {
        let output = intent()
            .args(["build", "intent.yaml", "--target", target])
            .output()
            .expect("intent build should run");

        assert!(
            output.status.success(),
            "target {target} should be accepted"
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
        assert!(stdout.contains("Build placeholder"));
        assert!(stdout.contains(target));
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
    let output = intent()
        .args(["explain", "intent.yaml"])
        .output()
        .expect("intent explain should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("Explain placeholder"));
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
