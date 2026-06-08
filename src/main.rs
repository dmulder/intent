use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use intent::audit::{apparmor as apparmor_audit, selinux as selinux_audit, AuditFormat};
use intent::compiler::{apparmor as apparmor_compiler, selinux as selinux_compiler, Target};
use intent::config::IntentConfig;
use intent::schema::ValidationOptions;

fn main() -> ExitCode {
    match Cli::parse(env::args().skip(1)) {
        Ok(command) => {
            if let Err(error) = run(command) {
                eprintln!("{error}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("{message}\n");
            eprintln!("{}", usage());
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Cli {
    Validate {
        intent_path: PathBuf,
        deny_warnings: bool,
    },
    Build {
        intent_path: PathBuf,
        target: Target,
        output: Option<PathBuf>,
    },
    Observe {
        source: PathBuf,
        format: AuditFormat,
    },
    Explain {
        intent_path: PathBuf,
    },
    Help,
}

impl Cli {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        let Some(command) = args.first().map(String::as_str) else {
            return Ok(Self::Help);
        };

        match command {
            "-h" | "--help" | "help" => Ok(Self::Help),
            "validate" => parse_validate(&args[1..]),
            "build" => parse_build(&args[1..]),
            "observe" => parse_observe(&args[1..]),
            "explain" => parse_explain(&args[1..]),
            other => Err(format!("unknown command '{other}'")),
        }
    }
}

fn parse_validate(args: &[String]) -> Result<Cli, String> {
    let mut intent_path = None;
    let mut deny_warnings = false;

    for arg in args {
        if arg == "--deny-warnings" {
            deny_warnings = true;
        } else if intent_path.is_none() {
            intent_path = Some(PathBuf::from(arg));
        } else {
            return Err("usage: intent validate <intent.yaml> [--deny-warnings]".to_string());
        }
    }

    let Some(intent_path) = intent_path else {
        return Err("usage: intent validate <intent.yaml> [--deny-warnings]".to_string());
    };

    Ok(Cli::Validate {
        intent_path,
        deny_warnings,
    })
}

fn parse_build(args: &[String]) -> Result<Cli, String> {
    let Some(intent_path) = args.first() else {
        return Err(
            "usage: intent build <intent.yaml> --target selinux|apparmor|all [--output <dir>]"
                .to_string(),
        );
    };

    let mut target = None;
    let mut output = None;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--target" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --target selinux|apparmor|all".to_string());
                };
                target = Some(
                    value
                        .parse::<Target>()
                        .map_err(|err| format!("invalid --target: {err}"))?,
                );
                index += 2;
            }
            "--output" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --output <dir>".to_string());
                };
                output = Some(PathBuf::from(value));
                index += 2;
            }
            other => {
                return Err(format!(
                    "unknown build option '{other}'; usage: intent build <intent.yaml> --target selinux|apparmor|all [--output <dir>]"
                ));
            }
        }
    }

    let Some(target) = target else {
        return Err("missing required --target selinux|apparmor|all".to_string());
    };

    Ok(Cli::Build {
        intent_path: PathBuf::from(intent_path),
        target,
        output,
    })
}

fn parse_observe(args: &[String]) -> Result<Cli, String> {
    if args.len() != 4 {
        return Err(
            "usage: intent observe --source <audit.log> --format selinux|apparmor".to_string(),
        );
    }

    if args[0] != "--source" {
        return Err("missing required --source <audit.log>".to_string());
    }

    if args[2] != "--format" {
        return Err("missing required --format selinux|apparmor".to_string());
    }

    Ok(Cli::Observe {
        source: PathBuf::from(&args[1]),
        format: args[3]
            .parse::<AuditFormat>()
            .map_err(|err| format!("invalid --format: {err}"))?,
    })
}

fn parse_explain(args: &[String]) -> Result<Cli, String> {
    match args {
        [intent_path] => Ok(Cli::Explain {
            intent_path: PathBuf::from(intent_path),
        }),
        _ => Err("usage: intent explain <intent.yaml>".to_string()),
    }
}

fn run(command: Cli) -> Result<(), String> {
    match command {
        Cli::Validate {
            intent_path,
            deny_warnings,
        } => {
            let config = IntentConfig::from_path_with_options(
                &intent_path,
                ValidationOptions { deny_warnings },
            )
            .map_err(|err| err.to_string())?;
            let report = config.document.validate_with_options(ValidationOptions {
                deny_warnings: false,
            });
            if let Ok(report) = report {
                for warning in report.warnings() {
                    eprintln!("{warning}");
                }
            }
            println!(
                "Validated {} for application '{}'.",
                config.source.display(),
                config.document.application.name
            );
        }
        Cli::Build {
            intent_path,
            target,
            output,
        } => {
            let config = IntentConfig::from_path(&intent_path).map_err(|err| err.to_string())?;
            if let Some(output) = output {
                let outputs = build_file_outputs(&config.ir, target);
                fs::create_dir_all(&output).map_err(|err| {
                    format!(
                        "failed to create output directory {}: {err}",
                        output.display()
                    )
                })?;
                for (file_name, contents) in outputs {
                    let path = output.join(file_name);
                    fs::write(&path, contents)
                        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
                    println!("Wrote {}", path.display());
                }
            } else {
                let outputs = build_stdout_outputs(&config.ir, target);
                for (index, (_file_name, contents)) in outputs.into_iter().enumerate() {
                    if index > 0 {
                        println!();
                    }
                    print!("{contents}");
                }
            }
        }
        Cli::Observe { source, format } => {
            println!(
                "Observe placeholder: reading {} audit log from {}.",
                format,
                source.display()
            );
            match format {
                AuditFormat::Selinux => println!("{}", selinux_audit::observe_placeholder(&source)),
                AuditFormat::AppArmor => {
                    println!("{}", apparmor_audit::observe_placeholder(&source))
                }
            }
        }
        Cli::Explain { intent_path } => {
            let config = IntentConfig::from_path(&intent_path).map_err(|err| err.to_string())?;
            print!("{}", config.ir.explain());
        }
        Cli::Help => println!("{}", usage()),
    }

    Ok(())
}

fn usage() -> &'static str {
    "Intent - declarative Linux security policy compiler

Usage:
  intent validate <intent.yaml> [--deny-warnings]
  intent build <intent.yaml> --target selinux|apparmor|all [--output <dir>]
  intent observe --source <audit.log> --format selinux|apparmor
  intent explain <intent.yaml>"
}

fn build_stdout_outputs(ir: &intent::ir::PolicyIr, target: Target) -> Vec<(String, String)> {
    match target {
        Target::Selinux => vec![(
            selinux_compiler::module_file_name(ir),
            selinux_compiler::compile(ir),
        )],
        Target::AppArmor => vec![(
            apparmor_compiler::profile_file_name(ir),
            apparmor_compiler::compile(ir),
        )],
        Target::All => vec![
            (
                selinux_compiler::module_file_name(ir),
                selinux_compiler::compile(ir),
            ),
            (
                apparmor_compiler::profile_file_name(ir),
                apparmor_compiler::compile(ir),
            ),
        ],
    }
}

fn build_file_outputs(ir: &intent::ir::PolicyIr, target: Target) -> Vec<(String, String)> {
    match target {
        Target::Selinux => vec![
            (
                selinux_compiler::module_file_name(ir),
                selinux_compiler::compile(ir),
            ),
            (
                selinux_compiler::file_contexts_file_name(ir),
                selinux_compiler::file_contexts(ir),
            ),
        ],
        Target::AppArmor => vec![(
            apparmor_compiler::profile_file_name(ir),
            apparmor_compiler::compile(ir),
        )],
        Target::All => vec![
            (
                selinux_compiler::module_file_name(ir),
                selinux_compiler::compile(ir),
            ),
            (
                selinux_compiler::file_contexts_file_name(ir),
                selinux_compiler::file_contexts(ir),
            ),
            (
                apparmor_compiler::profile_file_name(ir),
                apparmor_compiler::compile(ir),
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parses_validate() {
        assert_eq!(
            Cli::parse(args(&["validate", "intent.yaml"])),
            Ok(Cli::Validate {
                intent_path: PathBuf::from("intent.yaml"),
                deny_warnings: false
            })
        );
    }

    #[test]
    fn parses_validate_deny_warnings() {
        assert_eq!(
            Cli::parse(args(&["validate", "--deny-warnings", "intent.yaml"])),
            Ok(Cli::Validate {
                intent_path: PathBuf::from("intent.yaml"),
                deny_warnings: true
            })
        );
    }

    #[test]
    fn parses_build() {
        assert_eq!(
            Cli::parse(args(&["build", "intent.yaml", "--target", "selinux"])),
            Ok(Cli::Build {
                intent_path: PathBuf::from("intent.yaml"),
                target: Target::Selinux,
                output: None
            })
        );
    }

    #[test]
    fn parses_build_output() {
        assert_eq!(
            Cli::parse(args(&[
                "build",
                "intent.yaml",
                "--target",
                "apparmor",
                "--output",
                "build"
            ])),
            Ok(Cli::Build {
                intent_path: PathBuf::from("intent.yaml"),
                target: Target::AppArmor,
                output: Some(PathBuf::from("build"))
            })
        );
    }

    #[test]
    fn parses_observe() {
        assert_eq!(
            Cli::parse(args(&[
                "observe",
                "--source",
                "audit.log",
                "--format",
                "apparmor"
            ])),
            Ok(Cli::Observe {
                source: PathBuf::from("audit.log"),
                format: AuditFormat::AppArmor
            })
        );
    }

    #[test]
    fn parses_explain() {
        assert_eq!(
            Cli::parse(args(&["explain", "intent.yaml"])),
            Ok(Cli::Explain {
                intent_path: PathBuf::from("intent.yaml")
            })
        );
    }
}
