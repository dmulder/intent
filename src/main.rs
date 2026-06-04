use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use intent::audit::{apparmor as apparmor_audit, selinux as selinux_audit, AuditFormat};
use intent::compiler::{apparmor as apparmor_compiler, selinux as selinux_compiler, Target};
use intent::config::IntentConfig;

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
    },
    Build {
        intent_path: PathBuf,
        target: Target,
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
    match args {
        [intent_path] => Ok(Cli::Validate {
            intent_path: PathBuf::from(intent_path),
        }),
        _ => Err("usage: intent validate <intent.yaml>".to_string()),
    }
}

fn parse_build(args: &[String]) -> Result<Cli, String> {
    if args.len() != 3 {
        return Err("usage: intent build <intent.yaml> --target selinux|apparmor|all".to_string());
    }

    if args[1] != "--target" {
        return Err("missing required --target selinux|apparmor|all".to_string());
    }

    let target = args[2]
        .parse::<Target>()
        .map_err(|err| format!("invalid --target: {err}"))?;

    Ok(Cli::Build {
        intent_path: PathBuf::from(&args[0]),
        target,
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
        Cli::Validate { intent_path } => {
            let config = IntentConfig::from_path(&intent_path).map_err(|err| err.to_string())?;
            println!(
                "Validated {} for application '{}'.",
                config.source.display(),
                config.document.application.name
            );
        }
        Cli::Build {
            intent_path,
            target,
        } => {
            let config = IntentConfig::from_path(&intent_path).map_err(|err| err.to_string())?;
            println!(
                "Build placeholder: compiling {} for target {target}.",
                intent_path.display()
            );
            match target {
                Target::Selinux => {
                    println!(
                        "{}",
                        selinux_compiler::compile_placeholder(&config.document)
                    )
                }
                Target::AppArmor => {
                    println!(
                        "{}",
                        apparmor_compiler::compile_placeholder(&config.document)
                    )
                }
                Target::All => {
                    println!(
                        "{}",
                        selinux_compiler::compile_placeholder(&config.document)
                    );
                    println!(
                        "{}",
                        apparmor_compiler::compile_placeholder(&config.document)
                    );
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
            println!(
                "Explain placeholder: {} describes application '{}' in higher-level security intent terms.",
                config.source.display(),
                config.document.application.name
            );
        }
        Cli::Help => println!("{}", usage()),
    }

    Ok(())
}

fn usage() -> &'static str {
    "Intent - declarative Linux security policy compiler

Usage:
  intent validate <intent.yaml>
  intent build <intent.yaml> --target selinux|apparmor|all
  intent observe --source <audit.log> --format selinux|apparmor
  intent explain <intent.yaml>"
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
                intent_path: PathBuf::from("intent.yaml")
            })
        );
    }

    #[test]
    fn parses_build() {
        assert_eq!(
            Cli::parse(args(&["build", "intent.yaml", "--target", "selinux"])),
            Ok(Cli::Build {
                intent_path: PathBuf::from("intent.yaml"),
                target: Target::Selinux
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
