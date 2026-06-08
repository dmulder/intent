use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use intent::audit::{
    apparmor as apparmor_audit, merge_value, merge_yaml_fragments, selinux as selinux_audit,
    AuditFormat, ReviewSuggestion,
};
use intent::compiler::{
    apparmor as apparmor_compiler, selinux as selinux_compiler, systemd as systemd_compiler, Target,
};
use intent::config::IntentConfig;
use intent::importer::{self, ImportFormat};
use intent::schema::{json_schema, markdown_documentation, ValidationOptions};

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
        interactive: bool,
        merge_into: Option<PathBuf>,
    },
    Import {
        policy_path: PathBuf,
        format: ImportFormat,
    },
    Explain {
        intent_path: PathBuf,
    },
    Schema {
        format: SchemaFormat,
    },
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaFormat {
    Markdown,
    JsonSchema,
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
            "import" => parse_import(&args[1..]),
            "explain" => parse_explain(&args[1..]),
            "schema" => parse_schema(&args[1..]),
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
            "usage: intent build <intent.yaml> --target selinux|apparmor|systemd|all [--output <dir>]"
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
                    return Err(
                        "missing value for --target selinux|apparmor|systemd|all".to_string()
                    );
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
                    "unknown build option '{other}'; usage: intent build <intent.yaml> --target selinux|apparmor|systemd|all [--output <dir>]"
                ));
            }
        }
    }

    let Some(target) = target else {
        return Err("missing required --target selinux|apparmor|systemd|all".to_string());
    };

    Ok(Cli::Build {
        intent_path: PathBuf::from(intent_path),
        target,
        output,
    })
}

fn parse_observe(args: &[String]) -> Result<Cli, String> {
    let mut source = None;
    let mut format = None;
    let mut interactive = false;
    let mut merge_into = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--source" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --source <audit.log>".to_string());
                };
                source = Some(PathBuf::from(value));
                index += 2;
            }
            "--format" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --format selinux|apparmor".to_string());
                };
                format = Some(
                    value
                        .parse::<AuditFormat>()
                        .map_err(|err| format!("invalid --format: {err}"))?,
                );
                index += 2;
            }
            "--interactive" => {
                interactive = true;
                index += 1;
            }
            "--merge-into" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --merge-into <intent.yaml>".to_string());
                };
                merge_into = Some(PathBuf::from(value));
                index += 2;
            }
            other => {
                return Err(format!(
                    "unknown observe option '{other}'; usage: intent observe --source <audit.log> --format selinux|apparmor [--interactive] [--merge-into <intent.yaml>]"
                ));
            }
        }
    }

    let Some(source) = source else {
        return Err("missing required --source <audit.log>".to_string());
    };
    let Some(format) = format else {
        return Err("missing required --format selinux|apparmor".to_string());
    };
    if merge_into.is_some() && !interactive {
        return Err("--merge-into requires --interactive".to_string());
    }

    Ok(Cli::Observe {
        source,
        format,
        interactive,
        merge_into,
    })
}

fn parse_import(args: &[String]) -> Result<Cli, String> {
    let Some(policy_path) = args.first() else {
        return Err("usage: intent import <policy-file> --format selinux|apparmor".to_string());
    };

    let mut format = None;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --format selinux|apparmor".to_string());
                };
                format = Some(
                    value
                        .parse::<ImportFormat>()
                        .map_err(|err| format!("invalid --format: {err}"))?,
                );
                index += 2;
            }
            other => {
                return Err(format!(
                    "unknown import option '{other}'; usage: intent import <policy-file> --format selinux|apparmor"
                ));
            }
        }
    }

    let Some(format) = format else {
        return Err("missing required --format selinux|apparmor".to_string());
    };

    Ok(Cli::Import {
        policy_path: PathBuf::from(policy_path),
        format,
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

fn parse_schema(args: &[String]) -> Result<Cli, String> {
    let mut format = SchemaFormat::Markdown;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --format markdown|json-schema".to_string());
                };
                format = match value.as_str() {
                    "markdown" => SchemaFormat::Markdown,
                    "json-schema" => SchemaFormat::JsonSchema,
                    other => {
                        return Err(format!(
                            "invalid --format '{other}'; expected markdown or json-schema"
                        ));
                    }
                };
                index += 2;
            }
            other => {
                return Err(format!(
                    "unknown schema option '{other}'; usage: intent schema [--format markdown|json-schema]"
                ));
            }
        }
    }

    Ok(Cli::Schema { format })
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
        Cli::Observe {
            source,
            format,
            interactive,
            merge_into,
        } => {
            let contents = fs::read_to_string(&source)
                .map_err(|err| format!("failed to read {}: {err}", source.display()))?;
            if interactive {
                let suggestions = review_suggestions(format, &contents);
                run_interactive_review(suggestions, merge_into)?;
            } else {
                let output = match format {
                    AuditFormat::Selinux => selinux_audit::observe(&contents),
                    AuditFormat::AppArmor => apparmor_audit::observe(&contents),
                };
                print!("{output}");
            }
        }
        Cli::Import {
            policy_path,
            format,
        } => {
            let imported =
                importer::import_path(&policy_path, format).map_err(|err| err.to_string())?;
            for warning in &imported.warnings {
                eprintln!("warning: {warning}");
            }
            print!("{}", imported.to_yaml().map_err(|err| err.to_string())?);
        }
        Cli::Explain { intent_path } => {
            let config = IntentConfig::from_path(&intent_path).map_err(|err| err.to_string())?;
            print!("{}", config.ir.explain());
        }
        Cli::Schema { format } => match format {
            SchemaFormat::Markdown => print!("{}", markdown_documentation()),
            SchemaFormat::JsonSchema => print!("{}", json_schema()),
        },
        Cli::Help => println!("{}", usage()),
    }

    Ok(())
}

fn usage() -> &'static str {
    "Intent - declarative Linux security policy compiler

Usage:
  intent validate <intent.yaml> [--deny-warnings]
  intent build <intent.yaml> --target selinux|apparmor|systemd|all [--output <dir>]
  intent observe --source <audit.log> --format selinux|apparmor [--interactive] [--merge-into <intent.yaml>]
  intent import <policy-file> --format selinux|apparmor
  intent explain <intent.yaml>
  intent schema [--format markdown|json-schema]"
}

fn review_suggestions(format: AuditFormat, contents: &str) -> Vec<ReviewSuggestion> {
    match format {
        AuditFormat::Selinux => selinux_audit::review_suggestions(contents),
        AuditFormat::AppArmor => apparmor_audit::review_suggestions(contents),
    }
}

fn run_interactive_review(
    suggestions: Vec<ReviewSuggestion>,
    merge_into: Option<PathBuf>,
) -> Result<(), String> {
    if suggestions.is_empty() {
        println!("No denials with high-level Intent suggestions detected.");
        return Ok(());
    }

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout();
    let mut accepted = Vec::new();

    for (index, suggestion) in suggestions.iter().enumerate() {
        let mut proposed_yaml = suggestion.yaml.clone();
        loop {
            print_interactive_suggestion(index, suggestions.len(), suggestion, &proposed_yaml);
            write!(
                stdout,
                "Choose [a]ccept, [r]eject, [e]dit, mark [u]nexpected, [s]how raw event: "
            )
            .map_err(|err| err.to_string())?;
            stdout.flush().map_err(|err| err.to_string())?;

            let choice = read_trimmed_line(&mut input)?;
            match choice.as_str() {
                "a" | "accept" => {
                    accepted.push(proposed_yaml);
                    println!("Accepted.");
                    break;
                }
                "r" | "reject" => {
                    println!("Rejected.");
                    break;
                }
                "u" | "unexpected" | "mark unexpected" => {
                    println!("Marked unexpected.");
                    break;
                }
                "s" | "show" | "raw" | "show raw event" => {
                    println!("Raw audit event(s):");
                    for denial in &suggestion.denials {
                        println!("  {}", denial.raw);
                    }
                    println!();
                }
                "e" | "edit" => {
                    println!("Enter replacement YAML. Finish with a single '.' line:");
                    proposed_yaml = read_multiline_yaml(&mut input)?;
                }
                _ => {
                    println!("Unknown choice.");
                }
            }
        }
    }

    if accepted.is_empty() {
        println!("No suggestions accepted.");
        return Ok(());
    }

    write_accepted_suggestions(&accepted, merge_into)
}

fn print_interactive_suggestion(
    index: usize,
    total: usize,
    suggestion: &ReviewSuggestion,
    proposed_yaml: &str,
) {
    println!();
    println!(
        "Suggestion {} of {}: {}",
        index + 1,
        total,
        suggestion.summary
    );
    println!("Grouped denials: {}", suggestion.denials.len());
    println!();
    println!("What was denied:");
    for (key, value) in &suggestion.denials[0].description {
        println!("  {key}: {value}");
    }
    if suggestion.denials.len() > 1 {
        println!("  plus {} similar denial(s)", suggestion.denials.len() - 1);
    }
    println!();
    println!("Why Intent mapped it this way:");
    println!("  {}", suggestion.reason);
    println!();
    println!("Proposed YAML fragment:");
    for line in proposed_yaml.lines() {
        println!("  {line}");
    }
}

fn read_trimmed_line(input: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    let bytes = input.read_line(&mut line).map_err(|err| err.to_string())?;
    if bytes == 0 {
        return Ok("reject".to_string());
    }
    Ok(line.trim().to_ascii_lowercase())
}

fn read_multiline_yaml(input: &mut impl BufRead) -> Result<String, String> {
    let mut yaml = String::new();
    loop {
        let mut line = String::new();
        let bytes = input.read_line(&mut line).map_err(|err| err.to_string())?;
        if bytes == 0 || line.trim() == "." {
            break;
        }
        yaml.push_str(&line);
    }
    Ok(yaml.trim_end().to_string())
}

fn write_accepted_suggestions(
    accepted: &[String],
    merge_into: Option<PathBuf>,
) -> Result<(), String> {
    let merged = merge_yaml_fragments(accepted)
        .map_err(|err| format!("failed to merge accepted YAML suggestions: {err}"))?;

    if let Some(path) = merge_into {
        let original = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let backup = backup_path(&path);
        fs::write(&backup, &original)
            .map_err(|err| format!("failed to write backup {}: {err}", backup.display()))?;

        let mut original_yaml: serde_yaml::Value = serde_yaml::from_str(&original)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
        let accepted_yaml: serde_yaml::Value = serde_yaml::from_str(&merged)
            .map_err(|err| format!("failed to parse accepted suggestions: {err}"))?;
        merge_value(&mut original_yaml, accepted_yaml);
        let contents = serde_yaml::to_string(&original_yaml)
            .map_err(|err| format!("failed to render merged YAML: {err}"))?;
        fs::write(&path, contents)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        println!("Backed up {} to {}", path.display(), backup.display());
        println!("Merged accepted suggestions into {}", path.display());
    } else {
        let path = PathBuf::from("intent.suggestions.yaml");
        fs::write(&path, merged)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        println!("Wrote accepted suggestions to {}", path.display());
    }

    Ok(())
}

fn backup_path(path: &std::path::Path) -> PathBuf {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    PathBuf::from(backup)
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
        Target::Systemd => vec![(
            systemd_compiler::dropin_file_name(),
            systemd_compiler::compile(ir),
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
            (
                systemd_compiler::dropin_file_name(),
                systemd_compiler::compile(ir),
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
        Target::Systemd => vec![(
            systemd_compiler::dropin_file_name(),
            systemd_compiler::compile(ir),
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
            (
                systemd_compiler::dropin_file_name(),
                systemd_compiler::compile(ir),
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
                format: AuditFormat::AppArmor,
                interactive: false,
                merge_into: None
            })
        );
    }

    #[test]
    fn parses_interactive_observe() {
        assert_eq!(
            Cli::parse(args(&[
                "observe",
                "--source",
                "audit.log",
                "--format",
                "selinux",
                "--interactive",
                "--merge-into",
                "intent.yaml"
            ])),
            Ok(Cli::Observe {
                source: PathBuf::from("audit.log"),
                format: AuditFormat::Selinux,
                interactive: true,
                merge_into: Some(PathBuf::from("intent.yaml"))
            })
        );
    }

    #[test]
    fn rejects_merge_into_without_interactive_review() {
        assert_eq!(
            Cli::parse(args(&[
                "observe",
                "--source",
                "audit.log",
                "--format",
                "selinux",
                "--merge-into",
                "intent.yaml"
            ])),
            Err("--merge-into requires --interactive".to_string())
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

    #[test]
    fn parses_schema() {
        assert_eq!(
            Cli::parse(args(&["schema"])),
            Ok(Cli::Schema {
                format: SchemaFormat::Markdown
            })
        );
        assert_eq!(
            Cli::parse(args(&["schema", "--format", "json-schema"])),
            Ok(Cli::Schema {
                format: SchemaFormat::JsonSchema
            })
        );
    }
}
