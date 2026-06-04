//! Configuration loading for `intent.yaml`.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostics::Diagnostic;
use crate::schema::{IntentDocument, ValidationError, ValidationOptions};

/// Parsed Intent configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentConfig {
    /// Location the configuration was loaded from.
    pub source: PathBuf,
    /// Parsed and validated intent document.
    pub document: IntentDocument,
}

impl IntentConfig {
    /// Load, parse, and validate an Intent configuration from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::from_path_with_options(path, ValidationOptions::default())
    }

    /// Load, parse, and validate an Intent configuration from disk.
    pub fn from_path_with_options(
        path: impl AsRef<Path>,
        options: ValidationOptions,
    ) -> Result<Self, ConfigError> {
        let source = path.as_ref().to_path_buf();
        let contents = fs::read_to_string(&source).map_err(|source_error| ConfigError::Read {
            path: source.clone(),
            source: source_error,
        })?;

        Self::from_yaml_with_options(source, &contents, options)
    }

    /// Parse and validate an Intent configuration from YAML text.
    pub fn from_yaml(source: PathBuf, contents: &str) -> Result<Self, ConfigError> {
        Self::from_yaml_with_options(source, contents, ValidationOptions::default())
    }

    /// Parse and validate an Intent configuration from YAML text.
    pub fn from_yaml_with_options(
        source: PathBuf,
        contents: &str,
        options: ValidationOptions,
    ) -> Result<Self, ConfigError> {
        let value =
            serde_yaml::from_str::<serde_yaml::Value>(contents).map_err(|source_error| {
                ConfigError::Parse {
                    path: source.clone(),
                    source: source_error,
                }
            })?;
        let mut diagnostics = Vec::new();
        collect_empty_list_diagnostics(&value, None, &mut diagnostics);

        let document =
            serde_yaml::from_str::<IntentDocument>(contents).map_err(|source_error| {
                ConfigError::Parse {
                    path: source.clone(),
                    source: source_error,
                }
            })?;

        diagnostics.extend(document.diagnostics());

        let has_fatal = diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == crate::diagnostics::Severity::Error
                || (options.deny_warnings
                    && diagnostic.severity == crate::diagnostics::Severity::Warning)
        });

        if has_fatal {
            return Err(ConfigError::Validation {
                path: source.clone(),
                source: ValidationError { diagnostics },
            });
        }

        Ok(Self { source, document })
    }
}

/// Failures while loading an Intent configuration.
#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    Validation {
        path: PathBuf,
        source: ValidationError,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse {} as intent.yaml: {source}",
                    path.display()
                )
            }
            Self::Validation { path, source } => {
                write!(f, "invalid intent config in {}:\n{source}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn collect_empty_list_diagnostics(
    value: &serde_yaml::Value,
    path: Option<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match value {
        serde_yaml::Value::Sequence(values) => {
            if values.is_empty() {
                if let Some(path) = &path {
                    diagnostics.push(
                        Diagnostic::error(format!("{path} must not be an empty list"))
                            .help("remove the field or add at least one item"),
                    );
                }
            }

            for (index, value) in values.iter().enumerate() {
                if let Some(path) = &path {
                    collect_empty_list_diagnostics(
                        value,
                        Some(format!("{path}[{index}]")),
                        diagnostics,
                    );
                }
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in mapping {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let next_path = match &path {
                    Some(path) => format!("{path}.{key}"),
                    None => key.to_string(),
                };
                collect_empty_list_diagnostics(value, Some(next_path), diagnostics);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_valid_yaml() {
        let config = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
"#,
        )
        .expect("config should load");

        assert_eq!(config.document.application.name, "demo");
    }

    #[test]
    fn reports_parse_errors() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
  typo: true
"#,
        )
        .expect_err("unknown field should fail parsing");

        assert!(error.to_string().contains("failed to parse intent.yaml"));
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn reports_missing_required_fields() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
"#,
        )
        .expect_err("missing executable should fail parsing");

        assert!(error.to_string().contains("missing field `executable`"));
    }

    #[test]
    fn reports_invalid_access_modes() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config:
    - path: /etc/demo
      access: write
"#,
        )
        .expect_err("invalid access mode should fail parsing");

        assert!(error.to_string().contains("invalid access mode 'write'"));
        assert!(error.to_string().contains("expected read or read-write"));
    }

    #[test]
    fn reports_unknown_network_protocols() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
network:
  outbound:
    - to: example.com
      protocol: sctp
"#,
        )
        .expect_err("unknown network protocol should fail parsing");

        assert!(error
            .to_string()
            .contains("unknown network protocol 'sctp'"));
    }

    #[test]
    fn reports_invalid_socket_modes() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
ipc:
  unix_sockets:
    - path: /run/demo.sock
      mode: peer
"#,
        )
        .expect_err("invalid socket mode should fail parsing");

        assert!(error.to_string().contains("invalid socket mode 'peer'"));
    }

    #[test]
    fn reports_empty_lists() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config: []
"#,
        )
        .expect_err("empty list should fail validation");

        assert!(error
            .to_string()
            .contains("error: storage.config must not be an empty list"));
        assert!(error.to_string().contains("help: remove the field"));
    }

    #[test]
    fn reports_validation_errors() {
        let error = IntentConfig::from_yaml(
            PathBuf::from("intent.yaml"),
            r#"
version: 1
application:
  name: ""
  executable: demo
"#,
        )
        .expect_err("invalid config should fail validation");

        let message = error.to_string();
        assert!(message.contains("invalid intent config"));
        assert!(message.contains("application.name must not be empty"));
        assert!(message.contains("application.executable must be an absolute path"));
    }
}
