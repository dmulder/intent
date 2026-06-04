//! Configuration loading for `intent.yaml`.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::schema::{IntentDocument, ValidationError};

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
        let source = path.as_ref().to_path_buf();
        let contents = fs::read_to_string(&source).map_err(|source_error| ConfigError::Read {
            path: source.clone(),
            source: source_error,
        })?;

        Self::from_yaml(source, &contents)
    }

    /// Parse and validate an Intent configuration from YAML text.
    pub fn from_yaml(source: PathBuf, contents: &str) -> Result<Self, ConfigError> {
        let document =
            serde_yaml::from_str::<IntentDocument>(contents).map_err(|source_error| {
                ConfigError::Parse {
                    path: source.clone(),
                    source: source_error,
                }
            })?;

        document
            .validate()
            .map_err(|source_error| ConfigError::Validation {
                path: source.clone(),
                source: source_error,
            })?;

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
