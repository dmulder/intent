//! Configuration loading for `intent.yaml`.

use std::path::{Path, PathBuf};

/// Parsed Intent configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentConfig {
    /// Location the configuration was loaded from.
    pub source: PathBuf,
}

impl IntentConfig {
    /// Create a placeholder configuration for the given path.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        Self {
            source: path.as_ref().to_path_buf(),
        }
    }
}
