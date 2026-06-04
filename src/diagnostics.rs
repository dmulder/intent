//! Diagnostics emitted by validation, compilation, and audit analysis.

/// Severity for a diagnostic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// A human-readable diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
}

impl Diagnostic {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
        }
    }
}
