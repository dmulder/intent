//! Public schema model for Intent files.

/// Current schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Top-level intent document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentDocument {
    /// Schema version declared by the document.
    pub version: u32,
}

impl Default for IntentDocument {
    fn default() -> Self {
        Self {
            version: CURRENT_SCHEMA_VERSION,
        }
    }
}
