//! AppArmor profile generation.

use crate::schema::IntentDocument;

/// Return placeholder AppArmor compiler output.
pub fn compile_placeholder(document: &IntentDocument) -> String {
    format!(
        "AppArmor profile generation is not implemented yet for {} ({})",
        document.application.name, document.application.executable
    )
}
