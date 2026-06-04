//! SELinux policy generation.

use crate::schema::IntentDocument;

/// Return placeholder SELinux compiler output.
pub fn compile_placeholder(document: &IntentDocument) -> String {
    format!(
        "SELinux policy generation is not implemented yet for {} ({})",
        document.application.name, document.application.executable
    )
}
