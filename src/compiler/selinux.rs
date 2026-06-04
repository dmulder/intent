//! SELinux policy generation.

use std::path::Path;

/// Return placeholder SELinux compiler output.
pub fn compile_placeholder(intent_path: &Path) -> String {
    format!(
        "SELinux policy generation is not implemented yet for {}",
        intent_path.display()
    )
}
