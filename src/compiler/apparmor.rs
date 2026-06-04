//! AppArmor profile generation.

use std::path::Path;

/// Return placeholder AppArmor compiler output.
pub fn compile_placeholder(intent_path: &Path) -> String {
    format!(
        "AppArmor profile generation is not implemented yet for {}",
        intent_path.display()
    )
}
