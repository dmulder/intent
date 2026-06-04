//! AppArmor audit log analysis.

use std::path::Path;

/// Return placeholder AppArmor audit analysis output.
pub fn observe_placeholder(source: &Path) -> String {
    format!(
        "AppArmor audit analysis is not implemented yet for {}",
        source.display()
    )
}
