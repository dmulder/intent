//! SELinux audit log analysis.

use std::path::Path;

/// Return placeholder SELinux audit analysis output.
pub fn observe_placeholder(source: &Path) -> String {
    format!(
        "SELinux audit analysis is not implemented yet for {}",
        source.display()
    )
}
