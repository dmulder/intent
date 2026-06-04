//! Audit-log ingestion and intent suggestion support.

pub mod apparmor;
pub mod selinux;

use std::fmt;
use std::str::FromStr;

/// Supported audit log formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    Selinux,
    AppArmor,
}

impl AuditFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selinux => "selinux",
            Self::AppArmor => "apparmor",
        }
    }
}

impl fmt::Display for AuditFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuditFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "selinux" => Ok(Self::Selinux),
            "apparmor" => Ok(Self::AppArmor),
            other => Err(format!(
                "unsupported audit format '{other}'; expected selinux or apparmor"
            )),
        }
    }
}
