//! Policy compiler front-end and backend dispatch.

pub mod apparmor;
pub mod selinux;

use std::fmt;
use std::str::FromStr;

/// Supported policy compiler targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Selinux,
    AppArmor,
    All,
}

impl Target {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selinux => "selinux",
            Self::AppArmor => "apparmor",
            Self::All => "all",
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Target {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "selinux" => Ok(Self::Selinux),
            "apparmor" => Ok(Self::AppArmor),
            "all" => Ok(Self::All),
            other => Err(format!(
                "unsupported target '{other}'; expected selinux, apparmor, or all"
            )),
        }
    }
}
