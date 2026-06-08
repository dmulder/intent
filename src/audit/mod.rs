//! Audit-log ingestion and intent suggestion support.

pub mod apparmor;
pub mod selinux;

use serde_yaml::{Mapping, Value};
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

/// One grouped high-level suggestion inferred from similar audit denials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSuggestion {
    pub summary: String,
    pub reason: String,
    pub yaml: String,
    pub denials: Vec<ReviewDenial>,
}

/// Reviewable context for one audit denial inside a grouped suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewDenial {
    pub description: Vec<(String, String)>,
    pub raw: String,
}

/// Render grouped suggestions for non-interactive review.
pub fn render_review_suggestions(format_name: &str, suggestions: &[ReviewSuggestion]) -> String {
    if suggestions.is_empty() {
        return format!("No {format_name} denials with high-level Intent suggestions detected.");
    }

    let mut output = String::new();
    for (index, suggestion) in suggestions.iter().enumerate() {
        if index > 0 {
            push_line(&mut output, "");
        }

        push_line(
            &mut output,
            &format!(
                "Suggestion {} of {}: {}",
                index + 1,
                suggestions.len(),
                suggestion.summary
            ),
        );
        push_line(
            &mut output,
            &format!("Grouped denials: {}", suggestion.denials.len()),
        );
        push_line(&mut output, "");
        push_line(&mut output, "What was denied:");
        for (key, value) in &suggestion.denials[0].description {
            push_line(&mut output, &format!("  {key}: {value}"));
        }
        if suggestion.denials.len() > 1 {
            push_line(
                &mut output,
                &format!("  plus {} similar denial(s)", suggestion.denials.len() - 1),
            );
        }
        push_line(&mut output, "");
        push_line(&mut output, "Why Intent mapped it this way:");
        push_line(&mut output, &format!("  {}", suggestion.reason));
        push_line(&mut output, "");
        push_line(&mut output, "Proposed YAML fragment:");
        for line in suggestion.yaml.lines() {
            push_line(&mut output, &format!("  {line}"));
        }
    }

    output
}

/// Merge accepted YAML fragments into one YAML document.
pub fn merge_yaml_fragments(fragments: &[String]) -> Result<String, serde_yaml::Error> {
    let mut root = Value::Mapping(Mapping::new());

    for fragment in fragments {
        let value: Value = serde_yaml::from_str(fragment)?;
        merge_value(&mut root, value);
    }

    serde_yaml::to_string(&root)
}

pub(crate) fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

pub fn merge_value(base: &mut Value, addition: Value) {
    match (base, addition) {
        (Value::Mapping(base), Value::Mapping(addition)) => {
            for (key, addition_value) in addition {
                if let Some(base_value) = base.get_mut(&key) {
                    merge_value(base_value, addition_value);
                } else {
                    base.insert(key, addition_value);
                }
            }
        }
        (Value::Sequence(base), Value::Sequence(mut addition)) => {
            base.append(&mut addition);
        }
        (base, addition) => {
            *base = addition;
        }
    }
}
