//! Public schema model for Intent files.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::diagnostics::{Diagnostic, Severity};

/// Current schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Render human-facing documentation for the current `intent.yaml` schema.
pub fn markdown_documentation() -> String {
    let mut output = String::new();

    output.push_str("# intent.yaml\n\n");
    output.push_str(
        "Intent files describe what a Linux application needs to do. Keep them small, readable, and focused on application behavior rather than SELinux or AppArmor policy syntax.\n\n",
    );
    output.push_str("## Example\n\n");
    output.push_str("```yaml\n");
    output.push_str("version: 1\n\n");
    output.push_str("application:\n");
    output.push_str("  name: my-service\n");
    output.push_str("  description: Small service that calls an HTTPS API\n");
    output.push_str("  executable: /usr/bin/my-service\n");
    output.push_str("  user: my-service\n");
    output.push_str("  group: my-service\n\n");
    output.push_str("storage:\n");
    output.push_str("  config:\n");
    output.push_str("    - path: /etc/my-service\n");
    output.push_str("      access: read\n");
    output.push_str("  state:\n");
    output.push_str("    - path: /var/lib/my-service\n");
    output.push_str("      access: read-write\n\n");
    output.push_str("network:\n");
    output.push_str("  outbound:\n");
    output.push_str("    - to: api.example.com\n");
    output.push_str("      protocol: https\n\n");
    output.push_str("ipc:\n");
    output.push_str("  unix_sockets:\n");
    output.push_str("    - path: /run/my-service/control.sock\n");
    output.push_str("      mode: server\n");
    output.push_str("```\n\n");

    output.push_str("## Fields\n\n");
    output.push_str(
        "| Field | Required | Example | Validation | Security notes | Backend support |\n",
    );
    output.push_str("| --- | --- | --- | --- | --- | --- |\n");

    for field in schema_fields() {
        let _ = writeln!(
            output,
            "| `{}` | {} | `{}` | {} | {} | SELinux: {}<br>AppArmor: {} |",
            field.path,
            if field.required { "yes" } else { "no" },
            escape_table(field.example),
            field.validation,
            field.security,
            field.selinux,
            field.apparmor,
        );
    }

    output.push_str("\n## Validation Summary\n\n");
    output.push_str("- Unknown fields are rejected so typos do not silently weaken policy.\n");
    output.push_str(
        "- Empty lists are rejected; omit a section when the application does not need it.\n",
    );
    output.push_str("- Paths must be absolute, normalized, one-line Linux paths without NUL bytes, `.` components, or `..` components.\n");
    output.push_str(
        "- Very broad storage paths such as `/`, `/etc`, `/var`, and `/usr` produce warnings.\n",
    );
    output.push_str("- Cache paths outside `/var/cache` and state paths outside `/var/lib` produce warnings unless they include a `justification`.\n");
    output.push_str("- Runtime paths must be under `/run` or `/var/run`.\n");
    output
        .push_str("- `tcp` and `udp` network entries require `port`; `http` and `https` do not.\n");
    output
        .push_str("- D-Bus names must be valid well-known names such as `org.example.Service`.\n");
    output.push_str("- Unknown extension blocks produce warnings. Known extension fragments are preserved and compiled into their backend-specific policy section.\n\n");
    output.push_str("## Backend Notes\n\n");
    output.push_str("- SELinux output currently includes a type-enforcement module and file-context suggestions for executable and storage paths.\n");
    output.push_str("- AppArmor output currently includes a profile with file, network, Unix socket, D-Bus, and capability rules where supported by the schema.\n");
    output.push_str("- Escape hatches under `extensions` are backend-specific and should be treated as temporary workarounds until Intent gains native fields for the behavior.\n");
    output.push_str("- Intent may accept high-level fields before every backend can express them equally. Backend notes above call out gaps.\n");

    output
}

/// Render a JSON Schema for the current `intent.yaml` schema.
pub fn json_schema() -> &'static str {
    r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://intent.dev/schema/intent.schema.json",
  "title": "Intent Linux security policy intent",
  "description": "Plain YAML schema for describing Linux application security intent.",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "application"],
  "properties": {
    "version": {
      "description": "Intent schema version.",
      "type": "integer",
      "const": 1
    },
    "application": {
      "description": "Application identity and launch context.",
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "executable"],
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1,
          "description": "Human-readable application name used in diagnostics and generated policy names."
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "description": "Short maintainer-facing description."
        },
        "executable": {
          "type": "string",
          "minLength": 1,
          "pattern": "^/",
          "description": "Absolute path to the executable that should run under this policy."
        },
        "user": {
          "type": "string",
          "minLength": 1,
          "description": "Unix user the application normally runs as."
        },
        "group": {
          "type": "string",
          "minLength": 1,
          "description": "Unix group the application normally runs as."
        }
      }
    },
    "processes": {
      "description": "Additional cooperating executables and SELinux process domains.",
      "type": "array",
      "minItems": 1,
      "items": { "$ref": "#/$defs/process" }
    },
    "storage": {
      "description": "Files and directories the application expects to use.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "config": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/storagePath" },
          "description": "Long-lived administrator or package-provided configuration."
        },
        "cache": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/storagePath" },
          "description": "Disposable data the application can rebuild."
        },
        "state": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/storagePath" },
          "description": "Persistent application-owned data."
        },
        "runtime": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/runtimeStoragePath" },
          "description": "Short-lived data such as pid files and sockets under /run or /var/run."
        }
      }
    },
    "network": {
      "description": "Network access requested by the application.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "outbound": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/outboundNetwork" },
          "description": "Outbound connections initiated by the application."
        }
      }
    },
    "ipc": {
      "description": "Local inter-process communication requested by the application.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "unix_sockets": {
          "type": "array",
          "minItems": 1,
          "items": { "$ref": "#/$defs/unixSocket" },
          "description": "Unix domain sockets created or contacted by the application."
        },
        "dbus": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "system": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "owns": {
                  "type": "array",
                  "minItems": 1,
                  "items": { "$ref": "#/$defs/dbusName" },
                  "description": "Well-known system-bus names provided by the application."
                },
                "talks_to": {
                  "type": "array",
                  "minItems": 1,
                  "items": { "$ref": "#/$defs/dbusName" },
                  "description": "Well-known system-bus services called by the application."
                }
              }
            }
          }
        }
      }
    },
    "capabilities": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string",
        "minLength": 1,
        "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$"
      },
      "description": "Linux capabilities by friendly kebab-case name."
    },
    "selinux": {
      "description": "Structured SELinux-specific policy details imported from or compiled into SELinux policy.",
      "$ref": "#/$defs/selinuxPolicy"
    },
    "extensions": {
      "description": "Backend-specific temporary escape hatches for policy capabilities not yet modeled by Intent.",
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "selinux": {
          "type": "object",
          "additionalProperties": true,
          "properties": {
            "policy": {
              "type": "array",
              "minItems": 1,
              "items": {
                "type": "string",
                "minLength": 1
              },
              "description": "Manual SELinux type-enforcement policy fragments inserted into the generated policy module."
            },
            "file_contexts": {
              "type": "array",
              "minItems": 1,
              "items": {
                "type": "string",
                "minLength": 1
              },
              "description": "Manual SELinux file-context fragments appended to the generated file-context output."
            }
          }
        },
        "apparmor": {
          "type": "object",
          "additionalProperties": true,
          "properties": {
            "rules": {
              "type": "array",
              "minItems": 1,
              "items": {
                "type": "string",
                "minLength": 1
              },
              "description": "Manual AppArmor profile-body rules inserted into the generated profile."
            }
          }
        }
      }
    },
    "notes": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "string",
        "minLength": 1
      },
      "description": "Free-form maintainer notes. Not compiled into policy."
    }
  },
  "$defs": {
    "storagePath": {
      "type": "object",
      "additionalProperties": false,
      "required": ["path", "access"],
      "properties": {
        "path": {
          "type": "string",
          "minLength": 1,
          "pattern": "^/",
          "description": "Absolute file or directory path."
        },
        "access": {
          "type": "string",
          "enum": ["read", "read-write"],
          "description": "High-level access mode."
        },
        "processes": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 },
          "description": "Process ids this storage entry applies to."
        },
        "selinux_type": {
          "type": "string",
          "minLength": 1,
          "description": "SELinux type name to use for this path when preserving imported labels."
        },
        "justification": {
          "type": "string",
          "minLength": 1,
          "description": "Human explanation for storage outside the conventional location."
        }
      }
    },
    "runtimeStoragePath": {
      "allOf": [
        { "$ref": "#/$defs/storagePath" },
        {
          "properties": {
            "path": {
              "pattern": "^(/run|/var/run)(/|$)"
            }
          }
        }
      ]
    },
    "outboundNetwork": {
      "type": "object",
      "additionalProperties": false,
      "required": ["to", "protocol"],
      "properties": {
        "to": {
          "type": "string",
          "minLength": 1,
          "description": "DNS name, host, network, or service label for the destination."
        },
        "protocol": {
          "type": "string",
          "enum": ["http", "https", "tcp", "udp"]
        },
        "port": {
          "type": "integer",
          "minimum": 1,
          "maximum": 65535
        },
        "processes": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 },
          "description": "Process ids this network need applies to."
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "protocol": { "enum": ["tcp", "udp"] }
            },
            "required": ["protocol"]
          },
          "then": {
            "required": ["port"]
          }
        }
      ]
    },
    "unixSocket": {
      "type": "object",
      "additionalProperties": false,
      "required": ["path", "mode"],
      "properties": {
        "path": {
          "type": "string",
          "minLength": 1,
          "pattern": "^/"
        },
        "mode": {
          "type": "string",
          "enum": ["server", "client"]
        },
        "processes": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 },
          "description": "Process ids this socket need applies to."
        }
      }
    },
    "process": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "name", "executable"],
      "properties": {
        "id": { "type": "string", "minLength": 1, "pattern": "^[a-z0-9]+(-[a-z0-9]+)*$" },
        "name": { "type": "string", "minLength": 1 },
        "executable": { "type": "string", "minLength": 1, "pattern": "^/" },
        "additional_executables": {
          "type": "array",
          "items": { "type": "string", "minLength": 1, "pattern": "^/" }
        },
        "domain_type": { "type": "string", "minLength": 1 },
        "exec_type": { "type": "string", "minLength": 1 },
        "role": { "type": "string", "minLength": 1 },
        "started_by": { "type": "string", "minLength": 1 },
        "use_nnp_transition": { "type": "boolean" },
        "permissive": { "type": "boolean" }
      }
    },
    "selinuxPolicy": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "compatibility": { "type": "string", "minLength": 1 },
        "types": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxType" }
        },
        "roles": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxRole" }
        },
        "transitions": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxTransition" }
        },
        "allows": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxAllow" }
        },
        "macro_calls": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxMacroCall" }
        },
        "filesystem_associations": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxFilesystemAssociation" }
        },
        "permissive": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 }
        },
        "file_contexts": {
          "type": "array",
          "items": { "$ref": "#/$defs/selinuxFileContext" }
        }
      }
    },
    "selinuxType": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name"],
      "properties": {
        "name": { "type": "string", "minLength": 1 },
        "kind": { "type": "string", "minLength": 1 },
        "optional": { "type": "boolean" }
      }
    },
    "selinuxRole": {
      "type": "object",
      "additionalProperties": false,
      "required": ["role", "domain"],
      "properties": {
        "role": { "type": "string", "minLength": 1 },
        "domain": { "type": "string", "minLength": 1 },
        "optional": { "type": "boolean" }
      }
    },
    "selinuxTransition": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source", "exec_type", "target"],
      "properties": {
        "source": { "type": "string", "minLength": 1 },
        "exec_type": { "type": "string", "minLength": 1 },
        "target": { "type": "string", "minLength": 1 },
        "optional": { "type": "boolean" }
      }
    },
    "selinuxAllow": {
      "type": "object",
      "additionalProperties": false,
      "required": ["source", "target", "class", "permissions"],
      "properties": {
        "source": { "type": "string", "minLength": 1 },
        "target": { "type": "string", "minLength": 1 },
        "class": { "type": "string", "minLength": 1 },
        "permissions": {
          "type": "array",
          "minItems": 1,
          "items": { "type": "string", "minLength": 1 }
        },
        "optional": { "type": "boolean" }
      }
    },
    "selinuxMacroCall": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name"],
      "properties": {
        "name": { "type": "string", "minLength": 1 },
        "args": {
          "type": "array",
          "items": { "type": "string", "minLength": 1 }
        },
        "optional": { "type": "boolean" },
        "condition": { "type": "string", "minLength": 1 }
      }
    },
    "selinuxFilesystemAssociation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type_name", "filesystem_type"],
      "properties": {
        "type_name": { "type": "string", "minLength": 1 },
        "filesystem_type": { "type": "string", "minLength": 1 },
        "optional": { "type": "boolean" }
      }
    },
    "selinuxFileContext": {
      "type": "object",
      "additionalProperties": false,
      "required": ["path", "type_name"],
      "properties": {
        "path": { "type": "string", "minLength": 1, "pattern": "^/" },
        "type_name": { "type": "string", "minLength": 1 },
        "file_type": { "type": "string", "minLength": 1 }
      }
    },
    "dbusName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255,
      "pattern": "^[A-Za-z_-][A-Za-z0-9_-]*(\\.[A-Za-z_-][A-Za-z0-9_-]*)+$"
    }
  }
}
"##
}

#[derive(Debug, Clone, Copy)]
struct SchemaField {
    path: &'static str,
    required: bool,
    example: &'static str,
    validation: &'static str,
    security: &'static str,
    selinux: &'static str,
    apparmor: &'static str,
}

fn schema_fields() -> &'static [SchemaField] {
    &[
        SchemaField {
            path: "version",
            required: true,
            example: "1",
            validation: "Must equal the current schema version, 1.",
            security: "Makes future schema changes explicit during review.",
            selinux: "Used only by Intent validation.",
            apparmor: "Used only by Intent validation.",
        },
        SchemaField {
            path: "application",
            required: true,
            example: "application: ...",
            validation: "Object. Unknown fields are rejected.",
            security: "Defines the process identity Intent protects.",
            selinux: "Drives module, domain, and executable type names.",
            apparmor: "Drives profile name and executable attachment.",
        },
        SchemaField {
            path: "application.name",
            required: true,
            example: "my-service",
            validation: "Non-empty string.",
            security:
                "Use a stable package or service name so generated policy remains reviewable.",
            selinux: "Used in generated type and module names.",
            apparmor: "Used as the generated profile name.",
        },
        SchemaField {
            path: "application.description",
            required: false,
            example: "Small service that calls an HTTPS API",
            validation: "Non-empty string when present.",
            security: "Documentation for reviewers; not a permission grant.",
            selinux: "Not compiled.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "application.executable",
            required: true,
            example: "/usr/bin/my-service",
            validation: "Absolute, normalized, one-line path.",
            security: "Choose the real executable entry point, not a broad directory.",
            selinux: "Labels the executable and creates the application domain transition target.",
            apparmor: "Attaches the profile to this executable path.",
        },
        SchemaField {
            path: "application.user",
            required: false,
            example: "my-service",
            validation: "Non-empty string when present.",
            security: "Documents the expected Unix account; omit for per-user apps.",
            selinux: "Documented in generated comments only.",
            apparmor: "Documented in generated comments only.",
        },
        SchemaField {
            path: "application.group",
            required: false,
            example: "my-service",
            validation: "Non-empty string when present.",
            security: "Documents the expected Unix group; omit when not fixed.",
            selinux: "Documented in generated comments only.",
            apparmor: "Documented in generated comments only.",
        },
        SchemaField {
            path: "processes[]",
            required: false,
            example: "{ id: helper, name: helper, executable: /usr/bin/helper }",
            validation: "Non-empty list of process entries.",
            security: "Use for cooperating executables that need distinct confinement.",
            selinux: "Generates additional process domains and executable labels.",
            apparmor: "Documented only; AppArmor still compiles the primary profile.",
        },
        SchemaField {
            path: "processes[].id",
            required: true,
            example: "helper",
            validation: "Non-empty kebab-case string.",
            security: "Stable process ids make scoped rules reviewable.",
            selinux: "Used as a fallback for generated type names.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "processes[].executable",
            required: true,
            example: "/usr/bin/helper",
            validation: "Absolute, normalized, one-line path.",
            security: "Choose the executable that enters the process domain.",
            selinux: "Labels the executable and creates the domain entry target.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "processes[].domain_type",
            required: false,
            example: "helper_t",
            validation: "Non-empty string when present.",
            security: "Preserves reviewed SELinux type names during import.",
            selinux: "Overrides generated process domain type names.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "storage",
            required: false,
            example: "storage: ...",
            validation: "Object. Omit when no storage access is needed.",
            security: "Declare storage by purpose so reviewers can spot overbroad paths.",
            selinux: "Generates file allow rules and file-context suggestions.",
            apparmor: "Generates path rules.",
        },
        SchemaField {
            path: "storage.config[]",
            required: false,
            example: "{ path: /etc/my-service, access: read }",
            validation: "Non-empty list of storage entries.",
            security: "Use read-only access for administrator or package-provided configuration.",
            selinux: "Generates read or write file permissions for declared paths.",
            apparmor: "Generates `r` or `rw` path permissions.",
        },
        SchemaField {
            path: "storage.cache[]",
            required: false,
            example: "{ path: /var/cache/my-service, access: read-write }",
            validation: "Non-empty list. Warns outside /var/cache unless justified.",
            security: "Cache should be disposable and narrow to the application.",
            selinux: "Generates file permissions and file contexts for cache paths.",
            apparmor: "Generates path permissions.",
        },
        SchemaField {
            path: "storage.state[]",
            required: false,
            example: "{ path: /var/lib/my-service, access: read-write }",
            validation: "Non-empty list. Warns outside /var/lib unless justified.",
            security: "State is persistent application-owned data; keep it application-specific.",
            selinux: "Generates file permissions and file contexts for state paths.",
            apparmor: "Generates path permissions.",
        },
        SchemaField {
            path: "storage.runtime[]",
            required: false,
            example: "{ path: /run/my-service, access: read-write }",
            validation: "Non-empty list. Path must be under /run or /var/run.",
            security: "Runtime paths should be short-lived sockets, pid files, and similar data.",
            selinux: "Generates file permissions and file contexts for runtime paths.",
            apparmor: "Generates path permissions.",
        },
        SchemaField {
            path: "storage.*[].path",
            required: true,
            example: "/var/lib/my-service",
            validation: "Absolute, normalized, one-line path; broad roots warn.",
            security: "Declare the narrowest file or directory the application needs.",
            selinux: "Used in file-context suggestions and file allow rules.",
            apparmor: "Used directly in path rules.",
        },
        SchemaField {
            path: "storage.*[].access",
            required: true,
            example: "read-write",
            validation: "Must be read or read-write.",
            security: "Prefer read unless the application must create or modify data.",
            selinux: "Maps to read-only or read/write file permissions.",
            apparmor: "Maps to `r` or `rw` path permissions.",
        },
        SchemaField {
            path: "storage.*[].processes",
            required: false,
            example: "[helper]",
            validation: "List of process ids when present.",
            security: "Scope storage access to only the process that needs it.",
            selinux: "Reserved for process-scoped storage generation.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "storage.*[].selinux_type",
            required: false,
            example: "helper_var_lib_t",
            validation: "Non-empty string when present.",
            security: "Preserves imported path labels for SELinux review.",
            selinux: "Reserved for imported type naming and file contexts.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "storage.*[].justification",
            required: false,
            example: "vendor package layout",
            validation: "Non-empty string when present.",
            security:
                "Explain exceptions such as cache outside /var/cache or state outside /var/lib.",
            selinux: "Not compiled.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "network",
            required: false,
            example: "network: ...",
            validation: "Object. Omit when no network access is needed.",
            security: "Declare only outbound destinations the application initiates.",
            selinux: "Generates coarse network permissions for supported protocols.",
            apparmor: "Generates network rules for supported protocols.",
        },
        SchemaField {
            path: "network.outbound[]",
            required: false,
            example: "{ to: api.example.com, protocol: https }",
            validation: "Non-empty list of outbound entries.",
            security: "Keep destinations specific enough for human review.",
            selinux: "Destination is documented; protocol influences generated allow rules.",
            apparmor: "Protocol influences generated network rules; destination is documented.",
        },
        SchemaField {
            path: "network.outbound[].to",
            required: true,
            example: "api.example.com",
            validation: "Non-empty string.",
            security: "Use a meaningful DNS name, host, network, or service label.",
            selinux: "Documented in generated comments.",
            apparmor: "Documented in generated comments.",
        },
        SchemaField {
            path: "network.outbound[].protocol",
            required: true,
            example: "https",
            validation: "Must be http, https, tcp, or udp.",
            security: "Choose the narrowest protocol that describes the connection.",
            selinux: "Maps to generated network permission templates.",
            apparmor: "Maps to `network inet tcp` or `network inet udp` style rules.",
        },
        SchemaField {
            path: "network.outbound[].port",
            required: false,
            example: "443",
            validation: "1 through 65535. Required for tcp and udp.",
            security: "Use explicit ports for raw TCP/UDP to avoid broad network access.",
            selinux: "Documented; port-level confinement depends on policy environment.",
            apparmor: "Documented; AppArmor network rules are protocol-oriented.",
        },
        SchemaField {
            path: "ipc",
            required: false,
            example: "ipc: ...",
            validation: "Object. Omit when no local IPC access is needed.",
            security: "Local IPC often crosses trust boundaries; keep entries intentional.",
            selinux: "Generates rules for supported IPC declarations.",
            apparmor: "Generates Unix socket and D-Bus rules.",
        },
        SchemaField {
            path: "ipc.unix_sockets[]",
            required: false,
            example: "{ path: /run/my-service/control.sock, mode: server }",
            validation: "Non-empty list of socket entries.",
            security: "Declare whether the application listens or connects.",
            selinux: "Generates Unix socket-related allow rules where expressible.",
            apparmor: "Generates Unix socket rules.",
        },
        SchemaField {
            path: "ipc.unix_sockets[].path",
            required: true,
            example: "/run/my-service/control.sock",
            validation: "Absolute, normalized, one-line path.",
            security: "Use an application-specific socket path when the application owns it.",
            selinux: "Used in file-context suggestions and socket permissions.",
            apparmor: "Used in Unix socket path rules.",
        },
        SchemaField {
            path: "ipc.unix_sockets[].mode",
            required: true,
            example: "server",
            validation: "Must be server or client.",
            security: "Server means the app creates/listens; client means it connects.",
            selinux: "Guides generated socket permissions.",
            apparmor: "Guides generated Unix socket permissions.",
        },
        SchemaField {
            path: "ipc.dbus.system.owns[]",
            required: false,
            example: "org.example.Service",
            validation: "Non-empty valid D-Bus well-known name.",
            security: "Owning a bus name exposes a service surface; keep names explicit.",
            selinux: "Documented for review; direct D-Bus confinement is limited.",
            apparmor: "Generates D-Bus own rules.",
        },
        SchemaField {
            path: "ipc.dbus.system.talks_to[]",
            required: false,
            example: "org.freedesktop.DBus",
            validation: "Non-empty valid D-Bus well-known name.",
            security: "Only list services the application is expected to call.",
            selinux: "Documented for review; direct D-Bus confinement is limited.",
            apparmor: "Generates D-Bus talk rules.",
        },
        SchemaField {
            path: "capabilities[]",
            required: false,
            example: "net-bind-service",
            validation: "Non-empty kebab-case capability name.",
            security:
                "Capabilities are powerful; keep the list short and prefer high-level intents.",
            selinux: "Generates capability allow rules for supported names.",
            apparmor: "Generates capability rules.",
        },
        SchemaField {
            path: "selinux",
            required: false,
            example: "selinux: ...",
            validation: "Object. Unknown fields are rejected.",
            security: "Structured SELinux details should be reviewed like backend policy.",
            selinux: "Generates SELinux-specific declarations, allows, transitions, macros, and file contexts.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "selinux.allows[]",
            required: false,
            example: "{ source: helper_t, target: self, class: capability, permissions: [dac_override] }",
            validation: "Requires source, target, class, and one or more permissions.",
            security: "Prefer high-level fields when available; use for precise SELinux imports.",
            selinux: "Generates SELinux allow rules.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "selinux.transitions[]",
            required: false,
            example: "{ source: init_t, exec_type: helper_exec_t, target: helper_t }",
            validation: "Requires source, exec_type, and target.",
            security: "Documents explicit process domain transitions.",
            selinux: "Generates type_transition rules.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "selinux.file_contexts[]",
            required: false,
            example: "{ path: /usr/bin/helper, type_name: helper_exec_t }",
            validation: "Requires absolute path and type_name.",
            security: "Labels must match the intended executable or data path.",
            selinux: "Generates structured SELinux file-context entries.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "extensions",
            required: false,
            example: "extensions: ...",
            validation: "Object. Unknown extension blocks produce warnings.",
            security: "Backend-specific escape hatches should be temporary and reviewed as raw policy.",
            selinux: "Contains optional SELinux policy fragments.",
            apparmor: "Contains optional AppArmor profile-body rules.",
        },
        SchemaField {
            path: "extensions.selinux.policy[]",
            required: false,
            example: "allow mydaemon_t self:capability sys_ptrace;",
            validation: "Non-empty SELinux policy fragment with complete statements where Intent can check them.",
            security: "Raw SELinux policy bypasses Intent's abstraction and should be replaced by native schema support when possible.",
            selinux: "Inserted into a manual policy extension section of the generated type-enforcement module.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "extensions.selinux.file_contexts[]",
            required: false,
            example: "/var/lib/mydaemon(/.*)? gen_context(system_u:object_r:mydaemon_var_lib_t,s0)",
            validation: "Non-empty SELinux file-context fragment.",
            security: "Raw SELinux file contexts should be reviewed with the corresponding raw policy.",
            selinux: "Appended to generated file-context suggestions.",
            apparmor: "Not compiled.",
        },
        SchemaField {
            path: "extensions.apparmor.rules[]",
            required: false,
            example: "capability sys_ptrace,",
            validation: "Non-empty AppArmor profile-body rule fragment; rules should terminate with commas.",
            security: "Raw AppArmor rules bypass Intent's abstraction and should be replaced by native schema support when possible.",
            selinux: "Not compiled.",
            apparmor: "Inserted into a manual rule extension section inside the generated profile.",
        },
        SchemaField {
            path: "notes[]",
            required: false,
            example: "Example policy only; paths may differ by distribution.",
            validation: "Non-empty string.",
            security: "Human review notes only; not a permission grant.",
            selinux: "Not compiled.",
            apparmor: "Not compiled.",
        },
    ]
}

fn escape_table(value: &str) -> String {
    value.replace('|', "\\|")
}

/// Top-level intent document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentDocument {
    /// Schema version declared by the document.
    pub version: u32,
    /// Application identity and launch context.
    pub application: Application,
    /// Additional cooperating executables/process domains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<Process>,
    /// Files and directories the application expects to use.
    #[serde(default, skip_serializing_if = "Storage::is_empty")]
    pub storage: Storage,
    /// Network access requested by the application.
    #[serde(default, skip_serializing_if = "Network::is_empty")]
    pub network: Network,
    /// Local IPC access requested by the application.
    #[serde(default, skip_serializing_if = "Ipc::is_empty")]
    pub ipc: Ipc,
    /// Linux capabilities requested by friendly name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Backend-specific temporary escape hatches.
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
    /// Structured SELinux-specific policy details.
    #[serde(default, skip_serializing_if = "SelinuxPolicy::is_empty")]
    pub selinux: SelinuxPolicy,
    /// Free-form maintainer notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl IntentDocument {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_with_options(ValidationOptions::default())
            .map(|_| ())
    }

    pub fn validate_with_options(
        &self,
        options: ValidationOptions,
    ) -> Result<ValidationReport, ValidationError> {
        let diagnostics = self.diagnostics();
        let has_fatal = diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == Severity::Error
                || (options.deny_warnings && diagnostic.severity == Severity::Warning)
        });

        if has_fatal {
            Err(ValidationError { diagnostics })
        } else {
            Ok(ValidationReport { diagnostics })
        }
    }

    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if self.version != CURRENT_SCHEMA_VERSION {
            diagnostics.push(
                Diagnostic::error(format!("version must be {CURRENT_SCHEMA_VERSION}"))
                    .found(self.version.to_string())
                    .help(format!("set version: {CURRENT_SCHEMA_VERSION}")),
            );
        }

        self.application.validate(&mut diagnostics);
        for (index, process) in self.processes.iter().enumerate() {
            process.validate(&mut diagnostics, index);
        }
        self.storage.validate(&mut diagnostics);
        self.network.validate(&mut diagnostics);
        self.ipc.validate(&mut diagnostics);
        self.extensions.validate(&mut diagnostics);
        self.selinux.validate(&mut diagnostics);

        for (index, capability) in self.capabilities.iter().enumerate() {
            validate_non_empty(
                &mut diagnostics,
                format!("capabilities[{index}]"),
                capability,
            );
            validate_kebab_name(
                &mut diagnostics,
                format!("capabilities[{index}]"),
                capability,
                "use developer-friendly kebab-case such as net-bind-service",
            );
        }

        for (index, note) in self.notes.iter().enumerate() {
            validate_non_empty(&mut diagnostics, format!("notes[{index}]"), note);
        }

        diagnostics
    }
}

/// Validation options used by `intent validate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidationOptions {
    pub deny_warnings: bool,
}

/// Diagnostics found while validating a syntactically parsed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
    }
}

/// A cooperating process for multi-binary applications.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub id: String,
    pub name: String,
    pub executable: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_executables: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_by: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_nnp_transition: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub permissive: bool,
}

impl Process {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>, index: usize) {
        let prefix = format!("processes[{index}]");
        validate_non_empty(diagnostics, format!("{prefix}.id"), &self.id);
        validate_kebab_name(
            diagnostics,
            format!("{prefix}.id"),
            &self.id,
            "use a stable kebab-case process id",
        );
        validate_non_empty(diagnostics, format!("{prefix}.name"), &self.name);
        validate_non_empty(
            diagnostics,
            format!("{prefix}.executable"),
            &self.executable,
        );
        validate_absolute_path(
            diagnostics,
            format!("{prefix}.executable"),
            &self.executable,
        );

        for (path_index, path) in self.additional_executables.iter().enumerate() {
            validate_absolute_path(
                diagnostics,
                format!("{prefix}.additional_executables[{path_index}]"),
                path,
            );
        }

        if let Some(role) = &self.role {
            validate_non_empty(diagnostics, format!("{prefix}.role"), role);
        }
        if let Some(started_by) = &self.started_by {
            validate_non_empty(diagnostics, format!("{prefix}.started_by"), started_by);
        }
        if let Some(domain_type) = &self.domain_type {
            validate_non_empty(diagnostics, format!("{prefix}.domain_type"), domain_type);
        }
        if let Some(exec_type) = &self.exec_type {
            validate_non_empty(diagnostics, format!("{prefix}.exec_type"), exec_type);
        }
    }
}

/// Application identity and launch context.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub executable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl Application {
    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        validate_non_empty(diagnostics, "application.name", &self.name);
        validate_non_empty(diagnostics, "application.executable", &self.executable);

        if !self.executable.starts_with('/') {
            diagnostics.push(
                Diagnostic::error("application.executable must be an absolute path")
                    .found(self.executable.clone())
                    .help(format!("use /{}", self.executable.trim_start_matches('/'))),
            );
        } else {
            validate_path(diagnostics, "application.executable", &self.executable);
        }

        if let Some(description) = &self.description {
            validate_non_empty(diagnostics, "application.description", description);
        }

        if let Some(user) = &self.user {
            validate_non_empty(diagnostics, "application.user", user);
        }

        if let Some(group) = &self.group {
            validate_non_empty(diagnostics, "application.group", group);
        }
    }
}

/// Files and directories the application expects to use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config: Vec<StoragePath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache: Vec<StoragePath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<StoragePath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime: Vec<StoragePath>,
}

impl Storage {
    pub fn is_empty(&self) -> bool {
        self.config.is_empty()
            && self.cache.is_empty()
            && self.state.is_empty()
            && self.runtime.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        validate_storage_paths(
            diagnostics,
            "storage.config",
            &self.config,
            StorageKind::Config,
        );
        validate_storage_paths(
            diagnostics,
            "storage.cache",
            &self.cache,
            StorageKind::Cache,
        );
        validate_storage_paths(
            diagnostics,
            "storage.state",
            &self.state,
            StorageKind::State,
        );
        validate_storage_paths(
            diagnostics,
            "storage.runtime",
            &self.runtime,
            StorageKind::Runtime,
        );
    }
}

/// A file or directory with a high-level access mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePath {
    pub path: String,
    pub access: StorageAccess,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
}

/// Storage access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageAccess {
    Read,
    ReadWrite,
}

impl<'de> Deserialize<'de> for StorageAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "read" => Ok(Self::Read),
            "read-write" => Ok(Self::ReadWrite),
            other => Err(de::Error::custom(format!(
                "invalid access mode '{other}'; expected read or read-write"
            ))),
        }
    }
}

impl Serialize for StorageAccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Read => "read",
            Self::ReadWrite => "read-write",
        })
    }
}

/// Network access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound: Vec<OutboundNetwork>,
}

impl Network {
    pub fn is_empty(&self) -> bool {
        self.outbound.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, outbound) in self.outbound.iter().enumerate() {
            let prefix = format!("network.outbound[{index}]");
            validate_non_empty(diagnostics, format!("{prefix}.to"), &outbound.to);

            if let Some(port) = outbound.port {
                if port == 0 {
                    diagnostics.push(
                        Diagnostic::error(format!("{prefix}.port must be between 1 and 65535"))
                            .found("0")
                            .help("use a TCP or UDP port from 1 through 65535"),
                    );
                }
            }

            if matches!(
                outbound.protocol,
                NetworkProtocol::Tcp | NetworkProtocol::Udp
            ) && outbound.port.is_none()
            {
                diagnostics.push(
                    Diagnostic::error(format!(
                        "{prefix}.port is required when protocol is tcp or udp"
                    ))
                    .help("add a port field, for example port: 443"),
                );
            }
        }
    }
}

/// An outbound network destination.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundNetwork {
    pub to: String,
    pub protocol: NetworkProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<String>,
}

/// Developer-facing network protocol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Http,
    Https,
    Tcp,
    Udp,
}

impl<'de> Deserialize<'de> for NetworkProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(de::Error::custom(format!(
                "unknown network protocol '{other}'; expected http, https, tcp, or udp"
            ))),
        }
    }
}

impl Serialize for NetworkProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Local IPC access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ipc {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_sockets: Vec<UnixSocket>,
    #[serde(default, skip_serializing_if = "Dbus::is_empty")]
    pub dbus: Dbus,
}

impl Ipc {
    pub fn is_empty(&self) -> bool {
        self.unix_sockets.is_empty() && self.dbus.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, socket) in self.unix_sockets.iter().enumerate() {
            let prefix = format!("ipc.unix_sockets[{index}]");
            validate_non_empty(diagnostics, format!("{prefix}.path"), &socket.path);

            if !socket.path.starts_with('/') {
                diagnostics.push(
                    Diagnostic::error(format!("{prefix}.path must be an absolute path"))
                        .found(socket.path.clone())
                        .help(format!("use /{}", socket.path.trim_start_matches('/'))),
                );
            } else {
                validate_path(diagnostics, format!("{prefix}.path"), &socket.path);
            }
        }

        self.dbus.validate(diagnostics);
    }
}

/// A Unix domain socket used by the application.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixSocket {
    pub path: String,
    pub mode: UnixSocketMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<String>,
}

/// Structured SELinux-specific policy details.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<SelinuxType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<SelinuxRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<SelinuxTransition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allows: Vec<SelinuxAllow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub macro_calls: Vec<SelinuxMacroCall>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem_associations: Vec<SelinuxFilesystemAssociation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissive: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contexts: Vec<SelinuxFileContext>,
}

impl SelinuxPolicy {
    pub fn is_empty(&self) -> bool {
        self.compatibility.is_none()
            && self.types.is_empty()
            && self.roles.is_empty()
            && self.transitions.is_empty()
            && self.allows.is_empty()
            && self.macro_calls.is_empty()
            && self.filesystem_associations.is_empty()
            && self.permissive.is_empty()
            && self.file_contexts.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, entry) in self.types.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.types[{index}].name"),
                &entry.name,
            );
        }
        for (index, entry) in self.roles.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.roles[{index}].role"),
                &entry.role,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.roles[{index}].domain"),
                &entry.domain,
            );
        }
        for (index, entry) in self.transitions.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.transitions[{index}].source"),
                &entry.source,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.transitions[{index}].exec_type"),
                &entry.exec_type,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.transitions[{index}].target"),
                &entry.target,
            );
        }
        for (index, entry) in self.allows.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.allows[{index}].source"),
                &entry.source,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.allows[{index}].target"),
                &entry.target,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.allows[{index}].class"),
                &entry.class,
            );
            if entry.permissions.is_empty() {
                diagnostics.push(
                    Diagnostic::error(format!(
                        "selinux.allows[{index}].permissions must not be empty"
                    ))
                    .help("add one or more SELinux permissions"),
                );
            }
        }
        for (index, entry) in self.macro_calls.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.macro_calls[{index}].name"),
                &entry.name,
            );
        }
        for (index, entry) in self.filesystem_associations.iter().enumerate() {
            validate_non_empty(
                diagnostics,
                format!("selinux.filesystem_associations[{index}].type_name"),
                &entry.type_name,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.filesystem_associations[{index}].filesystem_type"),
                &entry.filesystem_type,
            );
        }
        for (index, entry) in self.file_contexts.iter().enumerate() {
            validate_absolute_path(
                diagnostics,
                format!("selinux.file_contexts[{index}].path"),
                &entry.path,
            );
            validate_non_empty(
                diagnostics,
                format!("selinux.file_contexts[{index}].type_name"),
                &entry.type_name,
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxType {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxRole {
    pub role: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxTransition {
    pub source: String,
    pub exec_type: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxAllow {
    pub source: String,
    pub target: String,
    pub class: String,
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxMacroCall {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxFilesystemAssociation {
    pub type_name: String,
    pub filesystem_type: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelinuxFileContext {
    pub path: String,
    pub type_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
}

/// Whether the application creates or connects to a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixSocketMode {
    Server,
    Client,
}

impl<'de> Deserialize<'de> for UnixSocketMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            other => Err(de::Error::custom(format!(
                "invalid socket mode '{other}'; expected server or client"
            ))),
        }
    }
}

impl Serialize for UnixSocketMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Server => "server",
            Self::Client => "client",
        })
    }
}

/// D-Bus access requested by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dbus {
    #[serde(default, skip_serializing_if = "SystemBus::is_empty")]
    pub system: SystemBus,
}

impl Dbus {
    pub fn is_empty(&self) -> bool {
        self.system.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        self.system.validate(diagnostics);
    }
}

/// System bus names owned or contacted by the application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemBus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub talks_to: Vec<String>,
}

impl SystemBus {
    pub fn is_empty(&self) -> bool {
        self.owns.is_empty() && self.talks_to.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, name) in self.owns.iter().enumerate() {
            validate_dbus_name(diagnostics, format!("ipc.dbus.system.owns[{index}]"), name);
        }

        for (index, name) in self.talks_to.iter().enumerate() {
            validate_dbus_name(
                diagnostics,
                format!("ipc.dbus.system.talks_to[{index}]"),
                name,
            );
        }
    }
}

/// Backend-specific temporary policy fragments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "SelinuxExtensions::is_empty")]
    pub selinux: SelinuxExtensions,
    #[serde(default, skip_serializing_if = "AppArmorExtensions::is_empty")]
    pub apparmor: AppArmorExtensions,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_yaml::Value>,
}

impl Extensions {
    pub fn is_empty(&self) -> bool {
        self.selinux.is_empty() && self.apparmor.is_empty() && self.unknown.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        self.selinux.validate(diagnostics);
        self.apparmor.validate(diagnostics);

        for name in self.unknown.keys() {
            diagnostics.push(
                Diagnostic::warning(format!("extensions.{name} is not recognized"))
                    .help("unknown extension blocks are preserved but not compiled"),
            );
        }
    }
}

/// SELinux-specific escape hatches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SelinuxExtensions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_contexts: Vec<String>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_yaml::Value>,
}

impl SelinuxExtensions {
    pub fn is_empty(&self) -> bool {
        self.policy.is_empty() && self.file_contexts.is_empty() && self.unknown.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, fragment) in self.policy.iter().enumerate() {
            validate_policy_fragment(
                diagnostics,
                format!("extensions.selinux.policy[{index}]"),
                fragment,
                BackendSyntax::Selinux,
            );
        }

        for (index, fragment) in self.file_contexts.iter().enumerate() {
            validate_policy_fragment(
                diagnostics,
                format!("extensions.selinux.file_contexts[{index}]"),
                fragment,
                BackendSyntax::SelinuxFileContexts,
            );
        }

        for name in self.unknown.keys() {
            diagnostics.push(
                Diagnostic::warning(format!("extensions.selinux.{name} is not recognized"))
                    .help("unknown SELinux extension blocks are preserved but not compiled"),
            );
        }
    }
}

/// AppArmor-specific escape hatches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct AppArmorExtensions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_yaml::Value>,
}

impl AppArmorExtensions {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.unknown.is_empty()
    }

    fn validate(&self, diagnostics: &mut Vec<Diagnostic>) {
        for (index, fragment) in self.rules.iter().enumerate() {
            validate_policy_fragment(
                diagnostics,
                format!("extensions.apparmor.rules[{index}]"),
                fragment,
                BackendSyntax::AppArmor,
            );
        }

        for name in self.unknown.keys() {
            diagnostics.push(
                Diagnostic::warning(format!("extensions.apparmor.{name} is not recognized"))
                    .help("unknown AppArmor extension blocks are preserved but not compiled"),
            );
        }
    }
}

/// Validation failures found after a document was syntactically parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{diagnostic}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug, Clone, Copy)]
enum StorageKind {
    Config,
    Cache,
    State,
    Runtime,
}

#[derive(Debug, Clone, Copy)]
enum BackendSyntax {
    Selinux,
    SelinuxFileContexts,
    AppArmor,
}

fn validate_policy_fragment(
    diagnostics: &mut Vec<Diagnostic>,
    field: String,
    fragment: &str,
    syntax: BackendSyntax,
) {
    validate_non_empty(diagnostics, &field, fragment);

    if fragment.contains('\0') {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain NUL bytes"))
                .found("<contains NUL byte>"),
        );
    }

    let meaningful_lines = fragment
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();

    if meaningful_lines.is_empty() {
        return;
    }

    match syntax {
        BackendSyntax::Selinux => validate_selinux_fragment(diagnostics, &field, &meaningful_lines),
        BackendSyntax::SelinuxFileContexts => {
            validate_selinux_file_context_fragment(diagnostics, &field, &meaningful_lines)
        }
        BackendSyntax::AppArmor => {
            validate_apparmor_fragment(diagnostics, &field, &meaningful_lines)
        }
    }
}

fn validate_selinux_fragment(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    meaningful_lines: &[&str],
) {
    let body = meaningful_lines.join("\n");

    if !body.ends_with(';') && !body.ends_with(')') && !body.ends_with('}') {
        diagnostics.push(
            Diagnostic::error(format!("{field} must contain complete SELinux statements"))
                .found(body.clone())
                .help("terminate allow/type rules with ';', policy macros with ')', or blocks with '}'"),
        );
    }

    validate_balanced_delimiters(diagnostics, field, &body, '{', '}');
    validate_balanced_delimiters(diagnostics, field, &body, '(', ')');
}

fn validate_selinux_file_context_fragment(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    meaningful_lines: &[&str],
) {
    for line in meaningful_lines {
        if !line.contains("gen_context(") {
            diagnostics.push(
                Diagnostic::warning(format!("{field} may not be a SELinux file-context entry"))
                    .found(*line)
                    .help("expected a line containing gen_context(...)"),
            );
        }
    }

    let body = meaningful_lines.join("\n");
    validate_balanced_delimiters(diagnostics, field, &body, '(', ')');
}

fn validate_apparmor_fragment(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    meaningful_lines: &[&str],
) {
    for line in meaningful_lines {
        if line.starts_with("profile ") {
            diagnostics.push(
                Diagnostic::error(format!("{field} must contain AppArmor profile-body rules only"))
                    .found(*line)
                    .help("omit the profile declaration; Intent inserts rules inside the generated profile"),
            );
        }

        if !line.ends_with(',') && !line.ends_with('{') && !line.ends_with('}') {
            diagnostics.push(
                Diagnostic::error(format!("{field} must contain complete AppArmor rules"))
                    .found(*line)
                    .help("terminate AppArmor rules with ','"),
            );
        }
    }

    let body = meaningful_lines.join("\n");
    validate_balanced_delimiters(diagnostics, field, &body, '(', ')');
    validate_balanced_delimiters(diagnostics, field, &body, '{', '}');
}

fn validate_balanced_delimiters(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    body: &str,
    open: char,
    close: char,
) {
    let mut depth = 0usize;

    for ch in body.chars() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            if depth == 0 {
                diagnostics.push(
                    Diagnostic::error(format!("{field} has an unmatched '{close}'"))
                        .help("check the manual policy fragment syntax"),
                );
                return;
            }
            depth -= 1;
        }
    }

    if depth > 0 {
        diagnostics.push(
            Diagnostic::error(format!("{field} has an unmatched '{open}'"))
                .help("check the manual policy fragment syntax"),
        );
    }
}

fn validate_storage_paths(
    diagnostics: &mut Vec<Diagnostic>,
    field: &str,
    paths: &[StoragePath],
    kind: StorageKind,
) {
    for (index, entry) in paths.iter().enumerate() {
        let prefix = format!("{field}[{index}]");
        validate_non_empty(diagnostics, format!("{prefix}.path"), &entry.path);

        if !entry.path.starts_with('/') {
            diagnostics.push(
                Diagnostic::error(format!("{prefix}.path must be an absolute path"))
                    .found(entry.path.clone())
                    .help(format!("use /{}", entry.path.trim_start_matches('/'))),
            );
            continue;
        }

        validate_path(diagnostics, format!("{prefix}.path"), &entry.path);

        let broad_path = trim_trailing_slashes(&entry.path);
        if matches!(broad_path.as_str(), "/" | "/etc" | "/var" | "/usr") {
            diagnostics.push(
                Diagnostic::warning(format!("{prefix}.path is very broad"))
                    .found(entry.path.clone())
                    .help("declare the narrowest application-specific directory instead"),
            );
        }

        match kind {
            StorageKind::Config => {}
            StorageKind::Runtime => {
                if !is_under(&entry.path, "/run") && !is_under(&entry.path, "/var/run") {
                    diagnostics.push(
                        Diagnostic::error(format!(
                            "{prefix}.path must be under /run or /var/run for runtime storage"
                        ))
                        .found(entry.path.clone())
                        .help("move runtime files to /run/<application>"),
                    );
                }
            }
            StorageKind::Cache => {
                validate_expected_storage_root(
                    diagnostics,
                    &prefix,
                    &entry.path,
                    entry.justification.as_deref(),
                    "/var/cache",
                    "cache",
                    "move cache files to /var/cache/<application> or add justification",
                );
            }
            StorageKind::State => {
                validate_expected_storage_root(
                    diagnostics,
                    &prefix,
                    &entry.path,
                    entry.justification.as_deref(),
                    "/var/lib",
                    "state",
                    "move state files to /var/lib/<application> or add justification",
                );
            }
        }
    }
}

fn validate_dbus_name(diagnostics: &mut Vec<Diagnostic>, field: String, name: &str) {
    validate_non_empty(diagnostics, &field, name);

    if name.trim().is_empty() {
        return;
    }

    if !is_valid_dbus_name(name) {
        diagnostics.push(
            Diagnostic::error(format!("{field} must be a valid D-Bus well-known name"))
                .found(name.to_string())
                .help("use a dotted name such as org.example.Service"),
        );
    }
}

fn validate_non_empty(diagnostics: &mut Vec<Diagnostic>, field: impl AsRef<str>, value: &str) {
    if value.trim().is_empty() {
        diagnostics.push(Diagnostic::error(format!(
            "{} must not be empty",
            field.as_ref()
        )));
    }
}

fn validate_kebab_name(diagnostics: &mut Vec<Diagnostic>, field: String, value: &str, help: &str) {
    if value.is_empty() {
        return;
    }

    let valid = value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--");

    if !valid {
        diagnostics.push(
            Diagnostic::error(format!("{field} must be kebab-case"))
                .found(value.to_string())
                .help(help),
        );
    }
}

fn validate_absolute_path(diagnostics: &mut Vec<Diagnostic>, field: String, path: &str) {
    validate_non_empty(diagnostics, &field, path);

    if !path.starts_with('/') {
        diagnostics.push(
            Diagnostic::error(format!("{field} must be an absolute path"))
                .found(path.to_string())
                .help(format!("use /{}", path.trim_start_matches('/'))),
        );
    } else {
        validate_path(diagnostics, field, path);
    }
}

fn validate_path(diagnostics: &mut Vec<Diagnostic>, field: impl AsRef<str>, path: &str) {
    let field = field.as_ref();

    if path.contains('\0') {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain NUL bytes"))
                .found(path.to_string()),
        );
    }

    if path.lines().count() > 1 {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain line breaks"))
                .found(path.to_string())
                .help("keep paths on one line"),
        );
    }

    if path
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        diagnostics.push(
            Diagnostic::error(format!("{field} must not contain . or .. path components"))
                .found(path.to_string())
                .help("use a normalized absolute path"),
        );
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_expected_storage_root(
    diagnostics: &mut Vec<Diagnostic>,
    prefix: &str,
    path: &str,
    justification: Option<&str>,
    expected_root: &str,
    kind: &str,
    help: &str,
) {
    if is_under(path, expected_root) {
        return;
    }

    if justification.is_some_and(|value| !value.trim().is_empty()) {
        return;
    }

    diagnostics.push(
        Diagnostic::warning(format!(
            "{prefix}.path is outside {expected_root} for {kind} storage"
        ))
        .found(path.to_string())
        .help(help),
    );
}

fn is_under(path: &str, expected_root: &str) -> bool {
    let path = trim_trailing_slashes(path);
    path == expected_root || path.starts_with(&format!("{expected_root}/"))
}

fn trim_trailing_slashes(path: &str) -> String {
    if path == "/" {
        return path.to_string();
    }

    path.trim_end_matches('/').to_string()
}

fn is_valid_dbus_name(name: &str) -> bool {
    if name.len() > 255 || !name.contains('.') || name.starts_with('.') || name.ends_with('.') {
        return false;
    }

    name.split('.').all(|part| {
        let Some(first) = part.chars().next() else {
            return false;
        };

        !first.is_ascii_digit()
            && part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> IntentDocument {
        serde_yaml::from_str(value).expect("intent yaml should parse")
    }

    #[test]
    fn accepts_minimal_document() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
"#,
        );

        assert!(document.validate().is_ok());
        assert_eq!(document.storage.config, Vec::new());
    }

    #[test]
    fn accepts_supported_fields() {
        let document = parse(
            r#"
version: 1
application:
  name: himmelblaud
  description: Entra ID login daemon
  executable: /usr/libexec/himmelblaud
  user: root
  group: root
storage:
  config:
    - path: /etc/himmelblaud
      access: read
  cache:
    - path: /var/cache/himmelblaud
      access: read-write
  state:
    - path: /var/lib/himmelblaud
      access: read-write
  runtime:
    - path: /run/himmelblaud
      access: read-write
network:
  outbound:
    - to: login.microsoftonline.com
      protocol: https
ipc:
  unix_sockets:
    - path: /run/himmelblaud/socket
      mode: server
  dbus:
    system:
      owns:
        - org.freedesktop.resolve1
      talks_to:
        - org.freedesktop.DBus
capabilities:
  - net-bind-service
notes:
  - Example only.
"#,
        );

        assert!(document.validate().is_ok());
        assert_eq!(
            document.network.outbound[0].protocol,
            NetworkProtocol::Https
        );
        assert_eq!(document.ipc.unix_sockets[0].mode, UnixSocketMode::Server);
    }

    #[test]
    fn rejects_invalid_values_with_helpful_errors() {
        let document = parse(
            r#"
version: 99
application:
  name: " "
  executable: usr/bin/demo
storage:
  config:
    - path: relative/path
      access: read
network:
  outbound:
    - to: ""
      protocol: tcp
      port: 0
ipc:
  unix_sockets:
    - path: socket
      mode: client
  dbus:
    system:
      owns:
        - invalid
capabilities:
  - CAP_SYS_ADMIN
notes:
  - ""
"#,
        );

        let error = document.validate().expect_err("document should be invalid");
        let message = error.to_string();

        assert!(message.contains("version must be 1"));
        assert!(message.contains("application.name must not be empty"));
        assert!(message.contains("application.executable must be an absolute path"));
        assert!(message.contains("storage.config[0].path must be an absolute path"));
        assert!(message.contains("network.outbound[0].to must not be empty"));
        assert!(message.contains("network.outbound[0].port must be between 1 and 65535"));
        assert!(message.contains("ipc.unix_sockets[0].path must be an absolute path"));
        assert!(message.contains("ipc.dbus.system.owns[0] must be a valid D-Bus"));
        assert!(message.contains("capabilities[0] must be kebab-case"));
        assert!(message.contains("notes[0] must not be empty"));
    }

    #[test]
    fn warns_for_suspicious_broad_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  config:
    - path: /etc
      access: read
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        let message = report
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(message.contains("warning: storage.config[0].path is very broad"));
        assert!(document
            .validate_with_options(ValidationOptions {
                deny_warnings: true
            })
            .is_err());
    }

    #[test]
    fn rejects_invalid_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/../bin/demo
storage:
  config:
    - path: /etc/demo/./config
      access: read
"#,
        );

        let message = document
            .validate()
            .expect_err("invalid paths should fail")
            .to_string();

        assert!(message.contains("application.executable must not contain . or .."));
        assert!(message.contains("storage.config[0].path must not contain . or .."));
        assert!(message.contains("help: use a normalized absolute path"));
    }

    #[test]
    fn rejects_runtime_paths_outside_runtime_roots() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  runtime:
    - path: /tmp/demo
      access: read-write
"#,
        );

        let message = document
            .validate()
            .expect_err("runtime path outside /run should fail")
            .to_string();

        assert!(message.contains("storage.runtime[0].path must be under /run or /var/run"));
    }

    #[test]
    fn warns_for_unjustified_cache_and_state_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  cache:
    - path: /opt/demo/cache
      access: read-write
  state:
    - path: /srv/demo/state
      access: read-write
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        let message = report
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(message.contains("warning: storage.cache[0].path is outside /var/cache"));
        assert!(message.contains("warning: storage.state[0].path is outside /var/lib"));
    }

    #[test]
    fn accepts_justified_cache_and_state_paths() {
        let document = parse(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
storage:
  cache:
    - path: /opt/demo/cache
      access: read-write
      justification: vendor package layout
  state:
    - path: /srv/demo/state
      access: read-write
      justification: shared service data
"#,
        );

        let report = document
            .validate_with_options(ValidationOptions::default())
            .unwrap();
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = serde_yaml::from_str::<IntentDocument>(
            r#"
version: 1
application:
  name: demo
  executable: /usr/bin/demo
unexpected: true
"#,
        )
        .expect_err("unknown field should fail");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn generated_markdown_matches_checked_in_docs() {
        assert_eq!(
            markdown_documentation(),
            include_str!("../docs/intent-yaml.md")
        );
    }

    #[test]
    fn generated_json_schema_matches_checked_in_schema() {
        serde_yaml::from_str::<serde_yaml::Value>(json_schema())
            .expect("json schema should parse as yaml/json");
        assert_eq!(json_schema(), include_str!("../schema/intent.schema.json"));
    }
}
