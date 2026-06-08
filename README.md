# Intent

Intent is a declarative security policy compiler for Linux.

The project aims to let application developers describe what their software
needs to do in a plain, heavily documented `intent.yaml` file. Intent will then
compile that high-level intent into platform-specific security policies,
initially SELinux policy and AppArmor profiles.

## Problem

Linux mandatory access control systems are powerful, but their policy languages
are specialized and difficult for many application developers to write by hand.
That creates a gap: the people who understand an application best often cannot
easily express the least-privilege policy it needs, while security engineers
must reverse-engineer application behavior from documentation, source code, and
audit logs.

Intent is intended to make that workflow more direct:

- Developers describe application behavior in `intent.yaml`.
- Intent validates the declared behavior against a simple schema.
- Intent compiles the declaration into SELinux and AppArmor outputs.
- Intent reads SELinux and AppArmor audit logs and suggests higher-level intent
  entries that can be reviewed and added to `intent.yaml`.

## Current Status

This repository currently contains the first `intent.yaml` schema, YAML parsing,
validation, initial SELinux and AppArmor compiler backends, and audit-log
observation that suggests reviewable intent additions.

## Example `intent.yaml`

```yaml
version: 1

application:
  name: my-service
  description: Small service that calls an HTTPS API
  executable: /usr/bin/my-service
  user: my-service
  group: my-service

storage:
  config:
    - path: /etc/my-service
      access: read
  state:
    - path: /var/lib/my-service
      access: read-write

network:
  outbound:
    - to: api.example.com
      protocol: https

ipc:
  unix_sockets:
    - path: /run/my-service/control.sock
      mode: server
  dbus:
    system:
      talks_to:
        - org.freedesktop.DBus

capabilities:
  - net-bind-service

notes:
  - Keep this file focused on application behavior, not SELinux or AppArmor details.
```

## CLI

```sh
intent validate <intent.yaml>
intent build <intent.yaml> --target selinux|apparmor|all [--output <dir>]
intent observe --source <audit.log> --format selinux|apparmor
intent explain <intent.yaml>
intent schema [--format markdown|json-schema]
```

Schema documentation is also checked in at `docs/intent-yaml.md`, with a JSON
Schema at `schema/intent.schema.json`.

## AppArmor Build Example

Print an AppArmor profile to stdout:

```sh
intent build examples/himmelblaud.intent.yaml --target apparmor
```

Write the generated profile to `build/himmelblaud.apparmor`:

```sh
intent build examples/himmelblaud.intent.yaml --target apparmor --output build/
```

## SELinux Build Example

Print a reviewable SELinux type-enforcement module to stdout:

```sh
intent build examples/himmelblaud.intent.yaml --target selinux
```

Write the generated module and suggested file contexts to `build/himmelblaud.te` and `build/himmelblaud.fc`:

```sh
intent build examples/himmelblaud.intent.yaml --target selinux --output build/
```

## Audit Observation

Intent can inspect SELinux AVC logs or AppArmor denial logs and suggest
high-level `intent.yaml` additions:

```sh
intent observe --source tests/fixtures/selinux_audit.log --format selinux
intent observe --source tests/fixtures/apparmor_audit.log --format apparmor
```

For a guided review, add `--interactive`. Accepted suggestions are written to
`intent.suggestions.yaml` by default:

```sh
intent observe --source tests/fixtures/selinux_audit.log --format selinux --interactive
```

To merge accepted suggestions directly into an existing intent document, pass
`--merge-into`. Intent writes a `.bak` copy before modifying the file:

```sh
intent observe --source tests/fixtures/selinux_audit.log --format selinux --interactive --merge-into intent.yaml
```

Observation is deliberately not an `audit2allow` clone. Intent does not turn
audit records directly into SELinux allow rules or AppArmor profile entries.
Audit logs describe what was denied at a platform-specific enforcement layer;
they do not prove that the behavior is desirable, least-privilege, or portable
between MAC systems. Intent keeps the workflow as:

```text
audit denial -> inferred intent -> human review -> regenerated policy
```

That means denied file access might become a reviewed `storage.config`,
`storage.cache`, `storage.state`, or `storage.runtime` entry; denied outbound
network connects might become `network.outbound`; and denied Unix socket
operations might become `ipc.unix_sockets`. After review, rebuilding from
`intent.yaml` regenerates the platform-specific policy.

## Development

Build and test the project with Cargo:

```sh
cargo test
```
