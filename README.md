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

This repository currently contains the initial project skeleton. The CLI parses
the planned command structure and returns useful placeholder output, but policy
generation and audit-log analysis are not implemented yet.

## Planned CLI

```sh
intent validate <intent.yaml>
intent build <intent.yaml> --target selinux|apparmor|all
intent observe --source <audit.log> --format selinux|apparmor
intent explain <intent.yaml>
```

## Development

Build and test the project with Cargo:

```sh
cargo test
```
