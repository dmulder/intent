# Intent

Intent is an experimental declarative Linux security policy compiler.

It lets developers describe what an application is trying to do, then compiles
that declaration into reviewable SELinux, AppArmor, and related policy
artifacts.

Generated policy is not automatically secure. Intent is meant to make security
intent easier to express, discuss, review, and regenerate. The generated output
should be treated as a starting point for human review, testing, and hardening.

## What is Intent?

Intent is a command-line tool and schema for writing application security intent
in `intent.yaml`.

Instead of starting with low-level policy rules, an `intent.yaml` describes
application behavior:

- which executable runs
- which user and group it runs as
- which configuration, state, cache, and runtime paths it uses
- which outbound network destinations it needs
- which Unix sockets and D-Bus services it uses
- which Linux capabilities are part of the application design

Intent validates that document, normalizes it into an internal representation,
and emits platform-specific artifacts such as SELinux type-enforcement modules,
SELinux file contexts, AppArmor profiles, and advisory systemd hardening
drop-ins.

## Why does this exist?

SELinux and AppArmor are powerful, but their policy languages operate at a low
level. They describe labels, types, classes, path rules, permissions, and
kernel-mediated access checks.

Most developers do not think about their software that way. They think in terms
of application intent:

- "This service reads configuration from `/etc/my-service`."
- "This daemon writes state under `/var/lib/my-service`."
- "This process listens on one Unix socket."
- "This application connects to an HTTPS API."

That mismatch creates a difficult workflow. Developers know what the application
is supposed to do, while security engineers often have to infer that behavior
from source code, packaging, operational knowledge, and audit logs.

Existing tools can help, but many denial-driven workflows translate audit
denials directly into allow rules. That can be useful for debugging, but a
denial only says what the program tried to do. It does not explain why the
access happened, whether it was expected, whether it is portable across policy
systems, or whether it should be allowed.

Intent tries to keep the higher-level reason in the loop:

```text
application behavior -> declared intent -> generated policy -> audit feedback -> reviewed intent
```

The goal is not to hide SELinux or AppArmor. The goal is to give developers and
reviewers a clearer artifact to discuss before low-level policy is accepted.

## What Intent is not

Intent is not a security guarantee.

It is also not:

- a replacement for SELinux or AppArmor expertise
- a proof that generated policy is least-privilege
- an `audit2allow` clone
- a tool for blindly granting everything seen in audit logs
- a complete model of every Linux security mechanism
- production-ready policy generation for arbitrary services

Intent should help explain and review policy. It should not remove review.

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
  runtime:
    - path: /run/my-service
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

## Manual policy escape hatches

Intent includes explicit backend escape hatches for uncommon cases that the
schema cannot model yet:

```yaml
extensions:
  selinux:
    policy:
      - |
        allow mydaemon_t self:capability sys_ptrace;

  apparmor:
    rules:
      - |
        capability sys_ptrace,
```

Manual fragments are preserved when Intent loads and saves YAML, validated for
basic backend syntax where possible, and inserted into the generated SELinux or
AppArmor policy section with comments that identify them as manual extensions.
Use them as temporary workarounds until Intent gains native fields for the
behavior.

Validate a document:

```sh
cargo run -- validate examples/minimal.intent.yaml
```

Print a human-readable explanation of the normalized intent:

```sh
cargo run -- explain examples/minimal.intent.yaml
```

## Build SELinux policy

Print a reviewable SELinux type-enforcement module and file-context rules:

```sh
cargo run -- build examples/himmelblau/intent.yaml --target selinux
```

Write the generated files to a directory:

```sh
cargo run -- build examples/himmelblau/intent.yaml --target selinux --output build/
```

This writes files such as:

- `build/himmelblaud.te`
- `build/himmelblaud.fc`

Review the generated SELinux output before using it. The compiler currently
models only the parts of application behavior represented by the Intent schema.

## Build AppArmor profile

Print a reviewable AppArmor profile:

```sh
cargo run -- build examples/himmelblau/intent.yaml --target apparmor
```

Write the generated profile to a directory:

```sh
cargo run -- build examples/himmelblau/intent.yaml --target apparmor --output build/
```

This writes a file such as:

- `build/himmelblaud.apparmor`

Review the generated profile before loading it. Path-based policy still needs
careful validation against the real package layout, runtime behavior, and host
environment.

## Observe audit logs

Intent can inspect SELinux AVC logs or AppArmor denial logs and suggest
higher-level `intent.yaml` additions:

```sh
cargo run -- observe --source tests/fixtures/selinux_audit.log --format selinux
cargo run -- observe --source tests/fixtures/apparmor_audit.log --format apparmor
```

For a guided review, use `--interactive`:

```sh
cargo run -- observe --source tests/fixtures/selinux_audit.log --format selinux --interactive
```

Accepted suggestions are written to `intent.suggestions.yaml` by default. To
merge accepted suggestions into an existing intent document:

```sh
cargo run -- observe --source tests/fixtures/selinux_audit.log --format selinux --interactive --merge-into intent.yaml
```

Intent writes a `.bak` copy before modifying the target file.

Observation deliberately keeps a review step between denial and policy:

```text
audit denial -> inferred intent -> human review -> regenerated policy
```

An audit event means access was denied. It does not mean the access was
intended, appropriate, portable, or safe to allow.

## Suggested workflow

1. Write an initial `intent.yaml` from what the application is supposed to do.
2. Validate it with `cargo run -- validate <intent.yaml>`.
3. Generate SELinux, AppArmor, or systemd output with `cargo run -- build`.
4. Review the generated artifacts as policy drafts.
5. Test the application under enforcement in a controlled environment.
6. Feed relevant audit logs into `cargo run -- observe`.
7. Review each suggested intent change before accepting it.
8. Regenerate policy from the reviewed `intent.yaml`.
9. Keep the intent file in source control with the application or packaging.

The important artifact is the reviewed intent, not the raw denial stream.

## Current limitations

Intent is early and incomplete. Current limitations include:

- the schema models a narrow set of daemon-style application behavior
- generated SELinux and AppArmor output is a compiler snapshot, not final policy
- some SELinux details are distribution-specific and cannot be inferred safely
- AppArmor path rules depend on the real installed filesystem layout
- network intent is higher-level than what every backend can enforce directly
- D-Bus, PAM/NSS, resolver, certificate, TPM, and system integration are only
  partially represented
- multi-process applications and helper domains need richer modeling
- audit observation can miss context or infer the wrong high-level reason

Use the output for review and iteration, not as a blanket permission grant.

## Project status

Intent currently includes:

- an `intent.yaml` schema
- YAML parsing and validation
- normalized internal representation output via `explain`
- SELinux policy generation
- AppArmor profile generation
- advisory systemd hardening drop-in generation
- SELinux and AppArmor audit-log observation
- snapshot and regression tests

The project is experimental. Interfaces, schema fields, generated output, and
review workflows may change as the model improves.

## Contributing

Contributions are welcome, especially in areas that make intent clearer and
review safer:

- schema improvements that capture real application behavior without leaking
  backend-specific policy syntax into `intent.yaml`
- compiler fixes for SELinux, AppArmor, and systemd output
- audit-observation improvements that explain why a suggestion was made
- realistic examples with documented gaps
- tests that prevent accidental broadening of generated policy

Before sending changes, run:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

If an intentional compiler, validation, or observer change updates generated
output, refresh and review the snapshots:

```sh
UPDATE_SNAPSHOTS=1 cargo test
git diff -- tests/snapshots
```

Only commit snapshot changes that match the intended behavior change.
