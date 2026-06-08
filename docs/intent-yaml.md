# intent.yaml

Intent files describe what a Linux application needs to do. Keep them small, readable, and focused on application behavior rather than SELinux or AppArmor policy syntax.

## Example

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
```

## Fields

| Field | Required | Example | Validation | Security notes | Backend support |
| --- | --- | --- | --- | --- | --- |
| `version` | yes | `1` | Must equal the current schema version, 1. | Makes future schema changes explicit during review. | SELinux: Used only by Intent validation.<br>AppArmor: Used only by Intent validation. |
| `application` | yes | `application: ...` | Object. Unknown fields are rejected. | Defines the process identity Intent protects. | SELinux: Drives module, domain, and executable type names.<br>AppArmor: Drives profile name and executable attachment. |
| `application.name` | yes | `my-service` | Non-empty string. | Use a stable package or service name so generated policy remains reviewable. | SELinux: Used in generated type and module names.<br>AppArmor: Used as the generated profile name. |
| `application.description` | no | `Small service that calls an HTTPS API` | Non-empty string when present. | Documentation for reviewers; not a permission grant. | SELinux: Not compiled.<br>AppArmor: Not compiled. |
| `application.executable` | yes | `/usr/bin/my-service` | Absolute, normalized, one-line path. | Choose the real executable entry point, not a broad directory. | SELinux: Labels the executable and creates the application domain transition target.<br>AppArmor: Attaches the profile to this executable path. |
| `application.user` | no | `my-service` | Non-empty string when present. | Documents the expected Unix account; omit for per-user apps. | SELinux: Documented in generated comments only.<br>AppArmor: Documented in generated comments only. |
| `application.group` | no | `my-service` | Non-empty string when present. | Documents the expected Unix group; omit when not fixed. | SELinux: Documented in generated comments only.<br>AppArmor: Documented in generated comments only. |
| `storage` | no | `storage: ...` | Object. Omit when no storage access is needed. | Declare storage by purpose so reviewers can spot overbroad paths. | SELinux: Generates file allow rules and file-context suggestions.<br>AppArmor: Generates path rules. |
| `storage.config[]` | no | `{ path: /etc/my-service, access: read }` | Non-empty list of storage entries. | Use read-only access for administrator or package-provided configuration. | SELinux: Generates read or write file permissions for declared paths.<br>AppArmor: Generates `r` or `rw` path permissions. |
| `storage.cache[]` | no | `{ path: /var/cache/my-service, access: read-write }` | Non-empty list. Warns outside /var/cache unless justified. | Cache should be disposable and narrow to the application. | SELinux: Generates file permissions and file contexts for cache paths.<br>AppArmor: Generates path permissions. |
| `storage.state[]` | no | `{ path: /var/lib/my-service, access: read-write }` | Non-empty list. Warns outside /var/lib unless justified. | State is persistent application-owned data; keep it application-specific. | SELinux: Generates file permissions and file contexts for state paths.<br>AppArmor: Generates path permissions. |
| `storage.runtime[]` | no | `{ path: /run/my-service, access: read-write }` | Non-empty list. Path must be under /run or /var/run. | Runtime paths should be short-lived sockets, pid files, and similar data. | SELinux: Generates file permissions and file contexts for runtime paths.<br>AppArmor: Generates path permissions. |
| `storage.*[].path` | yes | `/var/lib/my-service` | Absolute, normalized, one-line path; broad roots warn. | Declare the narrowest file or directory the application needs. | SELinux: Used in file-context suggestions and file allow rules.<br>AppArmor: Used directly in path rules. |
| `storage.*[].access` | yes | `read-write` | Must be read or read-write. | Prefer read unless the application must create or modify data. | SELinux: Maps to read-only or read/write file permissions.<br>AppArmor: Maps to `r` or `rw` path permissions. |
| `storage.*[].justification` | no | `vendor package layout` | Non-empty string when present. | Explain exceptions such as cache outside /var/cache or state outside /var/lib. | SELinux: Not compiled.<br>AppArmor: Not compiled. |
| `network` | no | `network: ...` | Object. Omit when no network access is needed. | Declare only outbound destinations the application initiates. | SELinux: Generates coarse network permissions for supported protocols.<br>AppArmor: Generates network rules for supported protocols. |
| `network.outbound[]` | no | `{ to: api.example.com, protocol: https }` | Non-empty list of outbound entries. | Keep destinations specific enough for human review. | SELinux: Destination is documented; protocol influences generated allow rules.<br>AppArmor: Protocol influences generated network rules; destination is documented. |
| `network.outbound[].to` | yes | `api.example.com` | Non-empty string. | Use a meaningful DNS name, host, network, or service label. | SELinux: Documented in generated comments.<br>AppArmor: Documented in generated comments. |
| `network.outbound[].protocol` | yes | `https` | Must be http, https, tcp, or udp. | Choose the narrowest protocol that describes the connection. | SELinux: Maps to generated network permission templates.<br>AppArmor: Maps to `network inet tcp` or `network inet udp` style rules. |
| `network.outbound[].port` | no | `443` | 1 through 65535. Required for tcp and udp. | Use explicit ports for raw TCP/UDP to avoid broad network access. | SELinux: Documented; port-level confinement depends on policy environment.<br>AppArmor: Documented; AppArmor network rules are protocol-oriented. |
| `ipc` | no | `ipc: ...` | Object. Omit when no local IPC access is needed. | Local IPC often crosses trust boundaries; keep entries intentional. | SELinux: Generates rules for supported IPC declarations.<br>AppArmor: Generates Unix socket and D-Bus rules. |
| `ipc.unix_sockets[]` | no | `{ path: /run/my-service/control.sock, mode: server }` | Non-empty list of socket entries. | Declare whether the application listens or connects. | SELinux: Generates Unix socket-related allow rules where expressible.<br>AppArmor: Generates Unix socket rules. |
| `ipc.unix_sockets[].path` | yes | `/run/my-service/control.sock` | Absolute, normalized, one-line path. | Use an application-specific socket path when the application owns it. | SELinux: Used in file-context suggestions and socket permissions.<br>AppArmor: Used in Unix socket path rules. |
| `ipc.unix_sockets[].mode` | yes | `server` | Must be server or client. | Server means the app creates/listens; client means it connects. | SELinux: Guides generated socket permissions.<br>AppArmor: Guides generated Unix socket permissions. |
| `ipc.dbus.system.owns[]` | no | `org.example.Service` | Non-empty valid D-Bus well-known name. | Owning a bus name exposes a service surface; keep names explicit. | SELinux: Documented for review; direct D-Bus confinement is limited.<br>AppArmor: Generates D-Bus own rules. |
| `ipc.dbus.system.talks_to[]` | no | `org.freedesktop.DBus` | Non-empty valid D-Bus well-known name. | Only list services the application is expected to call. | SELinux: Documented for review; direct D-Bus confinement is limited.<br>AppArmor: Generates D-Bus talk rules. |
| `capabilities[]` | no | `net-bind-service` | Non-empty kebab-case capability name. | Capabilities are powerful; keep the list short and prefer high-level intents. | SELinux: Generates capability allow rules for supported names.<br>AppArmor: Generates capability rules. |
| `extensions` | no | `extensions: ...` | Object. Unknown extension blocks produce warnings. | Backend-specific escape hatches should be temporary and reviewed as raw policy. | SELinux: Contains optional SELinux policy fragments.<br>AppArmor: Contains optional AppArmor profile-body rules. |
| `extensions.selinux.policy[]` | no | `allow mydaemon_t self:capability sys_ptrace;` | Non-empty SELinux policy fragment with complete statements where Intent can check them. | Raw SELinux policy bypasses Intent's abstraction and should be replaced by native schema support when possible. | SELinux: Inserted into a manual policy extension section of the generated type-enforcement module.<br>AppArmor: Not compiled. |
| `extensions.apparmor.rules[]` | no | `capability sys_ptrace,` | Non-empty AppArmor profile-body rule fragment; rules should terminate with commas. | Raw AppArmor rules bypass Intent's abstraction and should be replaced by native schema support when possible. | SELinux: Not compiled.<br>AppArmor: Inserted into a manual rule extension section inside the generated profile. |
| `notes[]` | no | `Example policy only; paths may differ by distribution.` | Non-empty string. | Human review notes only; not a permission grant. | SELinux: Not compiled.<br>AppArmor: Not compiled. |

## Validation Summary

- Unknown fields are rejected so typos do not silently weaken policy.
- Empty lists are rejected; omit a section when the application does not need it.
- Paths must be absolute, normalized, one-line Linux paths without NUL bytes, `.` components, or `..` components.
- Very broad storage paths such as `/`, `/etc`, `/var`, and `/usr` produce warnings.
- Cache paths outside `/var/cache` and state paths outside `/var/lib` produce warnings unless they include a `justification`.
- Runtime paths must be under `/run` or `/var/run`.
- `tcp` and `udp` network entries require `port`; `http` and `https` do not.
- D-Bus names must be valid well-known names such as `org.example.Service`.
- Unknown extension blocks produce warnings. Known extension fragments are preserved and compiled into their backend-specific policy section.

## Backend Notes

- SELinux output currently includes a type-enforcement module and file-context suggestions for executable and storage paths.
- AppArmor output currently includes a profile with file, network, Unix socket, D-Bus, and capability rules where supported by the schema.
- Escape hatches under `extensions` are backend-specific and should be treated as temporary workarounds until Intent gains native fields for the behavior.
- Intent may accept high-level fields before every backend can express them equally. Backend notes above call out gaps.
