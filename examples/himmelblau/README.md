# Himmelblau Intent Example

This is the first realistic Intent example for a daemon-style Linux identity and authentication service. It is intentionally labeled as an evolving example: the generated policy is a concrete compiler snapshot, not production-ready SELinux, AppArmor, or systemd policy.

The intent describes `himmelblaud` as a root-run system daemon with:

- read-only configuration in `/etc/himmelblau`
- writable cache in `/var/cache/himmelblaud`
- writable persistent state in `/var/lib/himmelblaud`
- writable runtime files in `/run/himmelblaud`
- outbound HTTPS to Microsoft identity endpoints
- a Unix stream socket server at `/run/himmelblaud/socket`
- a resolver Unix socket client connection
- system bus ownership and calls where the schema can represent them

The upstream Himmelblau SELinux policy is more detailed than this example. In particular, it includes multiple cooperating process domains, compatibility paths, private systemd directory layouts, NSS cache paths, and host integration permissions that Intent does not yet model directly.

## Reference Output

The `expected/` directory contains snapshot-style generated output from this intent:

- `expected/selinux/himmelblaud.te`
- `expected/selinux/himmelblaud.fc`
- `expected/apparmor/himmelblaud.apparmor`
- `expected/systemd/10-intent-hardening.conf`

Regenerate the files with:

```sh
cargo run -- build examples/himmelblau/intent.yaml --target all --output /tmp/intent-himmelblau
```

Then compare or copy the generated files into the matching backend directory.

## Known Gaps

Intent does not yet express all permissions a real Himmelblau deployment may require. The current schema is useful for making the abstraction concrete, but review the generated output as a starting point only. Current gaps include:

- multiple executable entry points and SELinux domains for helper daemons
- distro-specific SELinux D-Bus peer types
- exact DNS or host-level network confinement in SELinux and AppArmor
- package-specific private directory layouts under `/var/cache/private` or `/var/lib/private`
- NSS/PAM, certificate store, resolver, TPM, machine identity, and systemd integration reads
- capability and privilege setup precise enough for real authentication workflows
