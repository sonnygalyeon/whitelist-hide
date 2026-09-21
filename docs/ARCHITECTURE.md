# Architecture

## 1. Control plane vs. data plane

whitelist-hide is split into two layers.

### Control plane

Runs without administrator/root privileges whenever possible:

- parses configuration;
- selects strategies;
- validates domain/IP lists;
- resolves artifact metadata;
- reports status and diagnostics;
- asks a platform backend to apply or remove a network plan.

### Data plane

Contains the small privileged portion:

- installs packet interception;
- starts/stops the packet engine;
- owns firewall rules/routes/interfaces created by the project;
- performs cleanup and state restoration.

The UI must never construct privileged shell commands directly.

## 2. Platform backends

### Windows

Planned first implementation:

- WinDivert-compatible interception;
- explicit driver/service lifecycle;
- no unrelated registry/TCP changes;
- driver and engine version/hash reporting;
- cleanup scoped to services and rules created by whitelist-hide.

The Flowseal Windows reference currently launches `winws.exe` with strategy-specific arguments and uses WinDivert. Its service manager also contains host-wide repair/configuration operations. We keep packet strategy and host repair separate.

### macOS

Planned first implementation:

- dedicated `pf` anchor;
- a `utun` transport;
- launchd only for explicitly enabled persistent mode;
- capture and restore any sysctl changed by the backend;
- robust cleanup on termination.

The Flowseal macOS reference routes selected traffic through a `utun` interface with a dedicated pf anchor and a privileged launch daemon. That is a useful architectural reference, but our lifecycle/state tracking is independent.

### Linux

Planned first implementation:

- nftables by default;
- NFQUEUE for userspace packet processing;
- dedicated table/chain names;
- atomic cleanup;
- iptables compatibility only where required.

## 3. Strategy model

Strategies are data, not separate shell scripts.

```text
Strategy
  filters
    protocols
    ports
    domains
    ipsets
  transforms
    split
    disorder
    fake packet
    sequence overlap
  limits
    packet count / cutoff
  templates
    explicit verified binary payload references
```

The same strategy description can then be compiled into backend/engine-specific arguments.

## 4. Artifact trust

Third-party privileged artifacts are represented by metadata rather than by whatever happens to be in `bin/`.

Planned manifest concept:

```toml
name = "engine"
version = "..."
source = "https://..."
license = "..."
platform = "windows-x86_64"
sha256 = "..."
```

The launcher refuses to execute an artifact if the installed bytes do not match the expected digest.

## 5. Transactional host changes

Every start operation should build a plan:

```text
inspect current state
        |
        v
validate prerequisites
        |
        v
apply project-owned changes
        |
        v
start engine
        |
        v
health check
```

If any step fails, completed steps are rolled back in reverse order.

Stop/uninstall use the recorded state rather than broad networking reset commands.

## 6. Development sequence

1. Read-only CLI and architecture boundary.
2. Configuration schema + validation.
3. Artifact manifest + SHA-256 verification.
4. macOS backend prototype.
5. Windows backend prototype.
6. Linux backend prototype.
7. Strategy compiler.
8. Automated connectivity/rollback tests.
9. Signed, reproducible release pipeline.
10. GUI/mobile investigation.

The ordering intentionally establishes trust and rollback before enabling packet modification.
