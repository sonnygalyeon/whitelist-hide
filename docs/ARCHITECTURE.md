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
- builds explicit action plans;
- asks a platform backend to apply or remove a network plan.

The `whitelist-hide-service` crate is the application-facing facade. CLI and future GUI code should consume this service instead of calling operating-system commands directly.

### Data plane

Contains the small privileged portion:

- installs packet interception;
- starts/stops the packet engine;
- owns firewall rules/routes/interfaces created by the project;
- performs cleanup and state restoration.

The UI must never construct privileged shell commands directly.

## 2. Application boundary

The planned desktop application uses the same Rust service model as the CLI. A future Tauri shell should remain unprivileged and delegate only allow-listed mutating actions to a narrow privileged helper. See `docs/GUI.md`.

## 3. Platform backends

### Windows

Planned first implementation:

- WinDivert-compatible interception;
- explicit driver/service lifecycle;
- no unrelated registry/TCP changes;
- driver and engine version/hash reporting;
- cleanup scoped to services and rules created by whitelist-hide.

The Flowseal Windows reference currently launches `winws.exe` with strategy-specific arguments and uses WinDivert. Its service manager also contains host-wide repair/configuration operations. We keep packet strategy and host repair separate.

### macOS

Current implementation:

- read-only inspection of default route, pf, utun interfaces, keepinit and privilege state;
- dedicated PF anchor `com.apple/whitelist-hide`, beneath macOS's loaded `com.apple/*` anchor tree;
- SHA-256/platform verification before engine launch;
- exact engine PID and binary path recorded in the runtime journal;
- dynamically selected project-owned utun unit;
- gateway MAC discovery before BPF reinjection;
- structured strategy compilation into engine arguments and PF port rules;
- transactional start rollback for PF rules, engine process and PF enable token;
- stop refuses to kill a PID if it no longer belongs to the recorded engine binary;
- no global PF disable/reset and no process-name-wide kill.

Remaining macOS work before v1.0:

- privileged helper/LaunchDaemon IPC so the GUI itself stays unprivileged;
- root-level integration tests for repeated start/stop/failure recovery;
- richer multi-profile strategy parity and IPv6 gateway handling.

### Linux

Planned first implementation:

- nftables by default;
- NFQUEUE for userspace packet processing;
- dedicated table/chain names;
- atomic cleanup;
- iptables compatibility only where required.

## 4. Strategy model

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

## 5. Artifact trust

Third-party privileged artifacts are represented by metadata rather than by whatever happens to be in `bin/`.

The launcher refuses to execute an artifact if the installed bytes do not match the expected digest.

## 6. Transactional host changes

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

## 7. Development sequence

1. Read-only CLI and architecture boundary. Done.
2. Configuration schema + validation. Done.
3. Artifact manifest + SHA-256 verification. Done.
4. Application service boundary + macOS inspection/planning foundation. Done in this stage.
5. Verified macOS engine + utun lifecycle. Implemented, integration testing pending.
6. Windows backend prototype. Diagnostics/plans implemented.
7. Linux backend prototype. Diagnostics/plans implemented.
8. Strategy compiler. Initial typed compiler implemented.
9. Managed Linux lifecycle.
10. Managed Windows/WinDivert lifecycle.
11. Automated connectivity/rollback tests.
12. Tauri desktop UI, privileged helpers and signed packaging.
13. Mobile backend investigation.
