# Architecture

## 1. Layers

whitelist-hide separates presentation, application state and privileged networking.

```text
CLI / Tauri desktop
        |
        v
whitelist-hide-service
        |
        +-- BackendStatus / diagnostics
        +-- ActionPlan / ActionResult
        +-- runtime ownership journal
        |
        v
whitelist-hide-core
        |
        +-- configuration
        +-- artifact manifests + SHA-256
        +-- engine-agnostic strategy schema
        |
        v
platform backend
        |
        +-- macOS
        +-- Windows
        +-- Linux
```

The UI must not construct or execute arbitrary privileged shell commands.

## 2. Runtime ownership

Mutating backend sessions must record what they own in a runtime journal.

The current journal can record:

- engine PID, executable path and verified SHA-256;
- macOS pf anchor and utun interface;
- Linux nftables table;
- Windows service identifier;
- platform and session identity.

Cleanup and rollback use this ownership record instead of killing processes by a generic executable name or globally resetting networking.

## 3. Strategy model

Strategies are strict TOML data rather than separate scripts.

A strategy contains:

- TCP/UDP rules;
- optional port ranges;
- optional domain filters;
- ordered transforms such as split, multisplit, disorder and verified fake-packet template references.

Unknown TOML fields and unsafe identifiers are rejected.

The strategy schema is engine-agnostic. A later compiler maps this model to the exact argument/config format of a verified packet engine.

## 4. Platform backends

### macOS

Implemented foundation:

- inspect default route and gateway;
- inspect pf state;
- inspect existing utun interfaces;
- inspect `net.inet.tcp.keepinit`;
- inspect current privilege level;
- inspect dedicated `com.whitelisthide` pf anchor;
- generate explicit start/stop/cleanup plans;
- execute only scoped pf-anchor cleanup.

The next mutation milestone is a verified engine session with owned utun detection, runtime journaling and transactional rollback.

### Windows

Implemented foundation:

- inspect network-interface availability;
- inspect WinDivert service state;
- generate start/stop/cleanup plans.

Planned mutation path:

- verify exact WinDivert and engine artifacts;
- start only the pinned driver/service;
- record process/service ownership;
- rollback only project-owned resources.

### Linux

Implemented foundation:

- inspect default route;
- inspect nftables availability/state;
- generate start/stop/cleanup plans.

Planned mutation path:

- dedicated `whitelist_hide` nftables table;
- NFQUEUE hand-off to verified userspace engine;
- runtime ownership journal;
- atomic rollback.

## 5. Artifact trust

Privileged third-party components are external trust boundaries.

Before execution an artifact must match its manifest:

- upstream/source identity;
- version or commit;
- license metadata;
- target OS/architecture;
- SHA-256.

No future downloader may execute bytes before successful verification.

## 6. Transactional lifecycle

A full start transaction is designed as:

```text
inspect current host state
        |
        v
verify config + strategy + artifacts
        |
        v
create runtime journal
        |
        v
start owned engine
        |
        v
claim owned network resources
        |
        v
apply project-scoped routing/interception
        |
        v
health check
        |
        +---- success ---> RUNNING
        |
        +---- failure ---> rollback in reverse order
```

Stop and recovery consult the journal and remove only recorded project-owned resources.

## 7. Desktop boundary

The Tauri shell is an unprivileged client of the Rust service layer.

Read-only status and planning are already exposed as Tauri commands. Future network mutations must be delegated to a narrow privileged helper with an allow-listed protocol. The helper must never accept a free-form shell command.

## 8. Release sequence

Completed foundations:

1. Rust workspace and read-only CLI.
2. Strict configuration.
3. Artifact manifest and SHA-256 verification.
4. Shared application service layer.
5. macOS diagnostics/planning.
6. Strategy schema and validation.
7. Runtime ownership journal.
8. Windows/Linux diagnostics and plans.
9. Tauri desktop shell.
10. Cross-platform core and desktop CI.

Remaining before `ver1.0`:

1. Verified engine lifecycle on macOS.
2. Owned utun + pf transaction and rollback.
3. Pinned WinDivert lifecycle and Windows start/stop.
4. nftables/NFQUEUE lifecycle and Linux start/stop.
5. Strategy compiler for the chosen verified engine.
6. Connectivity and crash-recovery tests.
7. Desktop privileged-helper integration.
8. Installers, signing/release packaging and user documentation.
