# macOS backend

The macOS backend is the first platform with a managed start/stop implementation.

## Trust boundary

A start request must point to:

- an application config;
- an artifact manifest;
- the exact engine binary referenced by the config;
- a structured strategy.

Before the engine is executed, whitelist-hide verifies the artifact manifest, SHA-256 and target platform.

## Managed start

The current start sequence is:

1. require the privileged execution boundary;
2. refuse to start when a runtime journal already exists;
3. validate config and strategy;
4. verify the engine SHA-256 and platform;
5. inspect the IPv4 default interface and gateway;
6. resolve the gateway MAC from the ARP table;
7. reserve an unused utun unit from the project range;
8. persist the planned ownership journal;
9. spawn only the verified engine binary and record its PID;
10. wait for the exact expected utun interface;
11. configure the project utun;
12. enable PF only if it was disabled, preserving the returned PF token;
13. load route-to rules only into `com.apple/whitelist-hide`;
14. health-check the engine, interface and anchor;
15. mark the runtime journal as running.

If startup fails after the engine is created, whitelist-hide flushes only its anchor, kills the child it directly created, releases its PF token when one exists, and removes the runtime state when rollback succeeds.

## Managed stop

Stop uses the runtime ownership journal.

The PF anchor is flushed first. Then the recorded PID is inspected with `ps`; it is terminated only if its command still contains the recorded verified engine path. This prevents PID reuse from turning a stale journal into an unrelated-process killer.

When whitelist-hide enabled PF for the session, stop releases only the token recorded for that session.

Closing the engine releases its utun socket, so the interface disappears with the owned process.

## PF scope

The anchor is:

`com.apple/whitelist-hide`

macOS's default PF configuration loads the `com.apple/*` subtree. Keeping the project rules below that tree means the anchor participates in the active ruleset without editing `/etc/pf.conf`.

No normal operation uses a global PF flush or disables PF.

## Current limitations

The implementation is compiled and unit-tested by CI, but CI does not claim to perform privileged end-to-end PF/BPF/utun routing on an actual user's network.

Before Version 1.0 the project still needs:

- privileged-helper integration for the desktop GUI;
- repeated start/stop integration tests;
- forced engine-crash recovery tests;
- IPv6 gateway neighbor handling;
- broader multi-profile strategy support.

## CLI

Preview:

`whitelist-hide backend macos plan start`

Managed start:

`whitelist-hide backend macos start <CONFIG> <STRATEGY> --apply`

Managed stop:

`whitelist-hide backend macos stop --apply`

Read the ownership journal:

`whitelist-hide status`
