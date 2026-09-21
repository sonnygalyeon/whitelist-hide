# Version 1.0 release gate

The branch `ver1.0` must not be created or made the default branch until every required item below is satisfied.

## Functional

- [ ] macOS: verified engine lifecycle, owned utun, scoped pf routing, start/stop/rollback.
- [ ] Windows: verified engine + WinDivert lifecycle, start/stop/rollback.
- [ ] Linux: verified engine + nftables/NFQUEUE lifecycle, start/stop/rollback.
- [ ] Shared strategy model works on all supported desktop platforms.
- [ ] Domain/user lists have validation and deterministic precedence.
- [ ] Health checks detect broken packet path and trigger rollback.
- [ ] No global networking reset is used as normal recovery.

## Application

- [ ] Tauri 2 desktop app works on Windows, macOS and Linux.
- [ ] Start/Stop, strategy selection, diagnostics, logs and settings are available in GUI.
- [ ] GUI runs unprivileged by default.
- [ ] Privileged helper accepts only allow-listed structured operations.
- [ ] Installers/uninstallers clean only project-owned resources.

## Security / supply chain

- [ ] Every shipped engine/driver has source, version/commit, license and SHA-256 metadata.
- [ ] Release artifacts are built by documented CI.
- [ ] No runtime telemetry.
- [ ] No silent executable downloads.
- [ ] No arbitrary shell execution from GUI/helper IPC.
- [ ] Security documentation matches implementation.

## Quality

- [ ] fmt, clippy and tests pass on Windows, macOS and Linux.
- [ ] Start/stop/rollback integration tests exist for every platform.
- [ ] Repeated start/stop cycles do not accumulate firewall/routes/services.
- [ ] Unexpected engine termination restores connectivity.
- [ ] README contains installation, usage and recovery instructions.

## Release

When every required checkbox above is satisfied:

1. create branch `ver1.0` from the tested release commit;
2. make `ver1.0` the repository default branch;
3. tag the same commit `v1.0.0`;
4. publish signed/checksummed release artifacts;
5. keep `main` for ongoing development.
