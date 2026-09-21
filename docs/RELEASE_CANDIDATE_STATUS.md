# Release candidate status

This document records what has been demonstrated by automated checks and what still blocks `ver1.0`.

Last updated for the `feature/final-release-candidate` line.

## Demonstrated

### Core and runtime

- Strict TOML configuration parsing rejects unknown fields.
- Artifact manifests validate filename, target platform and SHA-256.
- Verified engine launch records the canonical executable path and owned PID.
- Engine stop refuses a PID whose live process identity no longer matches recorded ownership.
- Runtime state is journaled rather than inferred from broad host state.
- Structured strategy definitions validate before compilation.
- The example strategy compiles successfully for `utunws`, `nfqws` and `winws`.

### Supply chain

- macOS `utunws` is built from the exact pinned upstream commit in GitHub Actions.
- Linux `nfqws` is built from the exact pinned upstream commit in GitHub Actions.
- Windows `winws` is built from the exact pinned upstream commit in GitHub Actions.
- WinDivert 2.2.2 is pinned to an exact upstream commit and official release URL.
- The WinDivert release archive SHA-256 is pinned and checked before extraction.
- Windows artifact generation records DLL/SYS hashes, provenance and `winws.exe` runtime dependencies.
- Release readiness rejects tracked opaque executable/driver/library artifacts.
- Root `Cargo.lock` is committed and CLI release builds use `--locked`.
- Desktop `package-lock.json` is committed and frontend CI uses `npm ci`.

### Cross-platform quality

- Rust fmt, clippy and tests pass on Windows, macOS and Linux.
- The declared Rust 1.85 MSRV passes `cargo check --workspace --all-targets --locked`.
- Tauri Rust application checks pass on macOS and Linux and are required on Windows as well.
- Frontend production build passes using the committed npm lockfile.
- Native desktop bundle CI is configured for Windows, macOS and Linux.

### Desktop UI

The Tauri dashboard currently provides:

- current platform;
- backend availability/state;
- structured diagnostic items;
- Start/Stop/Cleanup plan previews.

The UI intentionally has no arbitrary shell permission and no privileged network-mutation command.

## Still blocks v1.0

### Privileged packet lifecycle

The project does not yet have a release-approved full transactional Start/Stop implementation that has been integration-tested on real hosts for all three platforms:

- macOS: verified engine -> owned utun -> scoped pf routing -> health check -> rollback;
- Linux: verified engine -> dedicated nftables/NFQUEUE scope -> health check -> rollback;
- Windows: verified engine/WinDivert lifecycle -> health check -> rollback.

This is the principal blocker. A passing compiler/build test is not a substitute for a live packet-path test.

### Privilege helper

The GUI is intentionally unprivileged, but the narrow privileged helper/service that will accept only allow-listed structured operations has not yet passed the release gate.

### Integration and recovery

Still required:

- repeated Start/Stop cycles without accumulating project-owned state;
- forced engine-crash recovery tests;
- network-change tests;
- confirmation that rollback restores connectivity;
- install/uninstall cleanup tests on all supported desktop targets.

### Windows runtime packaging

The upstream `winws` target is Cygwin-based. The release package must explicitly account for every runtime dependency reported by `cygcheck`; no dependency may be silently assumed to exist on the user's machine.

### Distribution

Before `v1.0.0`:

- finalize the project license;
- finalize installers/uninstallers;
- sign/notarize production artifacts where applicable;
- finish installation, normal-use and recovery documentation;
- publish checksummed release artifacts from the tested release commit.

## Branch policy

Until all mandatory items in `docs/V1_RELEASE_GATE.md` are complete:

- `main` remains the default development branch;
- `ver1.0` must not be created;
- no `v1.0.0` tag should be published.

That restriction is intentional: version 1.0 means the privileged networking lifecycle is tested, not merely that the UI and build pipeline look finished.
