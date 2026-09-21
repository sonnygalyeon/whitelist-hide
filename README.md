# whitelist-hide

Cross-platform, auditable network filtering / DPI-evasion toolkit and desktop application foundation.

> Status: pre-1.0. Configuration, artifact trust, strategy validation, runtime ownership, cross-platform diagnostics and a Tauri desktop shell exist. Full packet-processing start/stop is not enabled on all platforms yet.

## Goals

- Windows, macOS and Linux from one project.
- One desktop application backed by the same Rust service layer as the CLI.
- No telemetry or silent downloads.
- No hidden host-wide network resets.
- Every privileged action should be inspectable, scoped and reversible.
- Third-party engines and drivers require explicit provenance, platform metadata and integrity verification.
- Runtime cleanup must target only resources recorded as owned by whitelist-hide.

## Repository layout

```text
crates/core              configuration, artifact trust, strategies
crates/service           application API and runtime ownership journal
crates/platform-macos    pf/utun backend
crates/platform-windows  WinDivert backend foundation
crates/platform-linux    nftables/NFQUEUE backend foundation
crates/cli               command-line application
apps/desktop             Tauri 2 desktop application
```

## CLI

```text
whitelist-hide doctor
whitelist-hide status
whitelist-hide config-path

whitelist-hide config validate [PATH]
whitelist-hide config verify [PATH]
whitelist-hide strategy validate <PATH>
whitelist-hide engine verify <MANIFEST> <BINARY>

whitelist-hide backend <macos|windows|linux> inspect
whitelist-hide backend <macos|windows|linux> plan <start|stop|cleanup>

whitelist-hide backend macos cleanup
whitelist-hide backend macos cleanup --apply
```

The only currently enabled network mutation is the scoped macOS cleanup operation. It flushes only the dedicated `com.whitelisthide` pf anchor.

## Desktop application

The desktop shell lives in `apps/desktop` and uses Tauri 2. It consumes structured Rust service/backend data instead of parsing CLI output.

The current UI exposes:

- detected platform;
- backend state;
- backend diagnostics;
- explicit start/stop/cleanup plans.

Privileged mutations are intentionally not exposed by the GUI yet. They will go through a narrow privileged-helper protocol rather than running the full UI as root/Administrator.

## Build and test

Core/CLI:

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

CLI example:

```bash
cargo run -p whitelist-hide-cli -- doctor
cargo run -p whitelist-hide-cli -- backend macos inspect
cargo run -p whitelist-hide-cli -- strategy validate examples/strategy.example.toml
```

Desktop shell:

```bash
cd apps/desktop/src-tauri
cargo check
```

For a full local Tauri development run, install the platform prerequisites described by Tauri and use the Tauri CLI from the desktop application directory.

## Release policy

`main` remains the default branch during pre-1.0 development.

The `ver1.0` branch will be created and made the repository default only after the release gates in `docs/RELEASE.md` pass, including working start/stop/rollback on Windows, macOS and Linux and green desktop builds.

## Reference projects

The initial research compares behavior and architecture with:

- Flowseal/zapret-discord-youtube
- Flowseal/zapret-mac-discord-youtube
- bol-van/zapret

No code from those projects is copied into this repository unless its license and attribution requirements are handled explicitly.

## Security and architecture

See:

- `SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/ARTIFACTS.md`
- `docs/GUI.md`
- `docs/RELEASE.md`

## License

Project licensing will be finalized before the first public release. Third-party components keep their own licenses.
