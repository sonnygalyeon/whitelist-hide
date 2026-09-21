# whitelist-hide

Cross-platform, auditable network filtering / DPI-evasion toolkit.

> Status: early development. The project now has a shared application service layer plus a macOS inspection/planning backend. Full packet interception is not enabled yet.

## Goals

- Windows, macOS and Linux from one project.
- A desktop application with one shared interface and backend model.
- Clear separation between the unprivileged application and privileged packet-processing backends.
- No telemetry.
- No silent downloads.
- No hidden system modifications.
- Every privileged action should be inspectable and reversible.
- Third-party engines and drivers must have explicit provenance, versions and integrity metadata.

## Current commands

```text
whitelist-hide doctor
whitelist-hide status
whitelist-hide config-path
whitelist-hide config validate [PATH]
whitelist-hide config verify [PATH]
whitelist-hide engine verify <MANIFEST> <BINARY>

whitelist-hide backend macos inspect
whitelist-hide backend macos plan <start|stop|cleanup>
whitelist-hide backend macos cleanup
whitelist-hide backend macos cleanup --apply
```

The macOS cleanup apply command is deliberately narrow: it only flushes the dedicated `com.whitelisthide` pf anchor. It does not disable or reset global pf state.

## Planned application architecture

```text
CLI / Tauri GUI
      |
      v
whitelist-hide-service
      |
      v
whitelist-hide-core
      |
      +-- configuration
      +-- artifact trust
      +-- diagnostics
      +-- action plans
      |
      v
platform backend
      |
      +-- Windows: WinDivert-compatible backend
      +-- macOS: utun + pf backend
      +-- Linux: netfilter/NFQUEUE backend
```

See `docs/GUI.md` for the planned desktop privilege boundary.

## Development

Requires a current stable Rust toolchain.

```bash
cargo build
cargo run -p whitelist-hide-cli -- doctor
cargo test --workspace
```

## Reference projects

The initial research compares behavior and architecture with:

- Flowseal/zapret-discord-youtube
- Flowseal/zapret-mac-discord-youtube
- bol-van/zapret

No code from those projects is copied into this repository unless its license and attribution requirements are handled explicitly.

## Safety model

See `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/ARTIFACTS.md` and `docs/GUI.md`.

## License

Project licensing will be finalized before the first public release. Third-party components keep their own licenses.
