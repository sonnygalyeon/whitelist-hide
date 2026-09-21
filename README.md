# whitelist-hide

Cross-platform, auditable network filtering / DPI-evasion toolkit.

> Status: early development. The repository currently contains the control-plane foundation. Packet interception backends are intentionally not enabled yet.

## Goals

- Windows, macOS and Linux from one project.
- Clear separation between the control plane and privileged packet-processing backends.
- No telemetry.
- No silent downloads.
- No hidden system modifications.
- Every privileged action should be inspectable and reversible.
- Third-party engines and drivers must have explicit provenance, versions and integrity metadata.
- Configuration should be portable between operating systems where the underlying capability exists.

## Why this project exists

Projects in this area often combine shell scripts, privileged services, drivers, prebuilt executables and binary packet templates in one bundle. That can work, but it makes auditing and troubleshooting harder.

whitelist-hide takes a different approach:

1. keep the core small and readable;
2. isolate OS-specific privileged code;
3. make system changes transactional and reversible;
4. verify third-party artifacts before execution;
5. expose diagnostics instead of modifying the host silently.

## Current commands

```text
whitelist-hide doctor
whitelist-hide status
whitelist-hide config-path
whitelist-hide config validate [PATH]
whitelist-hide config verify [PATH]
whitelist-hide engine verify <MANIFEST> <BINARY>
whitelist-hide help
```

At this stage these commands do not alter network settings.

## Planned architecture

```text
CLI / future GUI
      |
      v
whitelist-hide-core
      |
      +-- configuration
      +-- strategy model
      +-- diagnostics
      +-- artifact trust
      |
      v
platform backend
      |
      +-- Windows: WinDivert-compatible backend
      +-- macOS: utun + pf backend
      +-- Linux: netfilter/NFQUEUE backend
      |
      v
packet engine
```

The packet engine is deliberately an interface rather than a hard-coded binary. This lets us begin with a well-audited external implementation while preserving a path toward more native code later.

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

See [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ARTIFACTS.md](docs/ARTIFACTS.md).

## License

Project licensing will be finalized before the first public release. Third-party components keep their own licenses.
