# whitelist-hide

Cross-platform, auditable DPI-evasion toolkit for Windows, macOS and Linux.

> **Release status:** release candidate infrastructure is active, but this repository is **not yet v1.0**. Verified engine execution, strategy compilation, source-built packet engines, desktop diagnostics and reproducible dependency locks are implemented. Privileged packet-path Start/Stop/rollback is still gated and must pass platform integration tests before the `ver1.0` branch may exist.

## Why this project exists

whitelist-hide is designed around a stricter trust model than "download a privileged binary and hope for the best":

- no telemetry;
- no silent executable downloads;
- no opaque prebuilt engine binaries committed to the repository;
- exact upstream commits/releases are pinned;
- external engines and drivers are hashed and carry provenance;
- verified engine ownership is recorded before it can later be stopped;
- system changes must be project-owned and reversible;
- the desktop UI stays unprivileged and does not expose arbitrary shell execution.

## Architecture

```text
Tauri desktop UI / CLI
          |
          v
     AppService
          |
    +-----+------------------+
    |                        |
 config / trust       diagnostics / plans
    |                        |
    +-----------+------------+
                |
                v
        platform backend
       /        |        \
  Windows     macOS      Linux
  WinDivert   utun/pf    NFQUEUE/nftables
```

Packet engines are separate pinned dependencies:

- Windows: `winws` built from the pinned bol-van/zapret source; WinDivert is pinned and checksum-verified.
- macOS: `utunws` built from the pinned Flowseal macOS source.
- Linux: `nfqws` built from the pinned bol-van/zapret source.

See `third_party/upstream.lock.toml`.

## Implemented CLI commands

```text
whitelist-hide doctor
whitelist-hide status

whitelist-hide config-path
whitelist-hide config validate [PATH]
whitelist-hide config verify [PATH]

whitelist-hide engine verify <MANIFEST> <BINARY>
whitelist-hide engine launch <MANIFEST> <BINARY> [ARGS...]
whitelist-hide engine stop

whitelist-hide strategy validate <PATH>
whitelist-hide strategy compile <PATH> <utunws|nfqws|winws>

whitelist-hide backend <macos|windows|linux> inspect
whitelist-hide backend <macos|windows|linux> plan <start|stop|cleanup>

whitelist-hide runtime state-path
whitelist-hide runtime show [PATH]
```

The verified engine runtime checks the manifest filename, target platform and SHA-256 before launch. It records the canonical executable path and PID. Stop refuses to terminate a PID if the current process identity no longer matches the process whitelist-hide originally launched.

### Current mutating operation

The only platform network mutation intentionally exposed at this stage is scoped macOS cleanup:

```text
whitelist-hide backend macos cleanup --apply
```

It flushes only the `com.whitelisthide` pf anchor. It does not disable or globally reset pf.

Full privileged Start/Stop remains blocked by the v1 release gate.

## Strategy model

Strategies are TOML data rather than separate shell scripts. A validated strategy can be compiled into explicit arguments for all three engine flavors:

```bash
cargo run -p whitelist-hide-cli -- \
  strategy compile examples/strategy.example.toml nfqws
```

The compiler is tested in CI for `utunws`, `nfqws` and `winws`.

## Desktop application

The desktop app lives in `apps/desktop` and uses Tauri 2 + Vite.

It currently exposes:

- platform detection;
- structured backend status;
- diagnostics;
- Start/Stop/Cleanup action-plan previews;
- a shared cross-platform dashboard.

It deliberately does **not** expose privileged network mutation until the helper/lifecycle release gate is complete.

Development:

```bash
cd apps/desktop
npm ci
npm run tauri:dev
```

Production bundle:

```bash
cd apps/desktop
npm ci
npm run tauri:build
```

## Build and test

The Rust workspace has a committed `Cargo.lock`. Release builds use `--locked`, and the declared MSRV (Rust 1.85) is verified in CI.

```bash
cargo build --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
```

The frontend has a committed `package-lock.json` and CI uses `npm ci`.

GitHub Actions currently cover:

- Rust fmt/clippy/tests on Windows, macOS and Linux;
- Rust 1.85 MSRV;
- strategy compilation for all three engines;
- source builds for `utunws`, `nfqws` and `winws`;
- WinDivert provenance and checksum verification;
- Tauri checks on Windows, macOS and Linux;
- native desktop bundle builds;
- release metadata checks that reject tracked opaque binaries.

## Supply-chain model

No `.exe`, `.dll`, `.sys`, `.dylib`, `.so` or packet `.bin` artifact is allowed to be casually committed into the project tree.

Release jobs build engines from pinned source where supported and generate:

```text
engine
SHA256SUMS
PROVENANCE.txt
```

The Windows source-build job additionally stages a pinned WinDivert release only after verifying the exact archive SHA-256 and records runtime dependencies of `winws.exe`.

## v1.0 policy

`docs/V1_RELEASE_GATE.md` is normative.

The `ver1.0` branch and `v1.0.0` tag must not be created until the privileged platform lifecycle, rollback/health integration tests, GUI Start/Stop path, installation/recovery documentation and release-signing requirements are satisfied.

Current evidence and remaining blockers are tracked in `docs/RELEASE_CANDIDATE_STATUS.md`.

## Reference projects

Architecture and behavior were researched against:

- Flowseal/zapret-discord-youtube
- Flowseal/zapret-mac-discord-youtube
- bol-van/zapret

Third-party code keeps its own license. No reference-project code is copied into this repository unless its license and attribution requirements are explicitly handled.

## Security

See:

- `SECURITY.md`
- `docs/ARCHITECTURE.md`
- `docs/ARTIFACTS.md`
- `docs/GUI.md`
- `docs/V1_RELEASE_GATE.md`

## License

The project license must be finalized before the first public v1 release. Third-party components retain their own licenses.
