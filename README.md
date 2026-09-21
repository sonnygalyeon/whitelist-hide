# whitelist-hide

Cross-platform, auditable packet-filtering and DPI-evasion toolkit for Windows, macOS and Linux.

> **Status:** release-candidate development. The verified engine lifecycle, strategy compiler, scoped platform network resources, watchdog rollback, Tauri desktop shell and source-build pipelines exist. Version 1.0 is still blocked on privileged end-to-end host tests, OS elevation/install integration and release signing/packaging evidence.

## What is implemented

- Strict TOML configuration and strategy schemas with unknown-field rejection.
- SHA-256 and platform verification before any privileged engine is launched.
- Deterministic strategy compilation for `nfqws`, `utunws` and `winws`.
- Linux backend with an owned `inet whitelist_hide` nftables table and NFQUEUE.
- macOS backend with owned `utun50`, dedicated `com.whitelisthide` PF anchor and PF enable-token restoration.
- Windows runtime using a verified `winws2` bundle and WinDivert runtime.
- Runtime ownership journal containing exact engine PID/binary and owned network resources.
- Watchdog cleanup if the engine or owned packet-path resource disappears.
- Tauri 2 desktop UI. Mutating UI commands call only the bundled `whitelist-hide-helper`; the WebView does not receive arbitrary shell execution.
- Pinned source builds for all three desktop engines. WinDivert 2.2.2 is pinned and its release ZIP is SHA-256 verified before extraction.
- Root Rust, desktop Rust and npm dependency lockfiles.

## CLI

```text
whitelist-hide doctor
whitelist-hide status
whitelist-hide config-path

whitelist-hide config validate [PATH]
whitelist-hide config verify [PATH]

whitelist-hide strategy validate <PATH>
whitelist-hide strategy compile <PATH> <nfqws|utunws|winws>

whitelist-hide engine verify <MANIFEST> <BINARY>
whitelist-hide engine launch <MANIFEST> <BINARY> [ARGS...]
whitelist-hide engine stop

whitelist-hide session start <CONFIG> <STRATEGY>
whitelist-hide session stop
whitelist-hide session health

whitelist-hide backend <macos|windows|linux> inspect
whitelist-hide backend <macos|windows|linux> plan <start|stop|cleanup>
```

`session start` performs the release-candidate lifecycle:

```text
load config
  -> verify engine + dependency manifests/SHA/platform
  -> validate + compile strategy
  -> create only project-owned packet-path resources
  -> launch verified engine
  -> persist ownership state
  -> immediate health check
  -> watchdog
```

A failure rolls back resources owned by whitelist-hide. The project does not use broad Winsock, PF, routing or nftables resets as normal recovery.

## Desktop

The desktop app uses the same diagnostics model as the CLI. Start/Stop/Health are forwarded to the bundled helper as fixed arguments rather than executed by the WebView.

The packaged helper is deliberately separate from the GUI. **Automatic OS-specific privilege elevation/installation is still a v1 release gate.** Until that integration is finished, a normal unprivileged desktop launch may report a permission error when Start/Stop requires Administrator/root rights.

## Building

The workspace declares Rust 1.85 as its MSRV.

```bash
cargo build --locked
cargo test --workspace --locked
```

Desktop:

```bash
cd apps/desktop
npm ci
npm run build
```

The Tauri Rust workspace has its own committed `apps/desktop/src-tauri/Cargo.lock`.

## External engines and drivers

No opaque engine/driver binaries are committed to the repository. CI builds/stages them from pinned metadata in `third_party/upstream.lock.toml`:

- macOS: Flowseal `utunws`, pinned commit;
- Linux: bol-van `nfqws`, pinned commit;
- Windows: bol-van `zapret2/winws2`, pinned commit;
- Windows driver: WinDivert 2.2.2, pinned source metadata and pinned official release archive SHA-256.

See `docs/UPSTREAM.md` and `docs/ARTIFACTS.md`.

## Recovery model

Runtime cleanup targets only resources recorded or reserved by this project:

- Linux: `inet whitelist_hide`;
- macOS: `com.whitelisthide`, `utun50`, and only the PF token created by whitelist-hide;
- Windows: the recorded engine process and its WinDivert-backed session.

If the engine terminates unexpectedly, the helper watchdog attempts scoped rollback. Real-host crash/recovery cycling is still required before the v1 tag.

## Release status

The hard release checklist is `docs/V1_RELEASE_GATE.md`. Evidence and remaining blockers are tracked in `docs/RELEASE_CANDIDATE_STATUS.md`.

No `ver1.0` branch or `v1.0.0` tag should be created until those live integration gates pass.

## Security

Core rules:

- no telemetry;
- no silent runtime executable downloads;
- no execute-before-verify;
- no arbitrary privileged shell IPC;
- least privilege and explicit resource ownership;
- fail closed on integrity mismatch.

See `SECURITY.md` and `docs/ARCHITECTURE.md`.

## License

Project licensing must be finalized before the public v1 release. Third-party components retain their own licenses.
