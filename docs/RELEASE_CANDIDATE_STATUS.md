# Release candidate status

This document records the current evidence for `feature/release-candidate` and the remaining blockers for `ver1.0`.

## Demonstrated by code + CI

### Core/runtime

- Strict config and strategy parsing with unknown-field rejection.
- Manifest/platform/SHA-256 verification before engine launch.
- Complete engine-bundle verification for additional privileged dependencies.
- Deterministic strategy compiler for `nfqws`, `utunws` and `winws`.
- Runtime journal stores canonical engine identity and owned network resources.
- Stop refuses to kill a PID whose live executable no longer matches recorded ownership.
- Startup rollback covers engine launch, network-resource failures and ownership-journal commit failures.
- Watchdog detects loss of the recorded process/resource and invokes scoped cleanup.

### Platform implementation

- Linux: dedicated `inet whitelist_hide` nftables table + NFQUEUE 200.
- macOS: dedicated `utun50`, `com.whitelisthide` PF anchor and PF token ownership.
- Windows: verified `winws2` lifecycle plus WinDivert health signal.

These are implemented but are **not yet release-certified by privileged end-to-end host tests**.

### Supply chain

- macOS `utunws` source-build succeeds from the exact pinned commit.
- Linux `nfqws` source-build succeeds from the exact pinned commit.
- Windows `winws2` source-build succeeds from the exact pinned commit.
- WinDivert 2.2.2 has pinned source metadata, license metadata, official asset URL and archive SHA-256.
- CI verifies the WinDivert ZIP before extraction.
- The release metadata gate rejects tracked opaque executable/driver/library artifacts.
- Root `Cargo.lock`, desktop `Cargo.lock` and desktop `package-lock.json` are committed.
- Rust release checks use `--locked`; frontend checks use `npm ci`.

### Application boundary

- Tauri WebView has no arbitrary shell API.
- Read-only diagnostics run in the normal app process.
- Start/Stop/Health invoke only the bundled `whitelist-hide-helper` with fixed argv.
- Helper accepts an allow-list of session operations.
- Helper starts the watchdog after a successful session start.

## Automated gates

Required workflows cover:

- fmt/clippy/tests on Windows, macOS and Linux;
- Rust 1.85 MSRV;
- locked release build/tests;
- strategy compilation for all three engine flavors;
- supply-chain metadata validation;
- frontend frozen install/build;
- locked Tauri Rust checks;
- source-built engines;
- desktop bundle construction.

The latest commit must have all of these green before promotion.

## Still blocks v1.0

### 1. Privileged live packet-path testing

Run real-host tests on Windows, macOS and Linux proving:

- Start succeeds with the actual source-built engine bundle;
- matching traffic traverses the intended packet path;
- Stop removes only project-owned resources;
- repeated cycles do not accumulate state;
- forced engine termination triggers watchdog rollback;
- connectivity is restored after rollback.

Hosted compile/unit CI alone is not accepted as proof of this.

### 2. Desktop privilege authorization

The helper is isolated and bundled, but automatic OS-native authorization/installation is not finished. The GUI must stay unprivileged while the helper receives only the rights required for mutations.

### 3. Installer/uninstaller

Install and removal flows must prove they clean only whitelist-hide-owned state.

### 4. Product surface

GUI logs/settings and polished strategy selection remain incomplete.

### 5. Distribution policy

Before a public `v1.0.0` tag:

- choose/finalize the project license;
- configure Windows signing and macOS signing/notarization policy;
- publish checksummed artifacts from the exact tested commit.

## Branch policy

`main` remains the stable development base until the above live gates pass. The old `feature/final-release-candidate` branch is superseded by the newer transactional `feature/release-candidate` line.

Do not create `ver1.0` or tag `v1.0.0` merely because compilation is green.
