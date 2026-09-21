# Application / GUI architecture

whitelist-hide uses a Tauri 2 desktop shell on top of the same Rust diagnostics and backend model used by the CLI.

## Current boundary

```text
WebView / JavaScript
        |
        | fixed Tauri commands only
        v
Tauri Rust process (unprivileged by design)
        |
        +-- backend_status: read-only AppService diagnostics
        |
        +-- session_start / session_stop / session_health
                |
                | direct process argv, no shell string
                v
        whitelist-hide-helper
                |
                v
        SessionController
                |
        +-------+--------+
        |       |        |
      macOS   Linux   Windows
```

The UI does not receive a generic command executor. It cannot submit an arbitrary shell command to the helper. The Rust host resolves the packaged helper through Tauri's sidecar API, so bundle layout is not guessed from the GUI executable path.

## Helper protocol

The bundled helper accepts only:

```text
start <CONFIG> <STRATEGY>
stop
health
watchdog   # internal child operation
```

Configuration and strategy paths are passed as sidecar arguments, not interpolated into a privileged shell string. The WebView capability intentionally grants no shell execute/spawn permission.

## Privilege elevation

The helper binary is bundled separately so the WebView and normal GUI process do not need to run permanently as root/Administrator.

The remaining v1 task is OS-native elevation/installation:

- Windows: install/authorize the narrow helper without elevating the WebView;
- macOS: privileged helper/LaunchDaemon authorization;
- Linux: polkit/systemd-style authorization where required.

Until this is installed, direct helper invocation from an ordinary desktop session can fail with an OS permission error. This is intentional and is not hidden by falling back to broad shell elevation.

## UI surface

The current UI exposes:

- backend state and diagnostics;
- config path;
- strategy path;
- Start;
- Stop;
- Health.

Logs/settings/installer UX remain release-gate work.

## Mobile

Android and iOS may reuse configuration, trust, compiler and UI concepts, but packet interception requires separate mobile-specific backends and is not part of desktop v1.
