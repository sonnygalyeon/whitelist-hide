# Application / GUI architecture

whitelist-hide is intended to become a normal desktop application, not a collection of terminal scripts.

## UI technology

The planned desktop shell is Tauri 2. The existing Rust crates remain the application logic; the UI is a client of the same service layer used by the CLI.

Planned shape:

```text
Tauri UI
   |
   v
AppService
   |
   +-- configuration
   +-- artifact trust
   +-- diagnostics
   +-- action planning
   |
   v
platform backend
```

## Privilege boundary

The graphical application itself should not run permanently as Administrator/root.

Mutating operations will eventually be delegated to a small privileged helper with a narrow API:

```text
unprivileged GUI
      |
      | structured request
      v
privileged helper
      |
      +-- verify request
      +-- execute allow-listed backend action
      +-- return structured result
```

The helper must not expose arbitrary shell execution. The UI must never send a free-form command string to run as root.

## Desktop targets

- Windows: Tauri application + narrowly scoped Windows service/helper.
- macOS: Tauri application + privileged helper/LaunchDaemon only for mutating operations.
- Linux: Tauri application + polkit/systemd helper where required.

## Mobile

Android and iOS can share parts of the Tauri/Rust application model, but packet interception is a separate platform problem. Mobile support will therefore reuse configuration, trust, diagnostics and UI concepts while using mobile-specific networking backends.

## Interface design

Visual design is intentionally postponed until the backend state model is stable. The UI should be designed around structured state such as connection status, selected strategy, backend health, diagnostics, logs and explicit start/stop actions rather than around shell output.
