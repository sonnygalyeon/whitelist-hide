# Desktop app

This is the Tauri 2 shell for whitelist-hide.

It intentionally exposes only read-only backend status and action-plan commands. Privileged network mutations will be connected only after the privileged-helper protocol is implemented.

Run from this directory with a Tauri 2 toolchain:

```bash
cargo tauri dev
```

The frontend is deliberately framework-free for now so visual design can be replaced later without touching the Rust service/backend architecture.
