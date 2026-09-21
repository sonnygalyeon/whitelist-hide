# whitelist-hide desktop

This directory is reserved for the Tauri 2 desktop application.

The desktop UI is intentionally not wired into the root Cargo workspace yet. Native networking and privilege boundaries are still stabilizing, and pulling Tauri/WebView system dependencies into the core CI before that would make backend failures harder to isolate.

The desktop app will consume structured values from `whitelist-hide-service`:

- backend status;
- diagnostics;
- action plans;
- strategy selection;
- engine trust state;
- logs/events.

It will not parse CLI text and it will not expose an arbitrary privileged shell command interface.

Planned frontend flow:

```text
Dashboard
  -> AppService status
  -> selected strategy
  -> Start / Stop
  -> diagnostics
  -> logs
  -> settings
```

The visual design will be agreed separately before implementation.
