# Desktop connection flow

Tauri resolves its packaged resources and starts one privileged helper operation:

```text
connect <BUNDLED_PROFILE_DIRECTORY> <auto|CANDIDATE_ID> <REQUEST_ID>
```

The frontend passes only a candidate id and request id. The resource directory comes from Tauri, not from the WebView. Only known ids are accepted; there is no generic command executor or shell capability. Elevation uses the existing UAC, macOS authorization or polkit path, once for the whole selection.

`SessionController` retains responsibility for artifact verification, scoped network setup and rollback. `connection::select_strategy` controls candidates and network probes; the privileged helper holds the operation lock until the result is complete. The GUI reports selection progress and prevents overlapping actions.

Read-only `selection` returns the progress/final JSON snapshot. Final results are bound to the request UUID and running session id; a previous success cannot mark a new session connected. This file also transports the result on Windows where UAC starts a separate console. `health` includes the session id and watchdog freshness. `logs`, `stop` and the low-level `start <CONFIG> <STRATEGY>` remain available.

The default option is **Автоподбор — Россия**. Manual options attempt only their selected strategy, with the same HTTPS verification. All failure details remain in the exported report. The five-second health refresh does not perform another service probe and is labelled accordingly.

HTTPS validation is not a test of video playback, QUIC or a voice call. The UI displays that limit next to the result. If baseline HTTPS already passed, Connect still enables the selected filter and explicitly reports that improvement has not been demonstrated. See [STRATEGIES.md](STRATEGIES.md).

The frontend development build is a read-only preview. No network mutation runs inside the WebView. Mobile interception backends are outside this desktop task.
