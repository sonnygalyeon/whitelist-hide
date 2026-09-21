# Privileged helper protocol

The desktop UI is not intended to run as root/Administrator.

Network mutations are delegated to the `whitelist-hide-helper` executable. The helper accepts exactly one JSON request on stdin and returns one JSON response on stdout.

It intentionally exposes no shell, command, executable-path, or raw-argument action.

## Request schema

```json
{
  "schema": 1,
  "action": {
    "type": "start",
    "config_path": "/absolute/path/config.toml",
    "strategy_path": "/absolute/path/strategy.toml",
    "state_path": "/absolute/path/runtime-state.json"
  }
}
```

or:

```json
{
  "schema": 1,
  "action": {
    "type": "stop",
    "state_path": "/absolute/path/runtime-state.json"
  }
}
```

Unknown fields are rejected. All paths must be absolute and parent traversal is rejected.

Platform-specific installation/elevation is kept outside this protocol. A production installer must grant the helper only the permissions needed by the platform backend and must not elevate the GUI process itself.
