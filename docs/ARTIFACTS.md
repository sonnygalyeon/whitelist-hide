# Artifact trust

whitelist-hide treats every executable packet engine and kernel/driver component as an external trust boundary.

## Manifest

An artifact manifest records the exact identity expected by the launcher:

```toml
schema = 1
name = "engine-name"
version = "upstream-version-or-commit"
source = "https://upstream.example/project"
license = "SPDX-or-upstream-license"

[artifact]
platform = "windows-x86_64"
filename = "engine.exe"
sha256 = "64-lowercase-or-uppercase-hex-characters"
```

Supported targets currently are:

- `windows-x86_64`
- `windows-aarch64`
- `macos-x86_64`
- `macos-aarch64`
- `linux-x86_64`
- `linux-aarch64`

Unknown fields are rejected. This is intentional: misspelled security-relevant fields must not be silently ignored.

## Verification

Direct verification:

```text
whitelist-hide engine verify engine.toml path/to/engine
```

Verification through the application configuration:

```text
whitelist-hide config verify path/to/config.toml
```

A trusted result requires both conditions:

1. the computed SHA-256 exactly matches the manifest;
2. the manifest target matches the operating system and CPU architecture running whitelist-hide.

Checksum mismatch and platform mismatch use different non-zero exit codes so packaging and CI can fail closed.

## Downloads

This stage contains no downloader. A future downloader, if added, must download to a temporary file, verify its digest first, and only then atomically install it. It must never execute bytes merely because a server returned HTTP 200.
