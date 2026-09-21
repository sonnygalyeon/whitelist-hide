# Release policy

## ver1.0 gate

The `ver1.0` branch must not become the repository default until all of these conditions are met:

- Windows backend can start, stop and rollback a pinned verified engine.
- macOS backend can start, stop and rollback a pinned verified engine and owned utun/pf state.
- Linux backend can start, stop and rollback a pinned verified engine and owned nftables/NFQUEUE state.
- Desktop application builds on all three desktop platforms.
- Start/stop survives engine failure without leaving project-owned network state behind.
- CI, package integrity checks and release artifacts are green.
- No runtime download is executed without integrity verification.
- User-facing install/uninstall documentation exists.

Before that point, `main` remains the default branch.
