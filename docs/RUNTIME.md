# Runtime ownership and recovery

Network resources must be changed only when whitelist-hide can prove ownership of them.

The runtime journal records:

- controller PID;
- engine PID;
- platform;
- lifecycle phase;
- owned network interface;
- owned firewall scope;
- previous values of settings changed by the session.

The state is validated before use. Resource names are restricted to conservative identifiers and are never interpolated into arbitrary shell strings.

## Recovery rule

A cleanup operation must use recorded ownership, not broad process names or global network resets.

Examples:

- good: stop PID recorded as the engine PID for the active session;
- bad: `pkill -9 -x utunws`;
- good: flush `com.whitelisthide`;
- bad: flush all pf rules;
- good: delete `inet whitelist_hide`;
- bad: reset the full nftables ruleset.

The journal is infrastructure for the upcoming transactional start/stop implementations. It does not by itself grant permission to mutate networking.
