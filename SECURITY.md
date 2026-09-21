# Security policy and trust model

whitelist-hide modifies packet flow only through explicit, reviewable platform backends.

## Non-negotiable rules

1. **No silent downloads.** Runtime code must not download executables, drivers, scripts or packet templates without an explicit user action.
2. **No execute-after-download without verification.** External artifacts require provenance and integrity metadata before execution.
3. **No global network reset as routine recovery.** Broad commands that reset Winsock, TCP/IP, DNS or firewall state are not a normal repair mechanism.
4. **Reversible privileged changes.** Firewall rules, services, routes, interfaces and sysctls created by whitelist-hide must be individually identifiable and removable.
5. **Restore previous values.** If a system setting is changed, its previous value must be captured before modification and restored on stop/uninstall where technically possible.
6. **Least privilege.** Configuration parsing, UI and diagnostics run unprivileged. Privilege is reserved for the narrow backend operation that requires it.
7. **No telemetry.** Diagnostics stay local unless the user explicitly exports them.
8. **No opaque shell concatenation.** User-provided values must not be inserted into privileged shell command strings.
9. **Fail closed for integrity.** A missing or mismatched artifact hash prevents that artifact from running.
10. **Logs must not contain secrets.** Authentication material, private keys and unrelated user traffic are out of scope for logging.

## Third-party engines

A backend may initially use an existing packet engine. Such a component must be treated as a separately versioned dependency, not as an unexplained file committed into `bin/`.

The release process will record at least:

- project and upstream URL;
- exact version or commit;
- license;
- SHA-256 of the distributed artifact;
- supported operating system and architecture;
- how the artifact was built or obtained.

Longer term, reproducible builds are preferred over downloading prebuilt executables.

## Reporting

Until a dedicated security contact exists, security findings should be reported privately to the repository owner rather than posted with exploit details in a public issue.
