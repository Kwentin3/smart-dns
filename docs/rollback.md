# Bounded candidate publication and rollback

**Historical lab scope (2026-11-06).** For current production use
[recovery scopes and evidence](operations.md#три-разных-восстановления) and
[the private recovery set](operations.md#что-хранить-вне-vps-и-как-восстанавливать-установку).
The stop-first lab sequence below is not the current service-only policy operator
procedure, a component updater, or proof of whole-VPS recovery.

This is the [isolated refactor](refactor.md); its results/cleanup belong in
[refactor acceptance](reports/2026-11-06/refactor-acceptance.md). No production,
shared Traefik/Hermes, firewall, system DNS or device-profile change is authorized.

## Prepare

Keep a private accepted bundle: rules, settings including admin hash/ClientIDs,
reviewed origins, image lock, generated files and native effective AGH rules/
Docker labels. Hash private inputs/outputs separately. `snapshot.json` covers
rules/origins, not complete settings or deployment identity.

Render to a new `--out` every time. `write_new` stages a complete sibling directory
and publishes by rename; existing outputs are rejected. Preparation failure must
not overwrite accepted files. Do not delete the accepted directory to circumvent
the refusal. AGH's writable runtime config can be normalized/changed by its native
owner; preserve effective policy readback alongside immutable candidate provenance.

Preserve native admin credentials, narrow DNS network, operator UID/GID, writable
AGH config/work tmpfs and DNS-only NET_BIND_SERVICE. Do not restore historical
`users:[]`, a single config-file bind or unsupported disabled plain DNS. Tie
runtime image IDs to digest-pinned references. Operate only on new task services.

## Stop-first update and restore

1. Stop only pilot DNS/DoH service access, withdrawing new rewritten answers.
   Leave shared edge/unrelated sites running. Stop the new relay before replacing
   its host generation; cached connections may fail during the window.
2. Review the complete new candidate and native syntax/policy. Recreate only the
   new relay so Docker publishes matching HostSNI labels; HAProxy reload alone
   does not update labels. Do not add an intermediate broad route.
3. If startup/verification fails, keep DNS withdrawn and restore the accepted
   relay/config bundle. Recreate only affected new services. Restore matching
   DNS after relay readiness; verify actual authorized DNS and origin TLS.
4. Read back effective user_rules, actual labels and relay configuration; compare
   exact sets, admin/ID admission, unrelated HTTP behavior and unchanged
   edge/unrelated-service identity. Running containers or cached DNS alone do
   not prove restore.

Runner injects an invalid relay candidate and restores it only in the disposable
lab. The new report owns the result; it is not a production rehearsal or atomic
transaction across native owners.

## Withdrawal and cleanup

For complete withdrawal remove pilot DoH access first and restore device resolver
settings only where authorized. Measure actual rewritten-answer TTL, not a guessed
default/upstream TTL. Browser/OS DNS, negative caches, HTTPS/SVCB, ECH and Alt-Svc
can outlive server changes. Agree bounded waiting or targeted cache handling;
do not erase unrelated user state.

Retain a previous fixed-target relay/routes during an agreed cache-drain window
only when explicitly authorized. Otherwise stop it and report possible temporary
failures of cached connections. Do not extend a public relay indefinitely or
permit additional targets for drain.

Remove only task-created containers/networks. Lab EXIT trap records cleanup and
compares existing-container IDs, leaving source/private `.local/` evidence and
image cache for readback. Remove only the disposable experiment copy after
collection within authorization; confirm no owned listeners/services/networks
remain. Actual production/device recovery needs its own evidence when applicable.
