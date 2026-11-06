# Bounded activation, change and rollback

This is a procedure for a separately approved integration. The offline pilot
does not authorize production deployment, existing-service restarts, firewall
changes, system DNS changes or device profile installation. Existing Traefik and
unrelated services stay under their current owners. Keep actual addresses,
networks, paths and credentials in private operator records.

The completed isolated Linux trial removed its own containers/network and
preserved the existing-container ID set. Native Windows checks stopped their
own processes. See the [acceptance report](reports/2026-11-06/acceptance.md) for
completed lab evidence and remaining production/device work. Generated evidence
and pulled images may remain for readback; neither is a running pilot service.

## Before an approved change

Retain a private rollback bundle: accepted rules, settings, origins, generated
configs, their hashes, exact image digests, effective AGH settings, new-service
labels and the prior relevant Traefik route state. `snapshot.json` is a
rules/origins fingerprint, not a complete settings or deployment hash. Verify
origin policy and DNS/HostSNI/HAProxy exact-name parity, native syntax checks and
the accepted integration evidence before any external activation. Preserve the
tested `config/images.lock.json` digests, AGH operator UID/GID, dedicated writable
config directory/work tmpfs and DNS-only NET_BIND_SERVICE capability. Restoring
a file-only config mount or dropping that required capability reintroduces
observed startup failures. Internal plain DNS on 5353 stays unpublished and
protected by ID-only admission; do not describe rollback as disabling a listener
that the tested native configuration requires.

Identify only the new DNS/relay containers and their volumes/networks. Do not
use an unscoped Compose down, prune, recursive removal or a command against an
existing application project. Reserve a bounded change window, identify how to
withdraw the pilot device resolver settings and agree the cache/drain policy.

## Changing rules without partial serving

Docker labels require recreation of the new relay container. A HAProxy reload
alone leaves Traefik's old HostSNI labels in effect. AGH rewrites and proxy labels
are separate state owners; stop-first is a deliberate availability tradeoff.

1. Withdraw access to the pilot DoH path and stop only the new pilot DNS service,
   preventing new rewritten answers. Do not stop the shared Traefik service.
2. Stop the new relay before replacing its rule generation. Existing connections
   can break; do not promise a zero-downtime update. Cached old answers may still
   reach the ingress, so keep those requests failing closed while changing.
3. Render the entire reviewed candidate to a new local output directory; inspect
   and hash all files. Replace the new services' configuration and recreate the
   new relay so Docker publishes its matching exact labels. Validate the running
   binary/config and target set before restoring any DNS answer.
4. Recreate/start the new DNS service with the matching generation, inspect its
   normalized native configuration, then restore only the approved DoH route.
   Verify ID admission, exact answers/omissions, intended TLS path and an
   unrelated existing site. If any mandatory check fails, withdraw DoH again
   and restore the accepted bundle or keep the pilot stopped.

This sequence avoids serving new DNS with old routing, but it does not erase
client caches. Host removal, origin changes and device switching need the cache
handling below. Never use an intermediate broad route to conceal a mismatch.

## Rollback and cache drain

Withdraw pilot DoH access first and restore the pilot devices' previous resolver
configuration where authorized. Verify ordinary resolution after that change;
server-side withdrawal does not prove device-side recovery. Restore only the
new-service accepted bundle when reverting to a previous pilot generation, or
remove only new pilot routes/services when abandoning the pilot.

Measure the TTL actually returned by native `dnsrewrite`; do not assume the
configured upstream TTL or a guessed default. Browser/OS DNS caches, negative
caches, HTTPS/SVCB, ECH and Alt-Svc can outlive server-side changes. Record the
observed TTLs and the permitted waiting/flush procedure for the actual devices.
Do not flush unrelated user state or change all device DNS settings implicitly.

If continued service for cached relay addresses is explicitly authorized, retain
the previously accepted fixed-target relay and its exact routes for the agreed
bounded drain window while DNS rewriting is withdrawn. It must keep the old
safe target policy; this is not permission to keep a public relay indefinitely.
If immediate shutdown is required, stop it and report the expected temporary
failure of cached pilot connections. Do not silently extend the drain or remove
unrelated routes to compensate.

After the chosen drain, remove only task-created containers, route labels and
temporary resources within authorization. Preserve private rollback evidence
until retention is agreed. Confirm pilot listeners and routes are gone, unrelated
Traefik routing still works, ordinary client resolution/browser access has
recovered, and no temporary test follower/process remains. If device verification
or cleanup is unavailable, record that gap and its next step; server-side checks
alone do not close rollback acceptance.
