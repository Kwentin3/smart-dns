# Pilot architecture

**Historical lab scope (2026-11-06).** The exact-only, fixed-origin refactor below
is not the current production topology. See [production operations](operations.md)
for the live suffix/dynamic-origin owners, certificate chains and maintenance.
Statements below about unchanged production apply only to that isolated stage.

Current work follows [the refactor GOAL](refactor.md). This candidate's results
belong in [refactor acceptance](reports/2026-11-06/refactor-acceptance.md), not the
historical [acceptance](reports/2026-11-06/acceptance.md) or
[PR2 follow-up](reports/2026-11-06/review-followup.md). Production, Hermes and the
shared Traefik are unchanged. Only exact `chatgpt.com` and `claude.ai` are in scope;
full product/device coverage is not claimed.

## Owners and publication

`rules/pilot.json` owns reviewed domains. `tools/render.py` validates explicit
private settings and reviewed origin IPv4s, translating into native configuration
without DNS lookup, registry fetch or deployment. The lab runner resolves origins
for its temporary test; production refresh remains a deliberate review.

| Artifact | Native owner |
| --- | --- |
| `agh-conf/AdGuardHome.yaml` | AGH v0.107.80: exact rewrites, ClientID admission, admin authentication |
| `haproxy.cfg` | HAProxy 3.2.26: exact lowercased SNI, numeric origin IPv4:443, global maxconn 256, connect 5s and client/server idle 60s |
| `compose.lab.json` | Traefik v3.6.25: Docker discovery, exact HostSNI/DoH boundaries and HTTP limits; unrelated-site fixture |
| `snapshot.json` | Rules/origins fingerprint and digest-pinned image references; private settings/effective outputs require separate hashes |

`write_new` prepares files in a sibling staging directory and renames it to a
new output directory; existing outputs are refused. This protects the accepted
file set during preparation. Live activation remains stop-first across separate
owners, not an atomic transaction. See [rollback](rollback.md).

## Traffic

The DoH router matches its configured host and exactly `/dns-query` or
`^/dns-query/[0-9a-f]{32,64}$`; Compose `$$` preserves the regex anchor in labels.
AGH receives the unchanged ClientID path over private HTTP. Native nonempty
`allowed_clients` contains only IDs; adding proxy/client IPs would bypass that
boundary. A required native admin username/bcrypt credential protects management
separately and does not grant DNS admission.

Native HTTP middleware order: overwrite Host with the configured resolver host;
rateLimit average 20/s, burst 40, requestHost criterion; inFlightReq amount 8 with
the same criterion. Canonical Host prevents case/port variants creating extra
buckets. This intentionally aggregates all DoH traffic on one router/process;
it is not per-device fairness or a distributed limit. Values are lab bounds,
not accepted production thresholds.
Native [header overwrite](https://github.com/traefik/traefik/blob/v3.6.25/pkg/middlewares/headers/header.go)
runs before the [source extractor](https://github.com/traefik/traefik/blob/v3.6.25/pkg/middlewares/extractor.go);
the pinned dependency otherwise keys requestHost by [raw req.Host](https://github.com/vulcand/oxy/blob/v2.1.0/utils/source.go).

AGH rewrites selected A to relay IPv4 and returns NODATA for selected
AAAA/HTTPS/SVCB. Other questions use ordinary DNS. Website TLS passes through
exact Traefik HostSNI and HAProxy lowercased exact SNI to fixed origins without
local TLS termination or runtime DNS fallback.

The dedicated DNS network joins only edge and AGH; relay/unrelated-site fixture
use the other lab network. AGH publishes no host ports, retaining required
internal plain DNS 5353 and authenticated HTTP/admin 3000. It runs under operator
UID/GID with writable config directory/work tmpfs; only DNS restores required
NET_BIND_SERVICE. Authentication complements narrow network access.

Matched DoH requests disable per-router access logs. Global lab JSON fields and
headers default to drop, retaining router/service/status and a synthetic case
header for other requests, including denied URLs. Thus negative cases remain
observable without saving secret paths. This does not accept production logging.

## Why HAProxy remains

Native Traefik supports external numeric TCP services with a suitable dynamic
provider, but its [inFlightConn counter is per IP](https://github.com/traefik/traefik/blob/v3.6.25/pkg/middlewares/tcp/inflightconn/inflight_conn.go),
and [TCP proxying](https://github.com/traefik/traefik/blob/v3.6.25/pkg/tcp/proxy.go)
does not provide the existing idle timeout. Dial timeout is not idle timeout.
Replacing HAProxy while preserving global cap/idle bounds needs another control
or changed guarantees. Keeping the established relay is smaller for this scope.

Read-only inventory found shared Traefik Docker provider enabled,
`exposedByDefault=false`, file provider disabled. The lab starts a separate edge;
no shared-edge provider/restart or production network change is authorized. Four
images are digest-pinned; evidence must tie running container image IDs to the
lock rather than merely inspect tags. Before production separately approve
new-service integration, credentials, network/certificate ownership, origins,
denied-request logging, capacity policy and rollback. Full login/CDN/files/devices,
ECH/QUIC and cache behavior remain outside this infrastructure refactor.
