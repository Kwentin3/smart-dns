# Security boundary of the pilot

The scope is two exact public hosts through established DNS and TLS passthrough
components. It is not a general-purpose forward proxy. Native owners remain
AdGuard Home, Traefik and HAProxy; `tools/render.py` only validates and translates
reviewed inputs. The [acceptance report](reports/2026-11-06/acceptance.md) records
the completed native Windows, contract and isolated Linux checks, with their
explicit limits. Production and ordinary-device acceptance remain separate.

## Admission and secrets

- AGH's nonempty `dns.allowed_clients` contains random per-device ClientIDs only.
  Missing/unknown DoH IDs were denied with DNS REFUSED and zero answers even
  though HTTP returned 200. Revocation/restart was not exercised. Do not add
  loopback/proxy/client IPs: native IP-or-ID semantics would bypass ID admission.
- ClientIDs are bearer credentials embedded in DoH URL paths. Redact the path in
  screenshots, shell transcripts, reports, reverse-proxy access logs, browser
  exports and backups intended for sharing. Never commit live settings, keys,
  SSH material, certificate private keys or complete credential URLs. Rotate an
  exposed ID and distribute the replacement through the approved private channel.
- Management/setup/API routes must not be exposed through the DoH frontend. Only
  exact `/dns-query` and a single lowercase-hex 32–64-character ClientID path are
  routed; suffixes, malformed IDs and unrelated prefixes are excluded. Preserve
  ClientID paths; forwarded headers
  must not create an IP admission exception. AGH has no published listener ports.
  Its required plain-DNS listener remains internal on 5353; native Windows checks
  observed UDP drop and TCP REFUSED without useful answers under ID-only ACL.
- A production proposal must isolate management using a dedicated narrow
  Traefik-to-AGH network or separately reviewed authentication/protection.
  `users: []` leaves AGH HTTP/admin on `0.0.0.0:3000` without user authentication;
  not publishing the port does not protect it from shared-network peer containers.
  The lab network is a disposable fixture, not acceptance of that production
  isolation. `trusted_proxies` governs address attribution separately from
  ClientID admission; never add the proxy to `allowed_clients` to fix attribution.
- DNS query logging/statistics are disabled for the pilot. HAProxy TCP logs still
  reveal traffic metadata; bound their size and access. Verify existing Traefik
  logging redacts or excludes secret DoH paths before activation. The follow-up
  lab JSON access log drops all fields/headers by default and keeps only
  RouterName, ServiceName, DownstreamStatus and synthetic X-Lab-Case. No path,
  query or ClientID is intentionally retained. This limited instrumentation
  does not prove the existing production logging policy is safe.

Native `dns.ratelimit: 20` is **not a DoH rate limit**. It does not create even
a shared proxy-source DoH bucket. In pinned dnsproxy v0.83.2, the
[rate-limit middleware checks only ProtoUDP](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/ratelimit/ratelimit.go#L51),
whereas the [DoH handler uses ProtoHTTPS](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/proxy/serverhttps.go#L254).
Consequently this setting provides no DoH request throttling. CPU/memory and
connection bounds do not replace a request limit. The appropriate production
DoH limit and attribution policy are future preactivation decisions; this
follow-up does not configure or deploy them.

## Destination policy

Traefik uses literal exact `HostSNI`; HAProxy lowercases SNI before matching the
same exact set, aligning case handling without expanding the allowlist. The
first-iteration direct-relay checks rejected unknown/missing SNI, IP literal and a
selected-host subdomain; logs showed no backend. An apex entry never grants
descendants. Non-TLS/CONNECT and fragmented ClientHello are additional untested
coverage, not conditions for closing the accepted first iteration. Do not
use catch-all HostSNI, client-selected destinations, wildcard upstreams or ports.

Origins are explicitly prepared public unicast numeric IPv4 addresses and fixed
port 443. Reject non-global, multicast, reserved/private, loopback, link-local,
metadata and shared-address space, plus the relay's own ingress/public endpoints
and provider-specific service addresses, including public-looking service IPs
where applicable. `is_global` alone is insufficient. Unsafe or mixed DNS answers
must fail preparation; a hostname must not be substituted at runtime. Compare
every rendered `server` address with the reviewed origin record.

With numeric fixed backends, DNS changes after preparation cannot select a new
destination during connect. Refresh requires reviewed regeneration and bounded
recreation. Stale CDN addresses may fail until reviewed refresh; no dynamic
fallback is authorized. The design assumes ordinary routing to those public
addresses: altered host NAT/routes or a compromised Docker host remain outside
this application-level guarantee. Any future runtime DNS implementation needs
same-address post-resolution checking and actual forbidden-connect evidence;
see [relay research](relay-research.md).

DNS credentials do not protect a public TLS relay. Someone can connect directly
using either allowed SNI and consume relay capacity. A shared approved origin IP
can also serve other virtual hosts: passthrough cannot inspect encrypted HTTP
Host, so fixed IP/SNI checks do not eliminate domain fronting by an accommodating
origin/CDN. These fixed-target public relay residuals are documented; they do
not authorize extra configured targets. Bound memory, CPU, process/connection
counts, timeouts, logs and network
exposure; observe capacity during ordinary-device acceptance. Server operator
access remains privileged. A Docker socket mounted read-only still exposes a
sensitive daemon API; the isolated lab fixture is not a hardened production
security boundary or a production socket policy.

All lab images are digest-pinned in `config/images.lock.json`. AGH uses the
operator UID/GID and a dedicated writable config directory so native atomic
writes work; do not replace it with a single config-file bind. Its image binary
requires NET_BIND_SERVICE, restored for DNS only after dropping all capabilities.
Other services retain the capability drop. These are the tested settings, not a
claim of protection from a compromised host or daemon.

## Acceptance and approvals

The accepted lab covered missing/unknown ClientID denial, intended DNS answers
and omissions, exact-host parity, forbidden origin inputs, fixed numeric backend
configuration, TLSv1.3 certificate verification for both origins, relay rejection,
unrelated HTTP-router coexistence and bounded resource smoke checks. Own
containers/network were removed with the existing-container ID sets unchanged.
Preserve the report's binary/image identities, redacted observations and limits;
do not expand these results into load, production or full-product claims.

The [review follow-up](reports/2026-11-06/review-followup.md) owns the revised
case-normalization and URL-boundary results. Negative URLs are evaluated using
both HTTP status and selected RouterName so a routed backend 404 cannot be
misreported as an edge rejection. The earlier accepted run does not establish
the result of these changed inputs; keep follow-up outcomes explicit.

ECH, cached DNS/HTTPS/SVCB/Alt-Svc, QUIC, alternate resolver settings and incomplete
login/CDN coverage can defeat or bypass the intended path. Do not claim complete
service availability from an A answer or a successful root-page handshake.

Actual production deploy requires explicit approval of the final private
integration, ingress/certificate/network choice, limits, logging policy, exact
origins and rollback window. Production restarts, DNS changes or firewall edits
are not authorized by the offline deliverable. Device profile installation and
ordinary-user product acceptance remain separate steps when not already granted.
