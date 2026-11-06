# Pilot security boundaries

The [refactor GOAL](refactor.md) preserves native AGH, Traefik and HAProxy owners.
This describes the candidate; actual results and gaps belong in
[refactor acceptance](reports/2026-11-06/refactor-acceptance.md). Earlier reports
do not establish changed-code behavior. Production/Hermes/shared Traefik remain
unchanged; complete products/devices are outside this stage.

## Admission and administration

Nonempty native AGH `allowed_clients` contains random per-device ClientIDs only.
Do not add proxy/peer/loopback/public client IPs: IP-or-ID semantics bypasses ID
admission. `trusted_proxies` concerns attribution separately. Required plain DNS
5353 is internal/unpublished; ordinary TCP/UDP cannot supply a ClientID. Check
DNS RCODE/answers, not HTTP status alone: refused DoH can return HTTP 200.

Renderer requires `admin_username` and bcrypt `admin_password_hash`, configuring
native AGH authentication separately from DNS admission. Generate real hashes
with existing tooling such as `htpasswd -Bni <admin_username>` and protected input;
save the hash after the separator privately. Do not put cleartext in arguments or
shared transcripts. The public `lab-only-change-me` credential is only a disposable
fixture. No Python bcrypt runtime dependency is added; syntax validation of the
hash does not establish password strength.

AGH HTTP/admin binds internal 3000 without host publication. A dedicated network
joins only AGH and edge; other app containers stay outside it. Exact public DoH
routes exclude management/setup and malformed paths; native login also protects
direct peer/operator requests. Production needs its own reviewed network and
management policy. Unpublished ports alone do not isolate shared-network peers.

AGH needs a writable config directory for atomic native writes, operator UID/GID
and matching work tmpfs. Only its required NET_BIND_SERVICE is restored after
capability drop. Docker host and read-only socket mount remain privileged trust
boundaries: `:ro` does not make daemon API access unprivileged.

## Limits and secret handling

Native middleware order is canonical Host overwrite → rateLimit 20/s burst 40 →
inFlightReq 8. Both use requestHost after normalization, preventing client Host
case/port variants multiplying buckets. These are aggregate per-router/process
budgets, not per-ID fairness or bandwidth quotas. Requests later refused by AGH
also consume them. Measured enforcement does not establish sustained production
capacity or protection of Hermes.

AGH `dns.ratelimit:20` is UDP-only: pinned dnsproxy gates its
[limiter on ProtoUDP](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/ratelimit/ratelimit.go#L51),
whereas [DoH uses ProtoHTTPS](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/proxy/serverhttps.go#L254).
The separate native Traefik middleware supplies the HTTP budget.

ClientIDs are bearer secrets in paths. Native DoH-router
`observability.accessLogs:false` excludes matched requests while retaining other
router logs. Denied URLs can also contain a valid ID and do not inherit this
router setting. Lab global field/header allowlisting retains only
router/service/status and synthetic X-Lab-Case; no paths/queries. Wire-level
checks own legitimate DoH acceptance; no DoH log row is intentional. Production
needs separate safe denied-request handling without disabling unrelated logs.

AGH query logs/statistics are disabled. Errors, HTTP tracing, shell output,
proxies and backups still need secret handling. Keep settings, generated configs,
password files/hashes, full credential URLs, keys and private evidence outside
Git. Share hashes/receipts rather than their secret source files; rotate an
exposed ID through the native owner.

## Destinations and residuals

DNS, exact Traefik HostSNI and lowercased exact HAProxy SNI share one approved
host set. Origins are reviewed numeric public unicast IPv4:443; reject private,
reserved/non-global, loopback, metadata/link-local, multicast, IPv6, provider
service and own ingress/public addresses. Refresh is reviewed preparation, never
hostname fallback or client-selected destinations. Runtime DNS rebinding cannot
change the fixed connection target.

HAProxy retains global maxconn 256, connect 5s and client/server idle 60s. Native
Traefik TCP inFlightConn is per IP; its transport dialTimeout is not an idle limit.
See [architecture](architecture.md). Memory/CPU/PID/log bounds complement these
controls but imply no sustained-load or bandwidth guarantee.

ClientID does not authenticate public relay traffic: anyone can consume capacity
using approved SNI. An approved shared origin can support domain fronting because
passthrough cannot inspect encrypted HTTP Host. These residuals grant no extra
configured targets. Compromised daemon/host, altered NAT/routes, CDN policy/region
changes, ECH/QUIC and cached resolver/Alt-Svc behavior remain outside this proof.

Planned candidate checks cover native admin/GET/revocation/direct-peer,
effective DNS/label/relay parity, running-image identity, rate/concurrency and
failed-candidate restore checks. Read the new report for completed results and
limits; counts alone are not product acceptance. Production and ordinary-device
acceptance remain separate, without extending this refactor to universal coverage.
