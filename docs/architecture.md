# Offline pilot architecture

This is a candidate for issue #1, not authorization to deploy. The approved
representation is deliberately limited to exact `chatgpt.com` and `claude.ai`.
It does not establish complete ChatGPT/Claude login, assets, upload or API
coverage. Subdomains and other registry suggestions require a separate review.

## Owners and traffic

`rules/pilot.json` is the reviewed exact-host authority. `tools/render.py` is a
small representation adapter, not a DNS server or traffic proxy. Explicit local
settings supply ClientIDs, owned/excluded infrastructure zones, DoH hostname,
relay ingress, upstream/bootstrap resolvers and reviewed numeric origin IPv4s.
It makes no network requests, deployment calls or automatic registry imports.

One render produces:

| Artifact | Native owner and purpose |
| --- | --- |
| `agh-conf/AdGuardHome.yaml` | AdGuard Home v0.107.80: native ClientID admission and exact DNS `user_rules` |
| `haproxy.cfg` | HAProxy 3.2.26: exact SNI admission and fixed reviewed origin IPv4:443 |
| `compose.lab.json` | Disposable Traefik v3.6.25/AGH/HAProxy integration fixture; localhost entrypoint and an unrelated-site fixture |
| `snapshot.json` | Rules/origin fingerprint, selected hosts and image references from digest-pinned `config/images.lock.json`; retain separately hashed settings for an exact run |

DoH flows from a client to Traefik HTTPS termination at the resolver hostname,
then to AGH's private HTTP listener. Only the intended `/dns-query` and ClientID
paths may reach AGH. The path must survive proxying. AGH admits IDs through
nonempty native `dns.allowed_clients`; no IP or proxy-subnet admission exception
is allowed. Management/setup paths must stay inaccessible externally.

AGH also keeps its native plain-DNS listener on internal port 5353 because its
startup validator requires a DNS transport listener. Compose publishes no AGH
port. ID-only admission gives anonymous plain UDP no answer and plain TCP DNS
REFUSED, as verified by the native Windows check. This is an unpublished,
access-restricted listener, not a disabled listener.

For each exact selected host, AGH returns the relay IPv4 for A, and empty NOERROR
for AAAA/HTTPS/SVCB. Other types and hosts use ordinary DNS. A website TLS
connection reaches Traefik's exact `HostSNI` TCP rule, then HAProxy and its fixed
origin IPv4:443. Both preserve the original client TLS session; the origin owns
the website certificate. The original public DNS is used only during explicit
origin preparation, never during a live HAProxy connection.

The production read-only inspection established Traefik v3.6.25 with Docker
provider enabled, `exposedByDefault=false`, and file provider disabled. Integration
must therefore use explicit labels on the new services. Do not assume writing a
dynamic YAML file makes it active. Actual inventory stays in private evidence.

## Isolation and limits

The rendered Compose project is a disposable lab, not a production Compose
overlay. It starts its own edge and unrelated-site fixture, exposing localhost
18443 for edge and 18444 for direct relay negative checks. It does not attach to
production networks or mount production config/data. All four images have digest
pins in `config/images.lock.json`. AGH runs under the operator UID/GID with a
writable dedicated configuration directory for native atomic writes and matching
work tmpfs. Only its required NET_BIND_SERVICE capability is restored; other
capabilities remain dropped.

The isolated Linux run passed all 13 recorded probe rows: DNS admission/rewrites,
TLSv1.3 with verified certificates for both origins, unknown/no-SNI/IP/subdomain
relay rejection, and an unrelated HTTP router on the shared lab entrypoint.
Task-owned containers/network were removed and existing-container ID sets matched.
Native Windows AGH and offline contract evidence are also recorded in the
[acceptance report](reports/2026-11-06/acceptance.md). These results establish the
bounded lab behavior, not production or ordinary-device acceptance.

Production integration remains a manual, reviewed step: select the existing
Traefik network, certificate ownership, private AGH listener, exact DoH path
boundary and labels, ensure no own-domain overlap, and create a separate bounded
Compose definition. Do not start the lab edge on production. No production
Compose deployment is finalized by this repository.

The relay is publicly usable for its two approved fixed targets by anyone who
can reach it; DNS ClientIDs do not authenticate website traffic. This residual
limitation is accepted for the bounded pilot, subject to capacity/abuse limits.
Shared origin IPs also retain a domain-fronting risk: passthrough cannot inspect
the encrypted HTTP Host or enforce an application-level host allowlist.
See [security](security.md). TCP only: ECH, QUIC/UDP, cached Alt-Svc and IPv6 need
explicit client evidence; suppressing new records does not clear old caches.

## Change boundary

Review rules, origins and all generated artifacts together. Keep DNS/HostSNI/SNI
sets identical. Docker routing labels are container metadata, so a HAProxy reload
alone cannot publish a changed HostSNI set: recreate the new relay container.
For a changed host set, use the bounded stop-first procedure in
[rollback](rollback.md) to avoid serving mismatched generations. There is no
claim of atomic live changes across AGH, Traefik and HAProxy.

Source mechanisms and licensing are recorded once in [DNS research](dns-research.md),
[relay research](relay-research.md) and [registry research](registry-research.md).
Remaining work is production-specific integration/approval and ordinary-device
product acceptance. The report lists optional untested protocol coverage
explicitly; it does not reopen the accepted first-iteration lab result.
