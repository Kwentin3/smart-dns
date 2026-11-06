# Relay selection for issue #1

Research date: 2026-11-06. Scope: an offline pilot; no server changes, public
listeners, DNS overrides, or deployment. This document records source evidence,
not successful runtime acceptance.

## Recommendation

Use ready-made **HAProxy 3.2.26 in TCP mode**, with one exact SNI entry and one
fixed, reviewed, globally routable IPv4 origin on port 443 for each approved
domain. Traefik owns the public `HostSNI` route; HAProxy repeats the exact
allowlist at its own boundary. Neither component terminates client TLS.

For this small pilot, resolve origins during explicit preparation, validate the
result, and render numeric `server` addresses. Do not put origin hostnames,
wildcards, a runtime resolver, `set-dst`, or client-selected ports in the delivered
HAProxy configuration. This closes the DNS check/connect race by removing DNS
from the connect path. An answer changing after preparation cannot redirect an
existing numeric backend to a private address. This is a bounded design choice,
not a claim that stock HAProxy automatically filters arbitrary DNS answers.

The preparation validator must reject every non-global address, private,
loopback, link-local, unspecified, multicast, reserved, documentation and shared
address space; only IPv4 is in scope. Explicitly reject infrastructure addresses
too: the VPS's own public addresses, relay ingress, and cloud-provider service or
metadata addresses, including public-looking ones such as `168.63.129.16` when
applicable. Reject missing or mixed unsafe answers rather than choosing a safe
member silently. `ipaddress.is_global` alone is insufficient for multicast and
provider-specific service addresses. Reject syntax that could inject a HAProxy
directive. A failed refresh leaves the accepted configuration unchanged.

Origin changes require fresh resolution, validation, review and reload. A stale
origin may stop working; it must not trigger a hostname fallback. IPv6, NAT64,
DNS-driven failover and automatic CDN rotation are outside this pilot.

## Version and evidence

- [Official 3.2 source releases](https://www.haproxy.org/download/3.2/src/):
  `haproxy-3.2.26.tar.gz`, released 2026-10-14.
- [Pinned source archive](https://www.haproxy.org/download/3.2/src/haproxy-3.2.26.tar.gz)
  and [publisher SHA-256](https://www.haproxy.org/download/3.2/src/haproxy-3.2.26.tar.gz.sha256):
  `760ef35fafc1e05844e73ad07e138e9e96fddbf5de02f606249c027f754827da`.
  Downloaded into memory and independently hashed during this research; matched.
- Official stable Git repository:
  `https://git.haproxy.org/git/haproxy-3.2.git`, tag `v3.2.26`, peeled commit
  `3e0f11a846f5dfc886840c90814da9695e28d2c1`, verified with `git ls-remote`.
  Main GitHub release tag `v3.2.0` is older; it must not be mistaken for the latest
  maintenance source.
- [HAProxy configuration manual, 3.2](https://docs.haproxy.org/3.2/configuration.html):
  `mode tcp`, `req.ssl_sni`, `tcp-request inspect-delay`, content ACLs and numeric
  `server` addresses provide the required building blocks. The online manual can
  move; the archive's `doc/configuration.txt` is the pinned authority.
- [HAProxy licensing](https://github.com/haproxy/haproxy/blob/v3.2.0/LICENSE):
  GPLv2 core, LGPL exportable headers and OpenSSL linking exception; the same
  license file was inspected in the 3.2.26 archive. Preserve license notices if
  redistributing a binary/container. Container image digest is a separate pin
  that must be recorded by implementation; a source SHA does not pin an image.

In the verified 3.2.26 archive, `src/backend.c:alloc_dst_address` copies the fixed
server sockaddr and service port into the connection destination. It consults
the client's destination only when the server address is unspecified. Therefore
the recommended configuration requires a concrete approved numeric address and
must reject `0.0.0.0`, rather than treating it as an ordinary backend.

## Minimal configuration shape

Illustration for one exact domain, not a deployable origin assignment.
`ORIGIN_PUBLIC_V4` must be supplied only by the reviewed preparation result; the
delivered configuration should contain the numeric literal after rendering.
`example.com` must be replaced by an explicitly approved hostname in both layers.
The relay port is internal to the isolated pilot network and must not be published
on the VPS. Traefik forwards original TLS bytes and sends no PROXY header unless
both sides are deliberately configured for it.

```haproxy
global
    maxconn 128

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    retries 0

frontend relay_tls
    bind :8443
    tcp-request inspect-delay 5s
    acl hello req.ssl_hello_type 1
    acl allowed req.ssl_sni,lower -m str example.com
    tcp-request content reject if hello !allowed
    tcp-request content accept if hello allowed
    tcp-request content reject if WAIT_END
    use_backend exact_example if allowed

backend exact_example
    server origin "${ORIGIN_PUBLIC_V4}:443"
```

An additional domain gets its own exact allowlist entry, routing condition and
fixed backend. No default forward backend, `ssl` bind, backend `ssl`, certificate,
HTTP CONNECT, wildcard, hostname resolver or transparent source mode is needed.
The final pinned lab passed `haproxy -c` and normal TLS passthrough with the
generated configuration; fragmented ClientHello remains untested. See the
[acceptance report](reports/2026-11-06/acceptance.md). Listener/source isolation,
limits and logs belong to the pilot integration, not to a new proxy implementation.

## Alternatives and dynamic DNS boundary

| Candidate | Exact SNI + fixed numeric origin | Native dynamic-answer protection evidence | Decision |
| --- | --- | --- | --- |
| HAProxy 3.2.26 | Yes, TCP ACLs and explicit backend | Yes, configurable `do-resolve` → IP ACL → `set-dst`; source evidence below, runtime acceptance pending | Preferred; fixed-origin variant first |
| nginx stream, reference 1.28.0 | Yes, `ssl_preread` + exact `map` + explicit upstream | No sufficient built-in post-resolution destination-deny proof established in reviewed stream directives | Capable fixed-origin alternative, less reason to switch |
| sniproxy 0.6.1 | Yes, anchored table regex and numeric target | No sufficient native post-resolution private-range deny evidence established | Avoid dynamic `*:443` target for this pilot |

Primary alternative sources:

- [nginx SSL preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)
  and [stream proxy](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html)
  describe extracting SNI without termination and forwarding to an upstream.
  [Pinned 1.28.0 source](https://github.com/nginx/nginx/tree/release-1.28.0),
  [license](https://github.com/nginx/nginx/blob/release-1.28.0/LICENSE): BSD-style.
  Stream/preread module availability must be checked in the actual build.
- [sniproxy 0.6.1 configuration](https://github.com/dlundquist/sniproxy/blob/0.6.1/sniproxy.conf)
  defines table patterns as regular expressions and supports numeric, hostname
  and wildcard targets. Exact matching therefore needs anchors and escaped dots.
  [Connection source](https://github.com/dlundquist/sniproxy/blob/0.6.1/src/connection.c)
  and [BSD-2-Clause license](https://github.com/dlundquist/sniproxy/blob/0.6.1/COPYING)
  were inspected. A hostname allowlist alone does not establish safe resolved IPs.

HAProxy's pinned manual explicitly permits `do-resolve` in `tcp-request content`,
stores a chosen IP in a variable, and includes a local-network prevention example.
The 3.2.26 source was inspected directly from the checksum-verified archive:

1. `src/resolvers.c:resolv_action_do_resolve` copies the selected DNS answer into
   an IPv4/IPv6 typed variable.
2. ACL rules can reject this same variable using `-m ip` before forwarding.
3. `src/tcp_act.c:tcp_action_req_set_dst` copies that typed address into the
   stream destination; `set-dst-port int(443)` fixes the destination port.
4. `src/backend.c:alloc_dst_address` uses that sockaddr for an unspecified numeric
   backend; the connect path copies the stream sockaddr into `srv_conn->dst`.

This is affirmative source evidence of check-then-connect to the **same numeric
address**, with no second hostname lookup in that path. It is not evidence that
all unsafe ranges are denied by default or that the candidate has passed runtime
rebinding tests. A dynamic variant must reject unset variables, every prohibited
IPv4/IPv6/transition range, provider service addresses and the relay's own public
IP; handle partial ClientHello input; and never forward before its checks.
`ipv4` on `do-resolve` is a preference, not a strict family restriction.

If a later implementation cannot prove the full native dynamic policy, keep the
fixed-origin design or add a thin egress firewall/network guard around an isolated
relay namespace. The guard must filter the actual destination for every new TCP
connect, cover both families, allow only reviewed origins on 443, separately allow
an approved resolver when needed, and deny private/link-local/metadata/self
addresses. Filtering DNS responses alone does not prove safe connect behavior.
No firewall change is proposed for production by this document.

## Acceptance still required

Run in a disposable Linux pilot, after candidate review; do not use production.

1. Check the exact binary version/image identity and `haproxy -c` for generated
   configs. Reject unsafe/mixed DNS results, malformed hostname/address input,
   wildcard names, non-443 ports, IPv6 and unspecified numeric backends before
   config generation. Check every generated destination against the accepted
   preparation record.
2. Verify the ordinary TLS client sees the origin certificate and a successful
   application response through Traefik and HAProxy. Also compare ALPN and test a
   fragmented ClientHello; no-SNI, unknown SNI, suffix/prefix lookalikes, invalid
   TLS and HTTP CONNECT must produce zero origin connections.
3. In an isolated mock DNS fixture, prepare an allowed hostname to a public-form
   fixture IP, then change DNS to loopback/private/link-local/metadata/self IPs.
   Observe actual connect destinations: fixed-origin config must remain numeric
   and unchanged; a regeneration attempt must fail closed. Do not contact real
   metadata services. Mixed/CNAME unsafe answers require negative cases too.
4. For any future dynamic variant, change DNS between lookups and repeat against
   each prohibited family/range; packet/socket evidence must show no forbidden
   connection. Source review alone does not close this acceptance item.
5. Check direct relay access is unavailable outside the pilot boundary, unknown
   HostSNI cannot enter the relay, ordinary non-pilot Traefik routing is unchanged,
   and timeout/concurrency bounds hold. ECH/hidden SNI and QUIC/UDP are outside the
   passthrough TCP pilot and must not be claimed supported.

The [final acceptance report](reports/2026-11-06/acceptance.md) closes the fixed-origin
syntax, image-digest, normal-TLS integration and selected negative-path smoke checks.
Fragmented handshakes, dynamic-resolver attacks, full product flows and production
acceptance remain unverified. The dynamic-resolver variant was not implemented.
