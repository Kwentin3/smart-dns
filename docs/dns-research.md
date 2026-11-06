# DNS research: first offline iteration

Research date: 2026-11-06. Scope: primary-source inspection and bounded native Windows checks; no server changes. Source-backed findings and runtime findings are distinguished below. Final receipts and remaining gates belong in the [acceptance report](reports/2026-11-06/acceptance.md).

## Pinned owner and version

Use AdGuard Home **v0.107.80**, stable release dated 2026-11-03, rather than `latest` or the v1 beta. Git annotated tag `fd87ea1b0d2ca10ccc060873a894659f51c22a04` resolves to commit **003d6e1e15e04127f6d6d5e2f5c1aa843130752a**. Verified using GitHub Git refs/tag API. Record the chosen platform archive checksum independently before execution.

- [Release](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.80)
- [Tag API](https://api.github.com/repos/AdguardTeam/AdGuardHome/git/tags/fd87ea1b0d2ca10ccc060873a894659f51c22a04)
- [Schema: configmigrate.go, lines 3–4](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/configmigrate/configmigrate.go#L3): `schema_version: 34`.

## Native admission: PASS from source

DoH supports `/dns-query/<ClientID>`; DoT uses `<ClientID>.dns.example.net`, requiring matching DNS and wildcard TLS certificate. URL identity takes priority over hostname identity. [Official client instructions](https://adguard-dns.io/kb/adguard-home/clients/).

A nonempty `dns.allowed_clients` containing **only ClientIDs** rejects missing and unknown IDs. Important: native admission permits an allowed IP **or** an allowed ID. Adding loopback, a proxy subnet or a public client IP creates a route that accepts anonymous requests from that IP. Persistent client registration supplies per-client settings; it does not by itself restrict admission. Use a different random, revocable, lowercase DNS-label-safe ID per device. Treat IDs as bearer secrets, not cryptographic device identities.

- [access.go, lines 100–117](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/dnsforward/access.go#L100): allowlist mode and missing/unknown IDs.
- [dnsforward.go, lines 903–933](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/dnsforward/dnsforward.go#L903): IP/ID OR semantics.
- [clientid.go](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/dnsforward/clientid.go): hostname identity extraction.

The version-specific insecure DoH key is **`http.doh.insecure_enabled`**, not the older `tls.allow_unencrypted_doh`. Default routes include GET and POST at `/dns-query` and `/dns-query/{ClientID}`. [Config definitions, lines 180–219](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/home/config.go#L180).

## Native fixture configuration

The native run used a deterministic localhost UDP upstream and no service installation or system DNS change. The example below uses fixed illustrative ports; the harness allocates its upstream port. IDs and addresses are public examples. AGH merges defaults and writes a normalized config, reviewed at `.local/native-agh/AdGuardHome.yaml`.

**FAIL, rejected candidate:** `serve_plain_dns: false` with only insecure HTTP DoH fails native startup: `validating plain: disabling plain dns requires at least one encrypted protocol`. An HTTP DoH listener does not satisfy this native encrypted-listener requirement.

**Chosen adaptation:** keep plain DNS enabled on an unpublished internal port 5353 in the rendered container config. The native fixture binds it to loopback port 15353. Retain ClientID-only admission: plain UDP gets no reply and plain TCP gets DNS REFUSED. Thus plain DNS has a listener but cannot serve useful anonymous answers under this allowlist. No public 53/5353 port is published.

```yaml
schema_version: 34
http:
  address: 127.0.0.1:13000
  doh:
    insecure_enabled: true
dns:
  bind_hosts: [127.0.0.1]
  port: 15353
  serve_plain_dns: true
  allowed_clients: [test-device-0123456789abcdef0123456789abcdef]
  disallowed_clients: []
  upstream_dns: [127.0.0.1:15354]
  fallback_dns: []
  bootstrap_dns: []
  use_private_ptr_resolvers: false
  serve_http3: false
  use_http3_upstreams: false
  cache_enabled: false
tls:
  enabled: false
  port_https: 0
  port_dns_over_tls: 0
  port_dns_over_quic: 0
filters: []
whitelist_filters: []
user_rules:
  - '|chatgpt.com|$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10'
  - '|chatgpt.com|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;'
```

`user_rules` belongs at the top level ([config.go, line 152](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/home/config.go#L152)). Single `|` anchors both ends: exact host only. `||` would include subdomains. Restrict the A rewrite to A queries so unrelated TXT/MX queries keep normal resolution. The second rule requests empty NOERROR responses for the three selected types. Exact selected A, empty AAAA/HTTPS/SVCB and nonmatching-name behavior passed the native fixture. TXT/MX and CNAME behavior remain untested. [Official rule grammar, anchors and modifiers](https://adguard-dns.io/kb/general/dns-filtering-syntax/).

Production adaptation requires valid TLS, reachable bootstrap DNS, appropriate upstreams and a generated private ID. Keep management local. If a reverse proxy terminates TLS, expose only the intended DoH paths, preserve the ClientID path and trust only the actual proxy; do not allowlist its IP. Native HTTPS can share the management handler, so a public HTTPS port alone does not establish management isolation.

## Relay and modern transport limits

`dns.ratelimit: 20` is a native **UDP-only** limit, not DoH abuse protection.
AGH pins dnsproxy v0.83.2; its [limiter protocol gate](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/ratelimit/ratelimit.go#L51)
checks `ProtoUDP`, while [HTTP/HTTPS DoH uses ProtoHTTPS](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/proxy/serverhttps.go#L254).
There is consequently no shared Traefik-IP DoH bucket from this setting, and no
DoH request limit from it either. Plan DoH rate/concurrency limits separately
before activation; never add the proxy to `allowed_clients`. `trusted_proxies`
only controls source attribution, separately from admission. This is pinned
source evidence, not a multi-device load test.

| Question | Finding | Status |
|---|---|---|
| Does AGH carry selected website traffic? | Its reviewed configuration and [documented capabilities](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/README.md) provide DNS filtering/rewriting, encrypted DNS and DHCP. No native target HTTPS/SNI relay was established. A rewrite changes destination discovery; it does not relay application traffic. Use a separate established relay. This is a bounded source-review conclusion. | PASS, bounded |
| Does DNS ClientID protect that relay? | No admission connection is established by the DNS mechanism. Any public relay needs its own bounded target policy and admission decision. A successful DNS test cannot close this gap. | NOT_TESTED |
| IPv6 bypass | A rewritten A alongside an original AAAA can send IPv6 clients directly to the origin. For selected hosts, provide a working relay AAAA or return AAAA NODATA; do not disable IPv6 globally. | NOT_TESTED |
| HTTPS/SVCB bypass | Records can advertise alternative targets, addresses, ALPN and ECH data. Exact selected-host NODATA is the conservative initial policy; verify with real clients. [RFC 9460 §§7.1–7.3](https://www.rfc-editor.org/rfc/rfc9460.html). | NOT_TESTED |
| ECH | A relay choosing upstream by plaintext SNI cannot assume the real origin name remains visible. ECH encrypts it; cached/preconfigured ECH can remain after DNS suppression. [RFC 9849 §§3.2, 8.2](https://www.rfc-editor.org/rfc/rfc9849.html), [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html). | NOT_TESTED |
| HTTP/3 and QUIC | A TCP SNI relay does not implement UDP QUIC. Browsers may fall back to TCP if UDP is unavailable, but application success must be tested. Cached Alt-Svc also matters. Disabling AGH DoQ/HTTP3 only affects DNS transport, not website HTTP/3. [RFC 9114 §3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1). | NOT_TESTED |

## Client delivery

| Client | Native first choice and limitation | Evidence/status |
|---|---|---|
| iOS/iPadOS | DNS Settings profile with `DNSProtocol: HTTPS` and full `ServerURL: https://dns.example.net/dns-query/<ID>`. Optional `ServerAddresses` avoids bootstrap dependence. Profile installation/removal and actual app behavior require device acceptance. | [Apple DNSSettings](https://developer.apple.com/documentation/devicemanagement/dnssettings/dnssettings-data.dictionary); NOT_TESTED |
| Android | Private DNS provider hostname can identify a device using `<ID>.dns.example.net` over DoT; arbitrary DoH URL paths are not the standard hostname field. Requires wildcard DNS/certificate and TCP 853 reachability. Built-in encrypted transports vary by Android version/provider; do not claim arbitrary DoH URL support from the Private DNS field. | [Android Private DNS description](https://developer.android.com/work/versions/android-10), [AGH ClientID formats](https://adguard-dns.io/kb/adguard-home/clients/); NOT_TESTED |
| Windows | Configure an OS-supported DoH template with the full ID path, map it to the resolver IP and disable UDP fallback. Exact Windows version and interface configuration must be checked; a browser setting alone does not configure other apps. | [Microsoft DoH client](https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support), [fallback/template flags](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientdohserveraddress); NOT_TESTED |
| Browsers | Custom DoH URL with ID works only for the browser resolver. Select strict/custom behavior and check policy restrictions, exceptions, bootstrap and other applications separately. | [Chrome custom provider/fallback](https://support.google.com/chrome/answer/10468685), [Firefox protection modes](https://support.mozilla.org/en-US/kb/dns-over-https); NOT_TESTED |

## Native runtime evidence and remaining checks

The primary agent ran [tools/test_native_agh.py](../tools/test_native_agh.py) against the pinned native binary and reported PASS for the following bounded behavior. The normalized config and server log were independently read back during this research review; test receipts are consolidated in the acceptance report.

| Behavior | Native result |
|---|---|
| Missing and unknown ClientID | PASS: HTTP 200 with DNS REFUSED and zero answers; HTTP status alone would misclassify admission. |
| Both pilot hosts, `chatgpt.com` and `claude.ai` | PASS: exact A rewrite; AAAA, SVCB and HTTPS return empty NOERROR. |
| Ordinary fixture host and selected-host subdomain | PASS: no relay rewrite; fixture resolution retained. |
| Anonymous plain UDP/TCP | PASS: UDP no response; TCP REFUSED with zero answers. |

The harness uses POST. GET, revocation, forged forwarding headers, TXT/MX and CNAME scenarios are **NOT_TESTED**. Source inspection establishes intended admission semantics; it does not prove those unexercised scenarios. The harness terminates its process and upstream thread in `finally`; final socket/process cleanup evidence belongs in acceptance.

Local HTTP establishes native DNS behavior only. Real TLS, DoT, certificates, edge management isolation, relay admission, IPv6/QUIC/ECH and ordinary-device product acceptance remain **NOT_TESTED** until separately exercised. Linux/container parity also remains untested on this Windows machine.

## Normalized-default review

Current render explicitly sets the upstreams, empty fallback/filter lists, disabled query logging/statistics and ClientID admission. Normalized AGH confirms safe browsing, parental controls and Safe Search are disabled; the block-host names in that config do not imply enabled lookups. `--no-check-update` is already used by the native harness.

The readback also exposes defaults that the minimal isolated profile should disable explicitly:

- `clients.runtime_sources.whois` and `rdns` are true: they can initiate identity lookups. Set the whole runtime-source block (`whois`, `arp`, `rdns`, `dhcp`, `hosts`) to false because client discovery is unnecessary here.
- `dns.hostsfile_enabled` is true: set false to avoid host-dependent answers from the machine's hosts file.
- `dns.handle_ddr` is true: set false because native encrypted resolver discovery is not part of the edge-terminated DoH profile.
- Add `--no-check-update` to the container launch as well. Keep `whitelist_filters: []` explicit for reviewability, although it normalizes empty already.

These are recommendations from the reviewed config, not claims that outbound traffic occurred. No external-fetch or packet-capture test was performed. Preserve the working native filtering settings; disabling protection or filtering to reduce external features would change the owner of the tested rewrite path. No such broad toggle is recommended.
