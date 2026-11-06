# PR #2 review follow-up, 2026-11-06

Scope: the three nonblocking technical comments in
[review 5800437428](https://github.com/Kwentin3/smart-dns/pull/2#pullrequestreview-5800437428).
No production commands or changes. Same approved isolated Linux lab and pinned
images as the initial run. Both trial stacks removed; private evidence retained
under ignored `.local/review-before/` and `.local/review-after/`.

## Observed cause and correction

1. **SNI case mismatch confirmed.** Mixed-case approved names failed TLS through
   the shared edge and directly at HAProxy before the fix, while lowercase
   names worked. Traefik [canonicalizes incoming SNI](https://github.com/traefik/traefik/blob/v3.6.25/pkg/muxer/tcp/mux.go#L22)
   using [lowercase](https://github.com/traefik/traefik/blob/v3.6.25/pkg/types/domains.go#L51);
   HAProxy's generated string ACL did not. Added native `req.ssl_sni,lower`.
   Both approved mixed-case names now complete TLSv1.3 with origin CA/hostname
   verification, through edge and directly at relay. Mixed-case subdomain and
   suffix lookalike still fail directly at relay.
2. **Broad path boundary confirmed, no demonstrated management disclosure.**
   Seven negative paths matched the old DoH router before receiving AGH 404.
   Replaced PathPrefix with exact `/dns-query` or an anchored ClientID path
   regex. Compose `$$` preserves a literal regex `$` in the actual Docker label.
   All 12 negative paths now return edge 404 without matching the DNS router.
   Three legitimate shapes still reach AGH; anonymous and unknown IDs produce
   DNS REFUSED, authorized ID works. Tested raw lookalikes, management/setup/root,
   trailing slash, literal/encoded/double-encoded traversal and backslashes.
   `http.client` preserves the raw paths and does not follow redirects.
3. **Rate-limit assumption corrected from pinned source.** `dns.ratelimit:20`
   applies only to UDP, not HTTP/HTTPS DoH. There is neither a shared proxy-IP
   DoH bucket nor DoH request limiting from that setting. See
   [pinned protocol gate](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/ratelimit/ratelimit.go#L51)
   and [DoH context protocol](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/proxy/serverhttps.go#L254).
   Documentation now requires separate DoH capacity/abuse planning. ClientID-only
   admission is unchanged; proxy trust for attribution never grants DNS access.

The lab edge now records only router/service/status and a synthetic case header,
with all other fields/headers dropped. This bounded native diagnostic separates
edge 404 from AGH 404. The harness checks the temporary ClientID is absent in
actual edge logs. Paths, queries and other request headers are not retained.
This does **not** accept the existing production logging configuration.

## Evidence

Before input SHA256: `f2d0724be5ef75a6b819c80d7fc1eb04859774e109d925253d2ff6664d791cb2`.
After input SHA256: `f98954be79e33f1b3edf052ba72c8501d41fe3412d2f5042fbf72bc2d3dbf09f`.
Both archive hashes matched sender/receiver. The before run added only bounded
diagnostics/test orchestration to the prior routing behavior. `--observe-review`
records expected baseline failures and is never acceptance. The after run
uses the default strict assertions and exited 0.

[Public result receipt](review-results.json) records source hashes, before/after
observations and original regression probes. Current runtime source bytes were
compared to after-archive members. The original receipt remains historical;
it is not presented as evidence for changed code.

| Check | Result |
| --- | --- |
| Four mixed-case approved TLS handshakes | PASS, system CA/hostname verification |
| Two mixed-case relay lookalikes | PASS, TLS rejected without completing handshake |
| Fifteen raw URL cases with actual RouterName | PASS, 3 legitimate shapes / 12 edge denies |
| Original DNS/TLS/coexistence regression matrix | PASS, 13 probes |
| Actual edge log contains no temporary ClientID | PASS |
| Offline configuration contracts | PASS, 10 tests |
| Cleanup for both runs | PASS, own containers/network removed; same 15 existing container IDs |

The first observation harness incorrectly expected the shared edge to reject
unknown-SNI TLS itself; it can legitimately terminate TLS for unrelated HTTP
routes. Those two observations are excluded from the baseline acceptance matrix
and retained in private raw results. The strict negative-SNI requirement is
tested at the relay. This correction does not weaken that relay assertion.

Reproduction in an approved disposable Linux copy:

```sh
python3 -m unittest discover -s tests -v
timeout --signal=TERM --kill-after=30 480 bash tools/run_lab.sh
```

## Still required before production

Approve a private integration using a narrow Traefik↔AGH network or separately
protected management/API. AGH `users:[]` on its internal HTTP listener is not
safe for a shared network of applications. Real DoH certificate/log redaction,
explicit DoH limits, ordinary iOS/Android/Windows tests, login/CDN dependencies,
production Compose approval and device rollback remain outstanding. Nothing in
this follow-up activates the service or closes those product steps.
