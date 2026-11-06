# Registry expansion and update delivery

Scope: the registry milestone of [product issue #3](https://github.com/Kwentin3/smart-dns/issues/3).
The complete product remains open. Earlier production evidence belongs to
[production-pilot.md](production-pilot.md); it does not establish deployment of
this revision.

## Source and ownership

The existing generated Sing-box v2 JSON in
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/tree/sing)
avoids implementing a Geosite parser. The accepted snapshot contains 2019 index
entries at `7da04853058c4a8858f339b266353fc905ef4eb4`; these include categories
and attribute variants, not 2019 proven geoblocked services. Only configured
definitions are fetched. A repeat real collection returned the same commit and
no changes, without modifying accepted data.

`rules/registry.json` retains the accepted index, selected raw definitions,
normalized exact/suffix matchers, unsupported predicates and source/license
provenance. The generated branch lacks a license file; the separately pinned
GPL-3.0 license from master is retained in full with its own reference. Cached
raw definitions are reused only after checking their Git blob hash. Source
failure, missing selected lists, unknown license or oversized/truncated data
cannot replace accepted inputs.

`rules/pilot.json` remains the sole owner of desired service selection, reasons,
manual overrides, exclusions and approved authority. Exact approval never grants
suffix authority. New roots stay pending. Regex, keyword and compound predicates
remain visible and are not silently approximated. A source list is discovery
evidence, not evidence that its service works through this VPS.

## Verification

| Boundary | Evidence | Result |
| --- | --- | --- |
| Source transport / normalized matchers / atomic proposal | Fixture Git trees and actual raw blobs, compound-rule quarantine, wrong pin/owner refusal, late fetch/write failure preserving accepted inputs | PASS |
| Desired authority / CLI | Actual projection, label-bounded suffixes, exact-to-suffix refusal, partial consent, disable, read-only wide-index CLI | PASS |
| Native AGH suffix / exceptions | AGH v0.107.80, actual compiler output, 18 names × A/AAAA/SVCB/HTTPS; owned zones, lookalikes, deep children, exact and zone exclusions | 72 PASS; cleanup PASS |
| Overlapping exact and suffix | Native AGH initially emitted duplicate identical A records; minimizing the positive wire union fixed the repeated 72-case run while preserving desired metadata | Fixed and verified |
| Full unit suite | 89 tests, including native-word-budget, Compose literal-dollar labels and read-only actual-status contracts | PASS |
| Actual Traefik / HAProxy suffix routing | 33 checks: public-CA origin TLS through edge and direct relay, actual-SNI own HTTPS, selected A/AAAA/SVCB/HTTPS, excluded names and label-boundary lookalikes | PASS; cleanup PASS |
| Bounded policy scale | Native HAProxy syntax in dynamic and fixed-origin modes and observed Traefik TCP routing for 2048 exact patterns; edge memory 19.21 MiB under its 128 MiB limit | PASS parsing/resource smoke; traffic capacity not claimed |
| Native actual status | Before apply: mounted five-host generation and four desired/actual discrepancies. After apply: mounted eight-namespace generation, matching rules/image/labels/bytes, no findings | PASS |
| Scheduled source workflow on the default branch | Daily collector and one proposal PR, candidate identity checks, contracts before publication | Pending activation/run |
| This revision in production | Corrected operator `5a5ab39`, eight approved namespaces; native apply/readback preserved admission and all protected containers. External verified DoH/DoT and origin TLS: 96 checks | PASS technical rollout; application/device acceptance remains open |

Exact-only legacy smoke/lab consumers now use the same registry projection and
refuse active suffix policies. They cannot silently validate a smaller manual
host list. Native suffix verification uses its separate fixture. Independent
source/workflow review found no blocking defects; actual workflow execution
remains required.

The first full-route fixture used an unsupported `.json` file-provider extension;
changing the fixture extension to `.yaml` allowed the native JSON-compatible YAML
to load. This file provider exists only in the isolated test edge, without Docker
socket/Traefik discovery labels, because the home lab has another running edge.
No file provider was added to production.

The scale run exposed a real renderer defect: listing every negated ACL name in
one condition exceeded HAProxy's 64-word directive limit. A single native ACL
with repeated OR declarations keeps that condition constant-sized. The repeated
33-case route run and 2048-pattern run passed after this fix. Existing home
container IDs and StartedAt values remained identical; owned containers/networks
were removed after every completed experiment.

Mixed-case `Auth.OpenAI.Com` still timed out during public-origin TLS. A logging-
only diagnostic proved direct-relay admission and selection of `104.18.41.241:443`;
a direct control to exactly that IP passed with lowercase SNI and timed out with
mixed case. The host's system DNS resolved other public IPs, so its initial direct
success was not an equivalent control. This is an observed external-path
limitation, with unknown cause, not proof of a specific provider or DPI fault.
Initial failures are retained separately from normal-case acceptance.

A correlated diagnostic subsequently proved mixed-case policy admission through
both direct relay and edge: original SNI, normalized session host, selected native
backend and the same public connection destination were observed. Both proxied
mixed-case TLS timeouts reproduced in direct same-IP controls; those external TLS
results remain `FAIL_EXTERNAL`, not TLS PASS. Diagnostic container/network cleanup
passed. The accepted normal-case run used unmodified compiled relay policy.

The native route/scale renderer SHA-256 is
`a098daad216a10503ae1d3efd5187901ff30bafcdaaf362d12d0b8bf8a52eda1`.
Collected private evidence was read back locally before the disposable remote
directory was removed. No owned runtime resources remain on the home lab.

The desired pilot now imports eight reviewed source namespaces for ChatGPT and
Claude login/API/assets/content, with OpenAI's unsupported regex explicitly
retained as partial. Other source roots stay pending. Generic Google/Microsoft
vendor bans from the first exact-only experiment were removed: explicit service
selection, own-zone exclusions and destination-IP guards own that boundary.
This desired edit alone does not apply the new policy.

The first authorized production update failed the final native routing-label
comparison and automatically restored the mounted five-host generation and its
native rules. Restore readback passed. The verifier had compared Compose's `$$`
regex escape to Docker's literal `$`; it now compares the native representation.
The source artifact comparison remains exact. A suffix-bundle regression also
rejects an actual changed regex, rather than relaxing route validation.
The corrected operator `5a5ab39` subsequently applied successfully. Native
readback independently reports `matches` for desired revision 4, generation
`424c3ed273975de9e79ff49d5e5f94f915f5655b6f343fc31a7c6765e06fa4ce`.
Actual Docker inspection confirmed the literal-dollar conversion. Admission and
every protected host container remained unchanged. From outside the VPS, 96
checks passed: verified DoH/DoT rewriting and A/AAAA/SVCB/HTTPS behavior across
all eight namespaces, selected login/API/assets/file children, positive ordinary
DNS, unauthorized-client refusal and ten public-CA origin TLS handshakes. These
probes do not log in, send messages or upload a user file.

## Automation boundary

There is one source scheduler, GitHub Actions, scheduled daily at 06:23 UTC.
It collects facts and updates a single bot-owned proposal branch/PR. It does not
auto-merge, deploy, change service preferences or alter native client/admin state.
Bot-created PRs do not start independent PR CI through `GITHUB_TOKEN`; candidate
contracts therefore run before publication in the trusted update workflow.

Approved suffixes already cover new children and native HAProxy resolution
refreshes their addresses. New domain roots and unsupported semantics require
review. Publishing a source snapshot or a proposal alone does not prove the
runtime was updated. Service-only application continues through the existing
bounded operator with native readback and rollback.

Real router/phone use, home-to-mobile switching and application login/message/
file/CDN/reopen remain product acceptance work. No registry/test count closes
those requirements. Certificate DNS-01 renewal is still manual.
