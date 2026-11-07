# Complete ready GEO profile

Scope: the owner's correction to issue #3 on 2026-11-07. A discovery index plus
two enabled AI services was insufficient. The rollout target is the complete
ready GEO category, including Gemini, rather than all country/vendor categories
in the mixed discovery index.

## Source and policy

The existing Git source loader now supports a second fixed profile:
`itdog-geoblock`, `itdoginfo/allow-domains`, branch `main`. The verified pin
`eb64def4353f8e1b9cc483858021979a3481c76e` contains:

- [GeoBlock](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Categories/geoblock.lst): 465 unique suffixes.
- [Google AI](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Services/google_ai.lst): 28 unique suffixes.

Their union has 492 suffixes. The source's converter explicitly uses suffix
semantics. The adapter accepts literal hostnames only; malformed lines, missing
files and mismatched Git blobs reject the candidate. Existing Meta collection
uses the same owner and remains compatible.

No license grant was established for this corpus. Full snapshots, approvals and
proposal bodies stay private. Git contains the adapter, unit templates and
provenance, without the complete fetched lists. The public Actions collector
uses `--public-artifact`; it rejects the private profile before fetching or
creating output.

The private bootstrap first projects the accepted prior policy and preserves it
as an explicit frozen local baseline, then approves both complete GEO groups.
Existing exact/suffix distinctions, source bounds, exclusions, own zones and
destination-IP guards remain with the existing policy owners. New upstream
roots remain pending. Source proposals cannot mutate accepted runtime or native
client/admin state.

## Evidence

| Check | Result |
| --- | --- |
| Unit contracts, including private source/transport/bootstrap/proposal boundaries | 101 PASS |
| Actual initial fetch and repeat private proposal | Correct pin and 492-source union; repeat `changed=false` |
| Full native Linux GEO fixture | 53 PASS; all source-selected samples present |
| Actual complete AGH policy | Authenticated `user_rules` exactly matched the compiled manifest |
| Complete Compose/Docker label transport | 41,028 native bytes, literal-dollar conversion and byte parity PASS |
| Native routing | Existing origin/own-HTTPS/exclusion/negative checks plus Gemini, Google API, Notion, Netflix, JetBrains and Canva DNS samples PASS |
| Resources | AGH 14.01 MiB, edge 19.11 MiB, relay 11.9 MiB under separate 128 MiB limits; no traffic-capacity guarantee |
| Isolation and cleanup | No discovery labels/socket for test edge; existing container IDs/StartedAt unchanged; owned containers/networks removed |
| systemd template validation | Native `systemd-analyze verify` PASS |
| Production GEO apply/status and external wire | `6ebfabd`: applied-and-readback, then independent `matches`; admission/protected containers unchanged; 180 external DoH/DoT/origin checks PASS |
| Private daily collector activation and first execution | Timer active; oneshot Result=success/exit0; actual private proposal `changed=false`, accepted/candidate checksum equal |

Private native inputs and results were collected and read back, with all source
hashes matching the workspace. Source and fixtures had no production credentials.
The policy includes 494 desired suffixes after preserving the previous baseline;
native minimization reduces these to 490 positive wire roots without dropping
coverage. The lab added only two explicit fixture exclusions.

The timer invokes the existing proposal collector only, daily at 06:31 UTC plus
up to five minutes of randomized delay. It writes private proposals; it does not
deploy, replace the accepted snapshot or activate new roots. Public Meta discovery
and private GEO collection have different source ownership and output boundaries.

Source coverage and successful DNS/TLS do not establish every application's
functionality. Google can additionally apply account and egress-IP region checks;
the authenticated Gemini result requires the owner's real session. No catch-all,
new proxy, public management port or shared-edge reconfiguration is introduced.

## Production readback

Desired and actual match generation
`2c15b051777061b8bc4d016993a3140834a5f5f7a2dda74e6933ec9dfc7bc6e7`.
Both complete source groups are enabled, with no pending roots in this accepted
snapshot. The previous accepted generation remains available for rollback.
Canonical live preferences and source snapshot reside under private
`.local/policy/rules/`; the checked-in Meta pilot is a public example/discovery,
not a second owner of this deployment's current policy.

The 180 external checks cover all previous namespaces plus Gemini, Google API,
Notion, Netflix, JetBrains, Canva, Adobe and Copilot: DoH/DoT A rewrites and
AAAA/HTTPS/SVCB suppression, selected API children, ordinary positive unrewritten
DNS, unauthorized-client refusal and 18 origin TLS handshakes. Separate anonymous
HTTP GETs through the deployed relay returned 200 for Gemini `/app` and `/`, with
title Google Gemini. No user's account or session was used.

The private collector fetched the real source on its first native execution;
pin `eb64def4353f8e1b9cc483858021979a3481c76e` and both snapshot checksums matched.
The timer's observed next event was 2026-11-07 06:35:43 UTC, within the configured
daily delay window. An actual future cron tick and changed-source GEO proposal
remain unobserved; neither accepted policy nor runtime is modified by collection.

Independent outcome review inspected the raw native, production, wire and timer
artifacts and returned PASS for this technical full-GEO milestone. The verdict
excludes authenticated application/device acceptance. Deployed source identity
is `6ebfabd`; subsequent documentation/reference updates do not alter its runtime
code or canonical private inputs.

## User confirmation and real source update

After the deployment the owner explicitly replied that Gemini works
("Заработал"). This confirms the reported Gemini problem is resolved for the
owner's use; it does not imply that all services, file flows or network switches
were tested.

The public Meta discovery collector also exercised a real changed-source path:
[run 42346695609](https://github.com/Kwentin3/smart-dns/actions/runs/42346695609)
created [PR #7](https://github.com/Kwentin3/smart-dns/pull/7). Its PR blob matched
the downloaded candidate artifact, candidate contracts passed, the license was
unchanged, and neither selected AI definition changed. The discovery index gained
two entries and changed 137; the resulting index has 2021 entries. PR #7 was
reviewed and merged. This updated discovery facts only, without changing private
GEO approvals, accepted private source or live routing.
