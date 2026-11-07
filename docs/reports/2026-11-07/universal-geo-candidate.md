# Universal GEO candidate for PRODUCT GOAL #12

Research and repository preparation, 2026-11-07. No VPS, shared edge, active
policy, clients/admin or Hermes changes were performed. Historical runtime
evidence is linked from the existing product task; it was not refreshed here.

## Actual source comparison

The three current default-branch heads were resolved through GitHub and their
immutable source files compared in memory. These numbers count source matchers,
not working applications. The private saved baseline was read back: itdog pin
below, 465 GEO + 28 Google AI suffixes, 492 unique roots.

| Source and immutable pin | Selected corpus | Compared with the saved 492 suffix baseline |
| --- | --- | --- |
| [dartraiden/no-russia-hosts `188e386`](https://github.com/dartraiden/no-russia-hosts/blob/188e386c28b0207381b053a6701b0862af9ea7c9/hosts.txt) | 870 root names; README describes parent-domain/session intent | 194 literal overlaps; 676 additional roots |
| [itdog GeoBlock `eb64def`](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Categories/geoblock.lst) and [Google AI](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Services/google_ai.lst) | 465 + 28 suffixes, union 492 | Current source baseline; not AI-only |
| [RussiaFancyLists `25e7b19`](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/lists/geoblock-sing-box/full.json) | Native JSON v3: 1090 exact + 1104 suffix predicates | 613 exact + 692 suffix predicates not covered by baseline roots; 1305 additional predicates |

The baseline covers the other 889 of the 2194 Fancy predicates by name/suffix
semantics. This is a comparison with one chosen corpus, not a percentage of the
Internet or functional compatibility. All 870 dartraiden names occur in Fancy's
raw GEO corpus, so importing both independently would mostly duplicate collection.
Three itdog/AI names are absent literally from Fancy's raw names; literal absence
does not prove a coverage hole when a broader suffix may cover the same name.
The candidate conservatively retains the entire previously accepted baseline.

Representative non-AI additions include developer/software resources
`activestate.com` and `tailscale.com`, and broad `amazon.com` / `microsoft.com`
namespaces. Source membership is the source maintainer's GEO claim; the latter
two grants also illustrate why activating the whole profile needs an explicit
breadth decision. They can include ordinary pages under the same suffix.
The discovery index in the public Meta snapshot is mixed services/categories;
it is not a complete inventory of regional restrictions.

## Why this source path

Fancy already [aggregates existing community sources](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/src/russiafancylists/config/providers.py#L131-L145)
and [builds the GEO union](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/src/russiafancylists/pipeline.py#L172-L213).
Use that ready output instead of building a second multi-registry platform.
This is an aggregate with inherited mistakes and lag, not independent
corroboration of every listed restriction.

Preserve the generated JSON's exact/suffix distinction. Its
[writer](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/src/russiafancylists/ruleset.py#L83-L101)
emits two-label names as suffix and longer names as exact. Importing raw `full.lst`
as all suffix would expand permissions. The native file has SHA256
`99eec5a154f52a7989e441c97a330c29ae310335eccdcbcacb87d513f4d87f12`.
[Sing-box source-format documentation](https://sing-box.sagernet.org/configuration/rule-set/source-format/)
describes v3 as adding network predicates. Existing literal normalization is
reused; unknown/compound/network conditions remain quarantined in their entirety.

Do not import `full-sld.lst`: its [last-two-label reduction](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/src/russiafancylists/processors.py#L231-L236)
does not use the Public Suffix List. The actual 1202-entry output contains public
suffixes such as `co.uk` and `com.au`. Censorship/blacklist and country-inside
corpora are outside this candidate; their scope does not establish GEO restrictions.

Directly subscribing AGH to arbitrary upstream hosts is insufficient:
[native filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
does not turn foreign hosts-file destination addresses into the operator's
coordinated DNS/SNI relay policy. Reuse the existing compiler and native engines.

No license grant was established in the pinned itdog/dartraiden trees. Fancy's
[MIT license](https://github.com/Noktomezo/RussiaFancyLists/blob/25e7b1912eca4b31d44906af0df10f00c85ab268/LICENSE)
does not itself establish permissions for aggregated third-party materials.
The adapter records the verified license text but keeps complete snapshots,
preferences and proposals private. Public artifact publication rejects it.

## Minimal implementation and explicit tradeoff

The existing `registry.fetch_snapshot` adds one fixed source profile,
`russia-fancy-geo`, and one `community-geo` definition. Existing Git tree/blob
verification, limits and error handling own transport/provenance; existing
normalization owns literal meaning; catalog owns approvals; renderer owns
native policy; product CLI owns apply/readback/rollback. No new runtime,
database, panel, timer, source merger or state store is introduced.

`bootstrap_geoblock.py --source russia-fancy-geo` prepares a private candidate
using explicit `--base-catalog`, `--base-registry`, and a new `.local/` output.
It projects the previous baseline before freezing it as local grants with
immutable `source_path` references, then adds the source-backed community group.
OFF states, local exclusions and accepted match types are retained.

One accepted snapshot remains authoritative: after a migration, Fancy is the
refreshed upstream, and the retained itdog baseline is frozen local policy.
It is not a second live itdog subscription. This avoids a second update owner,
but retained legacy grants do not automatically disappear when upstream removes
them. Retirement remains a reviewed policy change. Existing source refresh
continues to leave new roots pending and stops on removals/license changes;
new unsupported predicates now also stop at review, even when older partial
rules were previously accepted.

`smart-dns list` and `show ID` expose accepted discovery, desired ON/OFF,
definitions/provenance, pending scope and exclusions through the existing
deployment manifest without fetching, credentials or writes. Local/discovery
name collisions remain separate entries. These commands explicitly report
runtime, network path and user functionality as `not-checked`; `status` remains
the native actual-policy check. No new application-acceptance ledger is invented.

## Validation and delivery limits

The real private candidate was prepared from the saved GEO baseline and verified
against current pinned Fancy Git blobs. Local native AGH ran the complete compiled
policy and 35 bounded wire checks: exact and suffix samples/children, developer,
software/cloud and prior Gemini names, A rewrites, AAAA/HTTPS/SVCB suppression,
positive ordinary/exact-child direct answers, and unauthorized-client refusal.
Its process and UDP-fixture thread stopped. The real repeat source proposal was
unchanged, and candidate inputs remained byte-identical.

Compiled generation:
`7392c507d4d6bfef3ad4d00ae4e207258be0e9b7996ff1f0228b02aa3a2ee535`.
Native minimized wire scope: 114 exact + 1140 suffix roots; Compose label 95,422
bytes and native Docker label 94,282 bytes after Compose's dollar conversion.
The raw desired policy exceeded the existing default budget of 2048. Verification
used the existing explicit `max_policy_entries: 4096` setting in a disposable
fixture; neither the default nor production settings were changed.

Local unit/behavior checks cover source identity/blob tampering, v3 quarantine,
baseline preservation, refresh gates, failure last-good, OFF/exclusions,
rollback and CLI read-only behavior. CI results belong to the delivered revision.
Private evidence is retained under `.local/issue12-research/`; complete candidate
inputs under `.local/issue12-candidate-v2/`. The initial candidate with an incorrect
source declaration was superseded by v2 and removed after verification.

### Full Docker-provider and operator acceptance

The missing Linux native stage is now verified on an isolated GitHub-hosted
Ubuntu runner, without using the production VPS. Reuse of the existing private
lab lifecycle exposed a test gap: that older harness parsed a FILE-provider rule
and transported an inert custom Docker label. The tracked `tools/native_lab/`
instead runs the actual compiler-produced Docker provider, labels, AGH and
HAProxy. No FILE-provider route substitutes for the production owner's path.

[Native run 42360351223](https://github.com/Kwentin3/smart-dns/actions/runs/42360351223)
at source revision `1a1bbfeda0adb72e5a349c98a607c1b70aa6f6be` completed successfully.
The aggregate artifact was downloaded and read back; its candidate/baseline
catalog and registry checksums exactly match the local reproduction. The source
pins above and enforcement checksum
`2e815b2927ecd1d292b2d6258a1a734b40ed577e8dd69da1b0d0ee52c92bc136`
bind it to the reviewed candidate, not a synthetic scale list.

The CI reconstruction and its local reproduction have identical input checksums.
Compared with the original saved v2, the registry and enforcement scope are
identical; only immutable `source_path` annotations on the retained ChatGPT/Claude
services differ. Complete catalog bytes across those two variants are therefore
not claimed identical. These annotations do not change service state, matchers
or exclusions.

| Observation | Actual native evidence |
| --- | --- |
| Complete policy | All 2508 AGH rules and all 94,282 native Docker-label bytes match the compiler |
| Wire path | 52 checks: nine exact/suffix/descendant samples, A rewrites, AAAA/HTTPS/SVCB suppression, positive direct DNS, denied client, negative relay cases, own HTTPS coexistence |
| Origin TLS | System-CA-verified TLS for OpenAI and non-AI Tailscale through both actual edge and relay |
| Operator commands | Eight real CLI invocations: status, add, off, refresh, failed refresh, exclude, refresh, rollback; 60 checks |
| Owner preferences | Tailscale OFF and exact OpenAI exclusion remain direct after source refresh; edge returns local 404 and relay rejects these names |
| Source outage | Native transport through an unavailable loopback proxy fails; accepted source/catalog bytes, native rules, OFF and existing service remain unchanged |
| Rollback | Initial canonical inputs restored exactly; DNS rewrite and verified origin TLS restored |
| Isolation | DNS/edge/existing-site IDs and StartedAt, native admission unchanged; only owned relay operations permitted |
| Runtime identity and cleanup | Four running image IDs/digests match the lock; Python cleanup and workflow fallback confirm no owned containers/networks remain |

The fixture uses the same enforcement scope with disposable infrastructure
settings, public lab credentials and explicit 4096 budget. Its compiled generation
is `6d7bfad335f400f73434acd5783ca3e53d1c7bf1e3d2b4b833f6ed4d03b6961c`;
this differs from the earlier Windows fixture's generation because its settings
differ. Neither fixture is claimed to be a production deployment artifact.

Windows and Linux unit contracts: 152 PASS; [Linux CI](https://github.com/Kwentin3/smart-dns/actions/runs/42360350444).
Native receipts are retained privately in `.local/issue12-cli-ci-receipts/` and
published as aggregate `inputs.json`, `readback.json`, `management.json`, `result.json`
only. Complete corpora, configs, runtime logs and private credentials are excluded.

The successful refreshes saw the unchanged actual source. This proves native
refresh/retained decisions and outage handling; it does not claim that a new
Fancy upstream change occurred. Additive/removed/unsupported/partial/licensing
transitions are exercised through real collector/projection owners with synthetic
transport in the behavior tests. The historical real changed-source Meta update
is separate discovery evidence, not a changed-source Fancy production acceptance.

Remaining product acceptance: current live-baseline identity, separately approved
4096 budget and source activation, production readback/resource behavior, actual
changed-source behavior on that deployment, ordinary browsing, app functions in
multiple categories, and network/device switching. No build/lab ran on production.
Full #12 remains open.

Before activation: verify the current live baseline identity against the candidate,
then obtain approval for this specific source scope and the explicit budget
change. Native evidence above is reusable while relevant source, scope and
environment conditions remain unchanged. Keep existing private deployment paths,
systemd refresh and service-only apply/restore; do not change shared edge/Hermes.
After activation, prove actual routing/direct controls, update/exclusion/rollback
and ordinary-user functions in software/developer, cloud and media/game categories.
DNS/TLS and source counts alone cannot close these acceptance requirements.

## Release questions before activation

The owner's [review of PR #13](https://github.com/Kwentin3/smart-dns/pull/13#pullrequestreview-5811444613)
allows merging this repository-only slice once these questions are recorded.
They remain open release decisions, not authorization to deploy Fancy or increase
the production budget. The currently accepted GEO profile stays active.

During the documentation follow-up, [CI 42362186906](https://github.com/Kwentin3/smart-dns/actions/runs/42362186906)
stopped because Fancy's head advanced to `c02a150c417a6b3c39636653dbcc52f0e5f1dfaa`.
The selected definition, source index and license text were read back unchanged.
The native fixture now fetches the originally reviewed immutable commits through
the same verified loader. Normal product refresh still follows upstream; a moving
branch is no longer substituted for the frozen candidate's preparation input.

### 1. Broad suffixes versus ordinary direct traffic

A suffix routes its apex and descendants regardless of URL, account or whether
that individual request needs a foreign address. For example, ordinary browsing
on `www.amazon.com` and `www.microsoft.com` would also use the relay under the
proposed `amazon.com` and `microsoft.com` grants. Other vendor domains are separate
matchers; a vendor name alone does not determine their routing. DNS/SNI cannot
distinguish a blocked download from an ordinary page on the same hostname.

Before activation, present the private candidate's broad roots, exact grants,
baseline-to-candidate diff and the owner's ordinary critical hostnames with their
effective route and granting group. Existing `list` / `show community-geo` expose
the candidate's desired matchers and approvals; they do not automatically classify
ordinary browser scenarios or prove regional restrictions. They refer to the
deployment manifest selected for that command, not automatically to this candidate.

An exact `exclude NAME` keeps that name direct, not its whole subtree. If a broad
root is unwanted but specific children are needed, prepare a narrower local
approval: remove that broad suffix from every grant that still supplies it,
retain only reviewed exact names/narrow suffixes and compile the resulting wire
scope before approval. Keep these decisions in the existing canonical catalog;
do not hand-edit AGH, HAProxy and Traefik separately. Existing ON/OFF shared-route
semantics must be inspected: OFF on an overlapping broad service is not a promise
of a blanket deny when an enabled individual still shares that namespace.

Some necessary dependencies may be unknown. Preserving every GEO function while
pruning a broad namespace cannot be promised without that resource's functional
test. The owner must accept the broad side effect or the reviewed narrower scope
and its remaining gaps. If this changes the candidate, recheck the affected native
path; the previous full-profile checksum does not certify the modified scope.

### 2. Freshness of retained grants

The coverage summary must distinguish these states before activation:

| Portion | Update/freshness claim |
| --- | --- |
| Source-backed `community-geo` | Fancy is fetched by the existing refresh; approved bounds and review gates still apply |
| Retained local baseline | Frozen at its recorded source commit; current upstream membership and continued need are not automatically checked |
| Native `status=matches` | Desired/runtime policy agrees; this is not a freshness or application-success claim |

Frozen services already carry `previously-accepted-local-baseline` provenance and
immutable `source_path`, visible in desired `list/show` output. There is currently
no automatic stale-grant warning or live itdog comparison for those rows. A
successful Fancy refresh must not be described as updating the entire retained
policy. A removed Fancy entry can also remain routed through a frozen local grant.

Before activation, assign the owner and next review date for these retained rows.
At release review, compare them privately with fresh itdog/Fancy snapshots using
the existing source collector, without accepting or activating the fetched data.
Show unchanged, absent/different and unverified rows separately; upstream absence
is a review signal, not permission for silent deletion. Retire or narrow obsolete
local grants through a reviewed catalog change. If manual reconciliation is not
acceptable, this migration's freshness decision remains unresolved; this PR does
not add another timer or claim that automatic reconciliation exists.

### 3. Bounded rollout and user acceptance

After the separate scope/budget decision, use one short agreed observation window
(initially 15 minutes, not a load test) and keep the accepted generation ready:

1. Before mutation, read back the actual baseline and source/input identities,
   client/admin admission, protected container IDs/StartedAt and current resource
   use. Agree `max_policy_entries=4096`, the exact private candidate, existing
   CPU/memory/PID limits, rollback trigger and window. Do not install a lab/build
   on production or change shared edge/Hermes infrastructure.
2. Apply through the existing service-only operator. Check desired/actual, full
   native rules and relay identity, refused unknown client, resource/health state
   and unchanged protected containers. Resource exhaustion, drift or an ordinary
   site/Hermes regression triggers immediate rollback through the same operator.
3. On one admitted ordinary device, compare before/after use of one newly covered
   non-AI resource and one resource from another category. Developer/software,
   cloud and media/game candidates are selected from the actual approved diff
   and available accounts. Confirm a principal function such as login plus a
   real download, workspace action or playback; record unsupported/account/ASN
   cases instead of declaring them working from DNS/TLS.
4. Check three owner-selected ordinary critical sites, the broad namespaces
   discussed above according to the chosen routing decision, one existing AI
   function and Hermes's ordinary endpoint. Confirm intended direct/relay paths,
   usable browsing/download and one Wi-Fi-to-mobile reconnect on that device.
   Compare the same controls after a refresh; OFF/exclusions must remain effective.
5. Exercise the prepared rollback and confirm restored policy, the same ordinary
   controls and preserved admission/Hermes. Keep the old profile if any required
   check is unavailable or fails; do not silently leave the expanded profile as
   accepted. Further rollout follows an explicit acceptance result.

Record for each sampled resource: source discovery, enabled policy, verified wire
path, actual user function or an explicit unsupported/unverified reason. The
1305 additional predicates are source coverage, never 1305 accepted services.
No part of this checklist was executed on production by this PR.
