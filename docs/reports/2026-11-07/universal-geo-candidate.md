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
Native minimized wire scope: 114 exact + 1140 suffix roots; edge label 95,422 bytes.
The raw desired policy exceeded the existing default budget of 2048. Verification
used the existing explicit `max_policy_entries: 4096` setting in a disposable
fixture; neither the default nor production settings were changed.

Local unit/behavior checks cover source identity/blob tampering, v3 quarantine,
baseline preservation, refresh gates, failure last-good, OFF/exclusions,
rollback and CLI read-only behavior. CI results belong to the delivered revision.
Private evidence is retained under `.local/issue12-research/`; complete candidate
inputs under `.local/issue12-candidate-v2/`. The initial candidate with an incorrect
source declaration is superseded by v2 and must not be deployed.

Full native HAProxy/Traefik/Docker label transport for this larger candidate is
**NOT VERIFIED** here: Docker is unavailable in this Windows workspace. The prior
smaller label proof does not establish this candidate's transport. Linux lab,
live readback, changed-source integration on the actual deployment, runtime
resource bounds, ordinary browsing and application functions remain required.
No clean lab/build will run on production without separately prepared resources
and authorization. Full #12 remains open.

Before activation: verify the current live baseline identity against the candidate,
run the full isolated native path, then obtain approval for this specific source
scope and the explicit budget change. Keep existing private deployment paths,
systemd refresh and service-only apply/restore; do not change shared edge/Hermes.
After activation, prove actual routing/direct controls, update/exclusion/rollback
and ordinary-user functions in software/developer, cloud and media/game categories.
DNS/TLS and source counts alone cannot close these acceptance requirements.
