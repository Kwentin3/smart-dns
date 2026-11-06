# Registry research for issue #1

Reviewed 2026-11-06 against public GitHub source. This is source research and a pilot proposal. It does not establish regional blocking, service ownership for every listed hostname, DNS/SNI routing correctness, or browser acceptance.

## Recommendation

Use the existing public registries to discover candidates, then review exact hostnames in this repository. Keep `rules/sources.json` as provenance metadata, never as an instruction to import a whole registry. The local approved rules remain the only routing authority. A public entry alone does not approve a local rule.

Start the browser pilot with ChatGPT and Claude. A deliberately small proposed exact-host set is `chatgpt.com`, `chat.openai.com`, `auth.openai.com`, `claude.ai`, and `claude.com`. These are exact names, with no implicit descendants. `chat.openai.com` occurs in a comment in the pinned no-russia list; `auth.openai.com` is a manually proposed login dependency under upstream `openai.com`, not an independently observed registry line. Validate both against the actual pilot login/redirect path before approval. This proposal is not a complete dependency inventory.

Both primary sources also list `oaistatic.com`, `oaiusercontent.com`, `openai.com`, and `anthropic.com`. Treat those as discovery hints, not permission for suffix routing. Exact asset, upload, API, and authentication hosts must be observed during the bounded browser test and proposed separately. An apex rule does not cover its subdomains. Do not add `api.openai.com` or `api.anthropic.com` merely because the pilot includes the corresponding browser product.

## Pinned sources and limitations

| Source | Immutable commit | Finding and intended use |
| --- | --- | --- |
| [dartraiden/no-russia-hosts](https://github.com/dartraiden/no-russia-hosts/blob/188e386c28b0207381b053a6701b0862af9ea7c9/hosts.txt) | `188e386c28b0207381b053a6701b0862af9ea7c9` | Human-readable geoblock claims and explanatory comments. Selected ChatGPT/Claude entries are recorded in `sources.json`. |
| [itdoginfo GeoBlock](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Categories/geoblock.lst) | `eb64def4353f8e1b9cc483858021979a3481c76e` | Useful corroboration for the same products; many unrelated products remain excluded. |
| [itdoginfo Google AI](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/Services/google_ai.lst) | `eb64def4353f8e1b9cc483858021979a3481c76e` | Identified as the separate AI service list, but outside this pilot. No entries selected. |
| [viewer12/OverseasAI.list](https://github.com/viewer12/OverseasAI.list/blob/f8d93d9f6cb6b0eb183773ad238171d511f25a6c/rule/Clash/OverseasAI/OverseasAI.list) | `f8d93d9f6cb6b0eb183773ad238171d511f25a6c` | Optional corroboration only. Mixed suffix, keyword, CIDR, ASN, payment and shared dependency rules make wholesale import inappropriate. |

The [no-russia README](https://github.com/dartraiden/no-russia-hosts/blob/188e386c28b0207381b053a6701b0862af9ea7c9/README.md) explicitly explains its parent-domain strategy for consistent session egress. This is evidence that its list has broader semantics than an exact-host Smart DNS pilot. In particular, `google.com` and `microsoft.com` occur in that source and are excluded here.

The [itdoginfo README](https://github.com/itdoginfo/allow-domains/blob/eb64def4353f8e1b9cc483858021979a3481c76e/README.md) documents GeoBlock and the separate Google AI list, including a warning about Google classifying some foreign servers as RU. `Russia/inside-*`, Block, News, Porn, Anime, H.O.D.C.A, service-wide cloud networks, and all subnet files are outside this selection. Do not infer an AI-only category containing OpenAI and Anthropic: at this pin they appear in GeoBlock; Google AI has its own file.

## Licenses

No `LICENSE`, `COPYING`, or equivalent license file exists in the pinned recursive trees of `dartraiden/no-russia-hosts` and `itdoginfo/allow-domains`; their pinned READMEs contain no explicit license grant. Record the license as unknown, not public domain or an assumed permissive license. Do not vendor or automatically redistribute those complete lists without resolving permission. The small local proposal still requires independent service evidence and review.

The optional viewer12 source has a [GNU GPL version 2 license file](https://github.com/viewer12/OverseasAI.list/blob/f8d93d9f6cb6b0eb183773ad238171d511f25a6c/LICENSE); its [README](https://github.com/viewer12/OverseasAI.list/blob/f8d93d9f6cb6b0eb183773ad238171d511f25a6c/README.md) declares GPL-2.0, credits blackmatrix7/ios_rule_script, and references v2fly/domain-list-community. This review does not determine GPL-2.0-only versus GPL-2.0-or-later or solve all downstream license obligations. No viewer12 rule content is imported.

## Exclusions and update workflow

- Exclude wildcard, suffix, keyword, CIDR and ASN imports; broad zones such as `google.com`, `microsoft.com`, `googleapis.com`, and shared cloud/CDN parent zones; payment and unrelated telemetry/support networks without concrete pilot evidence.
- Exclude the operator's VPS names, resolver/relay/control endpoints, private domains and local infrastructure. Registry updates cannot grant access to or redefine those names. The implementer must compare actual inventory locally; this public-source research has no private inventory.
- Update through a reviewable PR: record old/new immutable SHAs, exact source paths, upstream delta, proposed local additions/removals, category, reason and license changes. Keep machine-discovered names as proposals and require deliberate approval of each exact hostname.
- Before merging a rules change, run the local validator/generator, inspect generated DNS and relay maps for exact-name parity and exclusions, and retain the diff. No runtime fetch from a mutable branch or silent refresh from `latest`.
- Before deployment, validate relevant host ownership and bounded browser evidence for login, ordinary prompt/response, static assets and any selected upload path; verify unrelated domains remain ordinary DNS. Production activation and end-user acceptance are separate authorized steps. Failure or missing evidence keeps the candidate unaccepted.

The [final acceptance report](reports/2026-11-06/acceptance.md) records the two-host
runtime integration and negative policy checks. Remaining gaps: full browser
dependency inventory, regional product/egress behavior, production-specific
exclusion comparison and ordinary-user acceptance. Pinned sources do not prove these.
