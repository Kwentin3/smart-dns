# First-iteration acceptance, 2026-11-06

Scope: offline/source artefacts and an isolated disposable Linux pilot for issue
#1. **No production deployment, installation, restart, firewall or Hermes change.**
Operator-only host/IP/network/path details and generated ClientIDs are excluded.

This is the initial `f2d8caf` acceptance record. The subsequent
[PR review follow-up](review-followup.md) supersedes the SNI/path/logging boundaries
with new source hashes and real before/after checks; other original evidence
retains its stated scope.

## Identity and commands

Native Windows AGH v0.107.80 ZIP SHA256:
`46f69352b088595ff2764917d1209a69a3e8fa7a60a643201fd0d4da3d9c94bb`.
Downloaded official release archive and compared against its `checksums.txt`.
Version read back from real startup log. No service was installed.

Final accepted Linux input archive SHA256:
`78cb34e3be92319c580f72142a1f314e350b15ea21fe936b11c9e7cda40a31dd`.
Matched Windows sender and Linux receiver before extraction. Source files for
that run: tools/render.py, tools/probe.py, tools/run_lab.sh and config/images.lock.json
at revision `f2d8caf`. Documentation-only edits after the run do not
change tested runtime inputs. Container runtime: Docker 28.5.1, Compose 2.40.3.
Image digests are fixed in [images.lock.json](../../../config/images.lock.json)
and were read back from pulled images. Python dependencies are stdlib only.

```sh
python -m unittest discover -s tests -v
python tools/test_native_agh.py --binary .local/agh/AdGuardHome/AdGuardHome.exe
# In frozen disposable copy on separately approved Linux lab:
timeout --signal=TERM --kill-after=30 480 bash tools/run_lab.sh
```

The public [probe receipt and source hashes](lab-results.json) bind the checked
runtime files to that input archive; source bytes were compared to archive
members before publishing this receipt. The accepted lab command exited 0;
native HAProxy config check succeeded before
startup. Full generated configs, raw logs and origin snapshot are retained
privately under ignored `.local/`; those contain credentials/infrastructure
metadata and are not public evidence. Public observations below are redacted.

## Results

| Requirement / observation | Result | Evidence |
| --- | --- | --- |
| Native missing/unknown DoH ClientID deny | PASS | Both Windows and Linux: HTTP 200, DNS RCODE REFUSED, zero answers for valid wire query |
| Authorized DoH / exact DNS rewrite | PASS | Both exact selected hosts returned one A = documentation-only relay test address |
| Selected AAAA, SVCB, HTTPS | PASS | NOERROR with zero answers for both hosts/types; avoids new IPv6/hint/ECH answers |
| Direct/unselected host | PASS | Deterministic Windows fixture A preserved; live Linux example.com resolved with nonempty ordinary answer |
| No implicit suffix import | PASS | sub.chatgpt.com did not acquire relay A; fixture and live checks |
| No unauthenticated plain DNS | PASS, Windows native | UDP no answer, TCP REFUSED without useful answers; internal listener exists, no Compose DNS port published |
| Three host sets identical | PASS | Actual generated DNS rules, HAProxy ACLs and Traefik labels parsed/compared by unit contract test |
| Fixed-origin validation | PASS | Real render rejects private/loopback/link-local/metadata/CGNAT/multicast/reserved/IPv6, own ingress and provider service IP; mismatched key sets rejected |
| No runtime DNS rebinding path | PASS, structural + running config | HAProxy native numeric IPv4:443 backends only; no resolvers, client-selected dst or fallback. Running config carried exactly the approved two origin addresses |
| TLS passthrough and origin cert | PASS | Through lab Traefik→HAProxy, both hostnames completed TLSv1.3 using system CA trust and hostname verification; no local TLS termination on selected SNI |
| Unapproved SNI/direct relay rejection | PASS | Unknown hostname, missing SNI, IP literal, selected-host subdomain failed TLS even with verification disabled; HAProxy logs showed NOSRV/PR and no backend |
| Coexistence with HTTP routers | PASS, isolated fixture | existing.example.net still returned HTTP 200 and expected whoami payload on same TLS entrypoint |
| Limits/monitoring | PASS, smoke only | 128 MiB, 0.5 CPU, 100 PIDs each; HAProxy maxconn 256/timeouts; bounded JSON logs; stats captured below |
| Cleanup | PASS | EXIT trap down removed own containers/network; before/after existing-container ID sets equal (15); final readback after collection confirmed no owned containers/networks or three temporary experiment directories |
| Production unchanged | PASS within command scope | SSH commands were inventory/inspect/DNS queries only; no production writes/services/firewall/system DNS commands |

Ten offline contract tests passed, including committed pilot and source-pin
validation. They exercise actual compiler output and
negative inputs; they do not establish live device behavior or origin ownership.
Origins must be reviewed, not accepted from caller-written provenance fields.

Smoke `docker stats` (one instant; no load/capacity claim): DNS 16.03 MiB,
relay 10.81 MiB, lab edge 15.03 MiB, unrelated-site fixture 1.617 MiB; CPU
0–0.02%. Captured DNS network I/O 13.6/7.11 kB, relay 15.3/12.7 kB. In a
production pilot monitor `docker stats`, container OOM/restarts, aggregate
Traefik/relay rejects and transfer totals without saving secret DoH URL paths.
Compose does not enforce a bandwidth quota; stop the pilot on agreed abuse or
capacity thresholds. Long-term retention and bandwidth limits need owner input.

## Failures found and corrected

1. AGH native startup rejected disabling plain DNS without a native encrypted
   listener. HTTP DoH behind TLS termination is insufficient for that validator.
   Kept plain listener internal with ID-only native ACL; proved no anonymous
   answers. Do not describe this as a disabled listener.
2. Linux image binary has `cap_net_bind_service=eip`; cap_drop ALL initially
   caused exec EPERM. Kept only NET_BIND_SERVICE for DNS; no raw/admin capability.
3. File-only config bind did not permit AGH atomic config writes. Mounted a
   writable dedicated config directory and ran AGH under operator UID/GID with
   matching work tmpfs. Final real container started and passed all probes.

Failed trial stacks were removed by the same EXIT trap. Failed checks were not
treated as acceptance; the final run used the corrected, pinned artefacts.

## NOT_TESTED / remaining production work

- Full ChatGPT/Claude product flow (login, CDN, uploads, account/region policies),
  Gemini, iOS/iPadOS profiles, Android DoT and ordinary Windows/browser acceptance.
- GET DoH, ID revocation/restart, forged forwarded headers, selected TXT/MX,
  CNAME aliases and fragmented ClientHello. Current evidence is bounded to POST
  and the query/transport matrix above. No requirement for a universal resolver
  or complete service-domain catalogue is inferred from this smoke.
- Real public DoH certificate, production path/management isolation and
  access-log secret redaction. The lab DoH TLS client deliberately accepts its
  disposable/default certificate; origin TLS certificate verification stays ON.
- Adversarial host NAT, compromised daemon, malicious approved origin/CDN
  domain fronting; TLS passthrough cannot inspect encrypted HTTP Host. Relay is
  public for its fixed targets, as expressly accepted in the issue.
- Real-device ECH/QUIC/cache/AAAA fallback behavior, load/abuse longevity and
  device-side rollback. No UDP relay/DoT port is opened by this lab.

Before activation: approve the private new-service Compose/labels, exact origin
snapshot, routing/cert/network ownership, DoH logging policy, limits and rollback
window. Only then deploy and perform ordinary-user acceptance. This report is
first-iteration evidence, never approval to modify production.
