"""PR #2 boundary regression: actual TLS SNI and raw URL routing, stdlib only."""
import argparse
import http.client
import json
import ssl
import subprocess
import time

from probe import question, rejected_tls, tls_origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--edge-container", required=True)
    parser.add_argument("--observe", action="store_true", help="Record failing baseline observations; never count as acceptance")
    args = parser.parse_args()
    settings = json.load(open(args.settings, encoding="utf-8"))
    rows = []
    for port, hop in ((18443, "edge"), (18444, "relay")):
        for name, allowed in (("ChAtGpT.CoM", True), ("ClAuDe.Ai", True), ("SuB.ChAtGpT.CoM", False), ("ChAtGpT.CoM.evil.invalid", False)):
            # Shared edge may complete TLS for unrelated HTTP routes. The strict
            # unknown-SNI handshake rejection belongs to the relay, not that edge.
            if hop == "edge" and not allowed:
                continue
            try:
                result = tls_origin("127.0.0.1", port, name) if allowed else rejected_tls("127.0.0.1", port, name)
                result.update(check="mixed-SNI-" + hop, domain=name)
            except (OSError, AssertionError) as error:
                result = {"check": "mixed-SNI-" + hop, "domain": name, "status": "FAIL", "error": type(error).__name__}
            rows.append(result)

    client_id = settings["client_ids"][0]
    # Paths are sent verbatim with http.client; no automatic redirect following
    # or client-side dot-segment normalization. Do not log/print actual secret paths.
    paths = [
        ("authorized", "/dns-query/" + client_id, True),
        ("anonymous", "/dns-query", True),
        ("unknown-client", "/dns-query/" + "0" * 32, True),
        ("prefix-lookalike", "/dns-query-evil", False),
        ("suffix-lookalike", "/dns-queryevil/" + client_id, False),
        ("management-under-prefix", "/dns-query/control/status", False),
        ("management", "/control/status", False),
        ("setup", "/install.html", False),
        ("root", "/", False),
        ("trailing-slash", "/dns-query/" + client_id + "/", False),
        ("dot-traversal", "/dns-query/../control/status", False),
        ("encoded-dot-traversal", "/dns-query/%2e%2e/control/status", False),
        ("encoded-slash-traversal", "/dns-query%2f..%2fcontrol%2fstatus", False),
        ("encoded-backslash", "/dns-query%5c..%5ccontrol%5cstatus", False),
        ("double-encoded-traversal", "/dns-query/%252e%252e/control/status", False),
    ]
    for case, path, allowed in paths:
        connection = http.client.HTTPSConnection("127.0.0.1", 18443, context=ssl._create_unverified_context(), timeout=10)
        try:
            connection.request("POST", path, question("chatgpt.com"), headers={"Host": settings["doh_host"], "Content-Type": "application/dns-message", "X-Lab-Case": case})
            response = connection.getresponse()
            body = response.read()
            good = response.status == 200 and len(body) >= 12 if allowed else response.status in (400, 404)
            if case in ("anonymous", "unknown-client"):
                good = good and body[3] & 15 == 5 and body[6:8] == b"\0\0"
            rows.append({"check": "DoH-path", "case": case, "status": "PASS" if good else "FAIL", "http": response.status, "expected_dns_route": allowed})
        finally:
            connection.close()
    # RouterName distinguishes edge 404 from AGH 404; status alone is insufficient.
    observed = {}
    for _ in range(30):
        raw = subprocess.check_output(["docker", "logs", args.edge_container], stderr=subprocess.STDOUT, text=True)
        assert client_id not in raw, "secret ClientID leaked into lab logs"
        for line in raw.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            case = record.get("request_X-Lab-Case")
            if case:
                observed[case] = record.get("RouterName", "")
        if all(case in observed for case, _, _ in paths):
            break
        time.sleep(.1)
    for row in rows:
        if row["check"] != "DoH-path":
            continue
        router = observed.get(row["case"])
        reached = router == "sd-doh@docker"
        good = router is not None and reached == row["expected_dns_route"]
        row["route_boundary"] = "PASS" if good else "FAIL"
        row["dns_router_matched"] = reached
        if not good:
            row["status"] = "FAIL"
    print(json.dumps(rows, indent=2))
    if not args.observe and any(row["status"] != "PASS" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
