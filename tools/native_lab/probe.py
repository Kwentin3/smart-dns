"""Bounded native policy readback and wire probes; only aggregate receipts."""
import http.client
import ipaddress
import json
import socket
import ssl

from tools.probe import management_request, question, rejected_tls, tls_origin


def request(name, path="/", body=None):
    # Fixture edge certificate only. Origin probes use tls_origin's system CA.
    with socket.create_connection(("127.0.0.1", 18443), timeout=5) as raw:
        with ssl._create_unverified_context().wrap_socket(raw, server_hostname=name) as tls:
            wire = ("GET " if body is None else "POST ") + path + " HTTP/1.1\r\nHost: " + name + "\r\nConnection: close\r\n"
            if body is not None:
                wire += "Content-Type: application/dns-message\r\nContent-Length: " + str(len(body)) + "\r\n"
            tls.sendall((wire + "\r\n").encode() + (body or b""))
            response = http.client.HTTPResponse(tls)
            response.begin()
            return response.status, response.read()


def probe(out, docker, project):
    def progress(stage, checks=0):
        (out / "readback.json").write_text(json.dumps({"status": "incomplete", "stage": stage,
                                                     "checks": checks}) + "\n", encoding="utf-8")

    progress("full-native-rule-readback")
    def load(name):
        return json.loads((out / name).read_text(encoding="utf-8"))

    settings, snapshot, compose = (load(name) for name in
        ("fixture-settings.json", "snapshot.json", "compose.lab.json"))

    def owned(service):
        identifiers = docker("compose", "-p", project, "-f", str(out / "compose.lab.json"),
                             "ps", "-q", service).stdout.split()
        assert len(identifiers) == 1, "fixture service missing or ambiguous"
        item = json.loads(docker("inspect", identifiers[0]).stdout)[0]
        assert item["Config"]["Labels"]["com.docker.compose.project"] == project
        assert item["Config"]["Labels"]["com.docker.compose.service"] == service
        return item

    label = "traefik.tcp.routers.sd-relay.rule"
    expected = compose["services"]["relay"]["labels"][label].replace("$$", "$")
    assert owned("relay")["Config"]["Labels"][label] == expected, "native routing label byte mismatch"
    dns = owned("dns")
    addresses = [network["IPAddress"] for network in dns["NetworkSettings"]["Networks"].values()
                 if network["IPAddress"]]
    assert len(addresses) == 1 and ipaddress.ip_address(addresses[0]).is_private
    status, payload = management_request("http://" + addresses[0] + ":3000", "/control/filtering/status",
                                         settings["admin_username"], "lab-only-change-me")
    assert status == 200, "authenticated fixture filtering readback failed"
    assert json.loads(payload)["user_rules"] == snapshot["service_rules"], "full native AGH rule mismatch"
    scope = snapshot["wire_scope"]
    exclusions = snapshot.get("policy_exclusions", {})

    def selected(name):
        if name in exclusions.get("domains", []) or any(name == root or name.endswith("." + root)
                                                       for root in exclusions.get("domain_suffixes", [])):
            return False
        return name in scope["domains"] or any(name == root or name.endswith("." + root)
                                              for root in scope["domain_suffixes"])

    samples = set()
    for kind in ("domains", "domain_suffixes"):
        values = scope[kind]
        if values:
            for index in {0, len(values) // 2, len(values) - 1}:
                samples.add(values[index])
                if kind == "domain_suffixes":
                    samples.add("native-fixture." + values[index])
    assert samples and all(selected(name) for name in samples), "sample crosses a policy exclusion"
    checks = 2
    relay_ip = ipaddress.IPv4Address(settings["relay_ipv4"]).packed

    def query(name, kind=1, client=None):
        wire = question(name, kind)
        code, answer = request(settings["doh_host"], "/dns-query/" + (client or settings["client_ids"][0]), wire)
        assert code == 200 and len(answer) >= 12 and answer[:2] == wire[:2] and answer[2] & 128
        return answer

    for name in sorted(samples):
        progress("selected-DNS", checks)
        for kind in (1, 28, 64, 65):
            answer = query(name, kind)
            assert answer[3] & 15 == 0
            assert (answer[6:8] == b"\0\1" and answer[-4:] == relay_ip) if kind == 1 else answer[6:8] == b"\0\0"
            checks += 1
    progress("direct-DNS-and-access-control", checks)
    assert not selected("example.net"), "direct positive fixture is selected"
    direct = query("example.net")
    assert direct[3] & 15 == 0 and int.from_bytes(direct[6:8], "big") > 0 and relay_ip not in direct[12:]
    checks += 1
    unknown = query(next(iter(sorted(samples))), client="0" * 32)
    assert unknown[3] & 15 == 5 and unknown[6:8] == b"\0\0"
    checks += 1
    for name in ("tailscale.com", "openai.com"):
        assert selected(name), "required origin probe is outside candidate"
        for port in (18443, 18444):
            progress("origin-TLS-" + name + ("-edge" if port == 18443 else "-relay"), checks)
            tls_origin("127.0.0.1", port, name)
            checks += 1
    progress("HTTP-coexistence-and-negative-relay", checks)
    status, body = request("existing.example.net")
    assert status == 200 and b"Hostname:" in body, "existing HTTP router shadowed"
    checks += 1
    negatives = {"existing.example.net", settings["doh_host"], "ordinary.native-fixture.invalid",
                 "badopenai.com", "openai.com.evil.invalid", "127.0.0.1"}
    for name in sorted(negatives):
        assert not selected(name), "negative fixture is selected by candidate"
        rejected_tls("127.0.0.1", 18444, name)
        checks += 1
    rejected_tls("127.0.0.1", 18444, None)
    checks += 1
    readback = {"status": "PASS", "checks": checks, "DNS_samples": len(samples),
                "AGH_rules": len(snapshot["service_rules"]), "Docker_label_bytes": len(expected.encode()),
                "full_AGH_rule_parity": True, "full_actual_Docker_label_parity": True,
                "origin_CA_TLS_both_hops": True, "own_HTTPS_coexistence": True,
                "scope": "native policy only; product applications and production not checked"}
    (out / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    return {"status": "PASS", "checks": checks}
