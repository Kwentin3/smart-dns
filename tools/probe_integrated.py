"""Probe an already running disposable Compose lab: verified DoH/DoT and relay."""
import argparse
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import urllib.parse

from probe import management_request, question, tls_origin
from probe_dot import assert_answer, dot_query
from render import ROOT, catalog_rules


class LabHTTPSConnection(http.client.HTTPSConnection):
    """Connect locally while verifying the configured DNS endpoint's hostname."""
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", 18443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def doh_query(context, host, client_id, domain, qtype=1):
    connection = LabHTTPSConnection(host, context=context, timeout=10)
    try:
        path = "/dns-query" + ("/" + client_id if client_id else "")
        connection.request("POST", path, question(domain, qtype), headers={"Host": host, "Content-Type": "application/dns-message"})
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200, "verified DoH did not return a DNS response"
        return body
    finally:
        connection.close()


def run(settings, ca, management_base, password):
    endpoint = urllib.parse.urlsplit(management_base)
    address = ipaddress.ip_address(endpoint.hostname)
    if endpoint.scheme != "http" or not (address.is_private or address.is_loopback) or address.is_unspecified or endpoint.username or endpoint.password or endpoint.path not in ("", "/"):
        raise ValueError("management base must be the disposable private-IP AGH HTTP endpoint")
    management_base = management_base.rstrip("/")
    host = settings["doh_host"]
    router_id, phone_id = settings["client_ids"][:2]
    unknown_id = "c" * 32
    assert unknown_id not in settings["client_ids"], "unknown fixture ID is already admitted"
    registry_path = ROOT / "rules/registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else None
    rules = catalog_rules(json.loads((ROOT / "rules/pilot.json").read_text(encoding="utf-8")), registry)
    assert not rules.get("domain_suffixes"), "exact-host integrated smoke requires separate native suffix acceptance"
    domains = rules["domains"]
    assert domains, "integrated probe requires an enabled pilot service"
    context = ssl.create_default_context(cafile=str(ca))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    rows = []

    def api(path, payload=None):
        status, body = management_request(management_base, path, settings["admin_username"], password, payload)
        assert status == 200, "authenticated disposable AGH API failed"
        return json.loads(body) if payload is None and body else None

    for role, client_id in (("router", router_id), ("phone", phone_id)):
        for domain in domains:
            assert_answer(doh_query(context, host, client_id, domain), settings["relay_ipv4"])
            assert_answer(dot_query(context, client_id + "." + host, domain), settings["relay_ipv4"])
        for qtype in (28, 64, 65):
            assert_answer(doh_query(context, host, client_id, domains[0], qtype))
            assert_answer(dot_query(context, client_id + "." + host, domains[0], qtype))
        rows.append({"check": "verified-DoH-DoT-rewrite-and-AAAA-SVCB-HTTPS-suppression", "client": role, "status": "PASS"})

    for client_id in (unknown_id, ""):
        assert_answer(doh_query(context, host, client_id, domains[0]), refused=True)
        assert_answer(dot_query(context, (client_id + "." if client_id else "") + host, domains[0]), refused=True)
    rows.append({"check": "DoH-DoT-unknown-and-missing-ID-REFUSED", "status": "PASS"})

    for body in (doh_query(context, host, router_id, "example.com"), dot_query(context, phone_id + "." + host, "example.com")):
        assert len(body) >= 12 and body[3] & 15 == 0 and int.from_bytes(body[6:8], "big") > 0, "ordinary DNS did not resolve"
        assert socket.inet_aton(settings["relay_ipv4"]) not in body[12:], "ordinary DNS was rewritten to relay"
    rows.append({"check": "ordinary-domain-positive-unrewritten-over-DoH-and-DoT", "status": "PASS"})

    status, _ = management_request(management_base, "/control/status")
    assert status == 401, "anonymous AGH management was not denied"
    api("/control/status")
    original_acl = api("/control/access/list")
    assert router_id in original_acl["allowed_clients"] and phone_id in original_acl["allowed_clients"]
    try:
        revoked = dict(original_acl, allowed_clients=[value for value in original_acl["allowed_clients"] if value != phone_id])
        api("/control/access/set", revoked)
        assert_answer(doh_query(context, host, phone_id, domains[0]), refused=True)
        assert_answer(dot_query(context, phone_id + "." + host, domains[0]), refused=True)
        assert_answer(doh_query(context, host, router_id, domains[0]), settings["relay_ipv4"])
        rows.append({"check": "native-phone-revocation-denies-DoH-and-DoT-router-remains-admitted", "status": "PASS"})
    finally:
        api("/control/access/set", original_acl)
    assert api("/control/access/list") == original_acl, "fixture ACL restoration differs"
    assert_answer(dot_query(context, phone_id + "." + host, domains[0]), settings["relay_ipv4"])
    assert_answer(doh_query(context, host, phone_id, domains[0]), settings["relay_ipv4"])
    rows.append({"check": "native-ACL-restored-and-phone-readmitted", "status": "PASS"})

    for domain in domains:
        for port, hop in ((18444, "relay"), (18443, "edge")):
            row = tls_origin("127.0.0.1", port, domain)
            row.update(check="dynamic-origin-public-CA-verified-TLS", hop=hop)
            rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--management-base", required=True)
    parser.add_argument("--admin-password-file", type=Path, required=True)
    args = parser.parse_args()
    settings = json.loads(args.settings.read_text(encoding="utf-8"))
    password = args.admin_password_file.read_text(encoding="utf-8").rstrip("\r\n")
    print(json.dumps(run(settings, args.ca, args.management_base, password), indent=2))


if __name__ == "__main__":
    main()
