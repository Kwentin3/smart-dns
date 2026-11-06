"""Wire-level checks shared by local native AGH and isolated Compose lab."""
import argparse
import base64
import json
from pathlib import Path
import socket
import ssl
import struct
import urllib.error
import urllib.request
if __package__:
    from .render import approved_rules
else:
    from render import approved_rules
import urllib.parse


def question(name, qtype=1):
    return struct.pack("!6H", 1234, 256, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack("!2H", qtype, 1)


def doh(url, host, wire, method="POST"):
    headers = {"Content-Type": "application/dns-message", "Host": host}
    if method == "GET":
        url += "?" + urllib.parse.urlencode({"dns": base64.urlsafe_b64encode(wire).rstrip(b"=").decode()})
    req = urllib.request.Request(url, data=wire if method == "POST" else None, headers=headers, method=method)
    # Lab edge uses a disposable/default certificate. Origin TLS checks below
    # ALWAYS use the system CA trust and expected origin hostname.
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def check_dns(base, host, client_id, domains, relay_ip, direct="example.com", direct_ip=None):
    rows = []
    for suffix in ("", "/" + "0" * 32):
        status, body = doh(base + suffix, host, question(domains[0]))
        assert status == 200 and len(body) >= 12 and body[3] & 15 == 5 and body[6:8] == b"\0\0", ("DNS REFUSED denial", status)
        rows.append({"check": "anonymous" if not suffix else "unknown-client", "status": "PASS", "http": status, "dns_rcode": "REFUSED", "answer_count": 0})
    for domain in domains:
        status, body = doh(base + "/" + client_id, host, question(domain))
        assert status == 200 and body[3] & 15 == 0 and struct.unpack("!H", body[6:8])[0] == 1 and body[-4:] == socket.inet_aton(relay_ip), ("rewrite", domain, status, body.hex())
        for qtype in (28, 64, 65):
            status, body = doh(base + "/" + client_id, host, question(domain, qtype))
            assert status == 200 and body[3] & 15 == 0 and body[6:8] == b"\0\0", ("suppress", domain, qtype, status)
        rows.append({"check": "rewrite-A-and-empty-AAAA-SVCB-HTTPS", "domain": domain, "status": "PASS"})
    status, body = doh(base + "/" + client_id, host, question(domains[0]), method="GET")
    assert status == 200 and len(body) >= 12 and body[3] & 15 == 0 and body[6:8] == b"\0\1" and body[-4:] == socket.inet_aton(relay_ip), "GET DoH rewrite failed"
    rows.append({"check": "authorized-GET-without-admin-credentials", "status": "PASS"})
    for name in (direct, "sub." + domains[0]):
        status, body = doh(base + "/" + client_id, host, question(name))
        assert status == 200 and len(body) >= 12 and socket.inet_aton(relay_ip) not in body[12:], ("exact/direct", name, status)
        if name == direct or direct_ip is not None:
            assert body[3] & 15 == 0 and struct.unpack("!H", body[6:8])[0] > 0, ("direct resolution failed", name)
            if direct_ip:
                assert body[-4:] == socket.inet_aton(direct_ip)
        rows.append({"check": "direct-answer-verified" if name == direct or direct_ip is not None else "subdomain-not-rewritten", "domain": name, "status": "PASS"})
    return rows


def management_request(base, endpoint, username=None, password=None, payload=None):
    """Use only against the disposable AGH fixture; never emit credentials."""
    headers = {"Content-Type": "application/json"}
    if username is not None:
        credential = base64.b64encode((username + ":" + password).encode()).decode()
        headers["Authorization"] = "Basic " + credential
    request = urllib.request.Request(base + endpoint, data=None if payload is None else json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def check_management(base, username, password):
    status, _ = management_request(base, "/control/status")
    assert status == 401, ("anonymous management", status)
    status, _ = management_request(base, "/control/status", username, password)
    assert status == 200, ("authenticated management", status)
    status, _ = management_request(base, "/control/status", username, password + "-wrong")
    assert status == 401, ("incorrect management password", status)
    status, _ = management_request(base, "/control/access/set", payload={"allowed_clients": [], "disallowed_clients": [], "blocked_hosts": []})
    assert status == 401, ("anonymous ACL mutation was not rejected", status)
    return [{"check": "management-anonymous-wrong-password-401-authenticated-200", "status": "PASS"},
            {"check": "anonymous-ACL-mutation-401", "status": "PASS"}]


def check_revocation(base, host, client_id, domain, username, password):
    status, body = management_request(base, "/control/access/list", username, password)
    assert status == 200, "cannot read fixture admission settings"
    original = json.loads(body)
    replacement = dict(original, allowed_clients=["b" * 32])
    assert client_id != "b" * 32
    try:
        status, _ = management_request(base, "/control/access/set", username, password, replacement)
        assert status == 200, "cannot revoke fixture ID"
        for method in ("POST", "GET"):
            status, answer = doh(base + "/dns-query/" + client_id, host, question(domain), method)
            assert status == 200 and len(answer) >= 12 and answer[3] & 15 == 5 and answer[6:8] == b"\0\0", "revoked fixture ID returned useful DNS"
    finally:
        status, _ = management_request(base, "/control/access/set", username, password, original)
        assert status == 200, "cannot restore fixture admission settings"
    status, answer = doh(base + "/dns-query/" + client_id, host, question(domain))
    assert status == 200 and len(answer) >= 12 and answer[3] & 15 == 0 and answer[6:8] != b"\0\0", "restored fixture ID failed"
    return [{"check": "native-ID-revocation-GET-POST-and-restoration", "status": "PASS"}]


def tls_origin(host, port, sni):
    with socket.create_connection((host, port), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=sni) as tls:
            return {"check": "origin-certificate", "domain": sni, "status": "PASS", "tls": tls.version()}


def rejected_tls(host, port, sni):
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with ssl._create_unverified_context().wrap_socket(raw, server_hostname=sni):
                raise AssertionError("unapproved SNI completed TLS")
    except (ssl.SSLError, ConnectionResetError):
        return {"check": "relay-reject-" + str(sni), "status": "PASS"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--rules", default="rules/pilot.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--edge-port", type=int, default=18443)
    parser.add_argument("--relay-port", type=int, default=18444)
    parser.add_argument("--management-base", help="Direct disposable AGH fixture URL; no production use")
    parser.add_argument("--admin-password-file", type=Path)
    parser.add_argument("--check-revocation", action="store_true", help="Temporarily mutate and restore disposable fixture ACL")
    args = parser.parse_args()
    settings = json.load(open(args.settings, encoding="utf-8"))
    domains = approved_rules(json.load(open(args.rules, encoding="utf-8")))["domains"]
    base = f"https://{args.host}:{args.edge_port}"
    rows = check_dns(base + "/dns-query", settings["doh_host"], settings["client_ids"][0], domains, settings["relay_ipv4"])
    for domain in domains:
        rows.append(tls_origin(args.host, args.edge_port, domain))
    for name in ("not-approved.example.net", None, "127.0.0.1", "sub." + domains[0]):
        rows.append(rejected_tls(args.host, args.relay_port, name))
    status, body = doh(base + "/dns-query", "existing.example.net", b"")
    assert status == 200 and b"Hostname:" in body, ("existing router", status)
    rows.append({"check": "existing-HTTP-router-coexistence", "status": "PASS"})
    if args.management_base:
        if args.admin_password_file is None:
            parser.error("--management-base requires --admin-password-file")
        password = args.admin_password_file.read_text(encoding="utf-8").rstrip("\r\n")
        rows += check_management(args.management_base, settings["admin_username"], password)
        if args.check_revocation:
            rows += check_revocation(args.management_base, settings["doh_host"], settings["client_ids"][0], domains[0], settings["admin_username"], password)
    elif args.check_revocation:
        parser.error("--check-revocation requires --management-base")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
