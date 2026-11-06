"""Disposable native AGH DoT/state-ownership experiment; localhost only."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import time

if __package__:
    from .probe import doh, management_request, question
    from .render import ROOT, compile_config
else:
    from probe import doh, management_request, question
    from render import ROOT, compile_config

ROUTER_ID, PHONE_ID = "a" * 32, "b" * 32
ADMIN = "labadmin"
PASSWORD = "lab-only-change-me"  # Public disposable fixture, never deployment input.
PASSWORD_HASH = "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56"
BASE = "http://127.0.0.1:13001"
HOST = "dns.example.net"
SELECTED, RELAY, DIRECT = "chatgpt.com", "192.0.2.10", "198.51.100.77"


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError("truncated DNS-over-TLS frame")
        data.extend(chunk)
    return bytes(data)


def dot_query(context, server_name, name=SELECTED, qtype=1):
    wire = question(name, qtype)
    with socket.create_connection(("127.0.0.1", 1853), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            tls.sendall(struct.pack("!H", len(wire)) + wire)
            length = struct.unpack("!H", receive_exact(tls, 2))[0]
            if length < 12:
                raise ValueError("short DNS-over-TLS response")
            return receive_exact(tls, length)


def assert_answer(body, address=None, refused=False):
    assert len(body) >= 12 and body[:2] == question(SELECTED)[:2], "invalid DNS response identity"
    assert body[2] & 128, "not a DNS response"
    if refused:
        assert body[3] & 15 == 5 and body[6:8] == b"\0\0", "unauthorized DNS was not REFUSED"
    else:
        assert body[3] & 15 == 0, "DNS query failed"
        if address is None:
            assert body[6:8] == b"\0\0", "expected empty DNS answer"
        else:
            assert body[6:8] == b"\0\1" and body[-4:] == socket.inet_aton(address), "unexpected DNS A answer"


def api(endpoint, payload=None):
    status, body = management_request(BASE, endpoint, ADMIN, PASSWORD, payload)
    assert status == 200, "authenticated fixture API failed"
    return json.loads(body) if payload is None and body else None


def check_preserved(context, expected_acl, expected_answer):
    assert api("/control/access/list") == expected_acl, "service update changed native client admission"
    api("/control/status")  # Same admin credentials remain valid after each update.
    assert_answer(dot_query(context, PHONE_ID + "." + HOST), refused=True)
    for attempt in range(30):
        status, body = doh(BASE + "/dns-query/" + ROUTER_ID, HOST, question(SELECTED))
        assert status == 200, "router DoH failed"
        try:
            assert_answer(body, expected_answer)
            break
        except AssertionError:
            if attempt == 29:
                raise
            time.sleep(.1)


def run(binary, certificate, private_key, ca):
    stop = threading.Event()
    upstream = thread = process = None
    rows = []
    try:
        # Refuse occupied fixture ports before starting or issuing any API write.
        for port, kind in ((13001, socket.SOCK_STREAM), (1853, socket.SOCK_STREAM), (15355, socket.SOCK_STREAM), (15355, socket.SOCK_DGRAM)):
            with socket.socket(socket.AF_INET, kind) as available:
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    available.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                available.bind(("127.0.0.1", port))
        context = ssl.create_default_context(cafile=str(Path(ca).resolve()))
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.settimeout(.2)

        def serve():
            while not stop.is_set():
                try:
                    request, address = upstream.recvfrom(4096)
                except socket.timeout:
                    continue
                response = request[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + request[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(DIRECT)
                upstream.sendto(response, address)

        thread = threading.Thread(target=serve)
        thread.start()
        settings = {"doh_host": HOST, "relay_ipv4": RELAY, "client_ids": [ROUTER_ID, PHONE_ID],
                    "own_zones": ["example.net"], "admin_username": ADMIN, "admin_password_hash": PASSWORD_HASH,
                    "upstream_dns": [f"127.0.0.1:{upstream.getsockname()[1]}"], "bootstrap_dns": [],
                    "dot": {"server_name": HOST, "certificate_path": str(Path(certificate).resolve()), "private_key_path": str(Path(private_key).resolve())}}
        config = compile_config({"domains": [SELECTED], "excluded_zones": []}, settings, {SELECTED: "1.1.1.1"})["agh-conf/AdGuardHome.yaml"]
        assert config["tls"]["enabled"], "renderer did not enable native DoT"
        config["http"]["address"] = "127.0.0.1:13001"
        config["dns"].update(bind_hosts=["127.0.0.1"], port=15355, serve_plain_dns=False)
        config["tls"].update(port_dns_over_tls=1853, port_https=0, strict_sni_check=True)
        folder = ROOT / ".local/native-dot"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "work").mkdir(exist_ok=True)
        config_path = folder / "AdGuardHome.yaml"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        with (folder / "server.log").open("wb") as log:
            process = subprocess.Popen([str(Path(binary).resolve()), "-c", str(config_path), "-w", str(folder / "work"), "--no-check-update"], stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("AGH DoT fixture stopped; inspect private local server log")
                try:
                    with socket.create_connection(("127.0.0.1", 1853), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("AGH DoT fixture readiness timeout")

            status, _ = management_request(BASE, "/control/status")
            assert status == 401, "anonymous management was not rejected"
            original_acl = api("/control/access/list")
            original_rules = api("/control/filtering/status")["user_rules"]
            assert_answer(dot_query(context, PHONE_ID + "." + HOST), RELAY)
            for qtype in (28, 64, 65):
                assert_answer(dot_query(context, PHONE_ID + "." + HOST, qtype=qtype))
            for name in ("ordinary.example.net", "sub." + SELECTED):
                assert_answer(dot_query(context, PHONE_ID + "." + HOST, name), DIRECT)
            rows.append({"check": "verified-wildcard-DoT-rewrite-suppression-and-exact-scope", "status": "PASS"})
            for name in ("c" * 32 + "." + HOST, HOST):
                assert_answer(dot_query(context, name), refused=True)
            rows.append({"check": "DoT-unknown-and-missing-ID-REFUSED", "status": "PASS"})
            try:
                dot_query(context, "outside.example.org")
            except ssl.SSLError:
                rows.append({"check": "outside-SAN-TLS-rejected", "status": "PASS"})
            else:
                raise AssertionError("outside-SAN TLS unexpectedly succeeded")

            revoked_acl = dict(original_acl, allowed_clients=[ROUTER_ID])
            try:
                api("/control/access/set", revoked_acl)
                check_preserved(context, revoked_acl, RELAY)
                api("/control/filtering/set_rules", {"rules": []})
                check_preserved(context, revoked_acl, DIRECT)
                api("/control/filtering/set_rules", {"rules": original_rules})
                check_preserved(context, revoked_acl, RELAY)
                rows.append({"check": "service-update-and-rollback-preserve-revocation-admin-and-router-DoH", "status": "PASS"})
            finally:
                try:
                    api("/control/filtering/set_rules", {"rules": original_rules})
                finally:
                    api("/control/access/set", original_acl)
            assert_answer(dot_query(context, PHONE_ID + "." + HOST), RELAY)
            rows.append({"check": "phone-reinstated-only-by-explicit-ACL-restore", "status": "PASS"})

            try:
                with socket.create_connection(("127.0.0.1", 15355), timeout=.5):
                    raise AssertionError("disabled plain TCP DNS still listens")
            except (ConnectionRefusedError, socket.timeout):
                pass
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as plain:
                plain.settimeout(.5)
                plain.sendto(question(SELECTED), ("127.0.0.1", 15355))
                try:
                    plain.recv(4096)
                except (socket.timeout, ConnectionResetError):
                    pass
                else:
                    raise AssertionError("disabled plain UDP DNS returned data")
            rows.append({"check": "plain-TCP-no-connection-and-UDP-no-answer", "status": "PASS"})
    finally:
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            stop.set()
            if thread is not None and thread.ident is not None:
                thread.join(timeout=2)
            if upstream is not None:
                upstream.close()
            assert thread is None or not thread.is_alive(), "fixture upstream thread remains"
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "certificate", "private-key", "ca"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--out", type=Path, help="Optional new JSON receipt under .local; never overwrites an existing file")
    args = parser.parse_args()
    if args.out is not None:
        args.out = args.out.resolve()
        if not args.out.is_relative_to((ROOT / ".local").resolve()) or args.out.exists():
            parser.error("--out must be a new file under repository .local")
    receipt = json.dumps(run(args.binary, args.certificate, args.private_key, args.ca), indent=2) + "\n"
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as output:
            output.write(receipt)
    print(receipt, end="")


if __name__ == "__main__":
    main()
