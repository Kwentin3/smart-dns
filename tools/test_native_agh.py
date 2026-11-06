"""Run real pinned AGH with a deterministic UDP upstream, no external DNS."""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

from probe import check_dns
from render import ROOT, compile_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    stop = threading.Event()
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.settimeout(0.2)
    upstream_port = upstream.getsockname()[1]
    def serve():
        while not stop.is_set():
            try:
                request, addr = upstream.recvfrom(4096)
            except socket.timeout:
                continue
            response = request[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + request[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("198.51.100.77")
            upstream.sendto(response, addr)
    thread = threading.Thread(target=serve)
    thread.start()
    folder = ROOT / ".local/native-agh"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "work").mkdir(exist_ok=True)
    settings = {"doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32], "own_zones": ["example.net"], "upstream_dns": [f"127.0.0.1:{upstream_port}"], "bootstrap_dns": []}
    rules = json.loads((ROOT / "rules/pilot.json").read_text())
    config = compile_config(rules, settings, dict(zip(rules["domains"], ["1.1.1.1", "8.8.8.8"]))) ["agh-conf/AdGuardHome.yaml"]
    config["http"]["address"] = "127.0.0.1:13000"
    config["dns"]["bind_hosts"] = ["127.0.0.1"]
    config["dns"]["port"] = 15353
    path = folder / "AdGuardHome.yaml"
    path.write_text(json.dumps(config), encoding="utf-8")
    process = None
    try:
        with (folder / "server.log").open("wb") as log:
            process = subprocess.Popen([str(Path(args.binary).resolve()), "-c", str(path), "-w", str(folder / "work"), "--no-check-update"], stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("AGH stopped: inspect .local/native-agh/server.log")
                try:
                    with socket.create_connection(("127.0.0.1", 13000), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            rows = check_dns("http://127.0.0.1:13000/dns-query", "dns.example.net", "a" * 32, rules["domains"], "192.0.2.10", "ordinary.example.net", "198.51.100.77")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as plain:
                plain.settimeout(1)
                from probe import question
                plain.sendto(question("ordinary.example.net"), ("127.0.0.1", 15353))
                try:
                    plain.recv(4096)
                    raise AssertionError("unauthenticated plain DNS returned a packet")
                except (socket.timeout, ConnectionResetError):
                    rows.append({"check": "plain-DNS-UDP-unauthorized-denied", "status": "PASS"})
            with socket.create_connection(("127.0.0.1", 15353), timeout=1) as plain_tcp:
                plain_tcp.settimeout(1)
                wire = question("ordinary.example.net")
                plain_tcp.sendall(struct.pack("!H", len(wire)) + wire)
                try:
                    body = plain_tcp.recv(4096)
                    assert not body or (len(body) >= 14 and body[5] & 15 == 5 and body[8:10] == b"\0\0"), ("plain TCP returned useful DNS", body.hex())
                except (socket.timeout, ConnectionResetError):
                    pass
                rows.append({"check": "plain-DNS-TCP-unauthorized-denied", "status": "PASS"})
            print(json.dumps(rows, indent=2))
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stop.set()
        thread.join(timeout=2)
        upstream.close()
        assert not thread.is_alive()


if __name__ == "__main__":
    main()
