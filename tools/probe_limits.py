"""Exercise native DoH limits with real HTTP requests and a held UDP fixture.

Only for the disposable lab: temporarily replaces native AGH upstreams and
always restores them. The UDP fixture binds the task-owned bridge gateway.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

from probe import doh, management_request, question


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--management-base", required=True)
    parser.add_argument("--admin-password-file", required=True)
    parser.add_argument("--fixture-bind", required=True)
    args = parser.parse_args()
    settings = json.loads(Path(args.settings).read_text())
    password = Path(args.admin_password_file).read_text().rstrip("\r\n")
    host = settings["doh_host"]
    url = "https://127.0.0.1:18443/dns-query/" + settings["client_ids"][0]
    api = lambda path, payload=None: management_request(args.management_base, path, settings["admin_username"], password, payload)
    rows = []
    status, body = api("/control/dns_info")
    assert status == 200, "cannot capture fixture upstreams"
    old_upstreams = json.loads(body)["upstream_dns"]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.fixture_bind, 0))
    udp.settimeout(.05)
    released, stopped = threading.Event(), threading.Event()
    pending = []
    lock = threading.Lock()

    def response(wire):
        end = 12
        while wire[end]:
            end += wire[end] + 1
        end += 5
        return wire[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + wire[12:end] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("198.51.100.77")

    def upstream():
        while not stopped.is_set():
            try:
                wire, address = udp.recvfrom(4096)
                with lock:
                    pending.append((wire, address))
            except socket.timeout:
                pass
            if released.is_set():
                with lock:
                    batch, pending[:] = pending[:], []
                for wire, address in batch:
                    udp.sendto(response(wire), address)

    thread = threading.Thread(target=upstream)
    pool = ThreadPoolExecutor(max_workers=8)
    thread.start()
    try:
        status, _ = api("/control/dns_config", {"upstream_dns": [f"{args.fixture_bind}:{udp.getsockname()[1]}"]})
        assert status == 200, "cannot select disposable upstream"
        futures = [pool.submit(doh, url, host, question(f"load-{i}.example.net")) for i in range(8)]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with lock:
                count = len(pending)
            if count == 8:
                break
            time.sleep(.02)
        assert count == 8 and not any(f.done() for f in futures), "did not hold eight actual upstream requests"
        status, _ = doh(url, host.upper() + ":443", question("load-ninth.example.net"))
        assert status == 429, ("native inFlightReq did not reject ninth request", status)
        with lock:
            assert len(pending) == 8, "ninth request reached upstream"
        status, payload = doh("https://127.0.0.1:18443/", "existing.example.net", b"")
        assert status == 200 and b"Hostname:" in payload, "unrelated router failed while DoH was full"
        released.set()
        for future in futures:
            status, answer = future.result(timeout=5)
            assert status == 200 and answer[-4:] == socket.inet_aton("198.51.100.77"), "held DNS request failed after release"
        rows.append({"check": "native-inflight-eight-held-ninth-429-other-router-200", "status": "PASS"})
    finally:
        released.set()
        try:
            pool.shutdown(wait=True)
            status, _ = api("/control/dns_config", {"upstream_dns": old_upstreams})
            assert status == 200, "fixture upstream restore failed"
        finally:
            stopped.set()
            thread.join(timeout=2)
            udp.close()
            assert not thread.is_alive()

    # Sequential persistent HTTP: inFlightReq cannot cause these 429s. Mixed
    # Host case/ports must consume the SAME rate bucket after native overwrite.
    connection = http.client.HTTPSConnection("127.0.0.1", 18443, context=ssl._create_unverified_context(), timeout=5)
    accepted, limited = 0, 0
    start = time.monotonic()
    try:
        for i in range(120):
            request_host = (host, host.upper(), host + ":443", host.upper() + ":8443")[i % 4]
            connection.request("POST", "/dns-query/" + settings["client_ids"][0], question("chatgpt.com"), headers={"Host": request_host, "Content-Type": "application/dns-message", "X-Forwarded-For": f"198.51.100.{i % 250 + 1}"})
            reply = connection.getresponse()
            body = reply.read()
            assert reply.status in (200, 429), ("unexpected rate response", reply.status)
            if reply.status == 200:
                assert body[-4:] == socket.inet_aton(settings["relay_ipv4"])
                accepted += 1
            else:
                limited += 1
    finally:
        connection.close()
    elapsed = time.monotonic() - start
    assert limited > 0 and accepted <= 40 + 20 * elapsed + 2, "rate bucket is absent or split by Host variants"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status, body = doh(url, host, question("chatgpt.com"))
        if status == 200:
            assert body[-4:] == socket.inet_aton(settings["relay_ipv4"])
            break
        assert status == 429
        time.sleep(.1)
    else:
        raise AssertionError("DoH did not recover after bounded burst")
    rows.append({"check": "native-shared-rate-budget-host-variants-429-and-recovery", "status": "PASS", "accepted": accepted, "limited": limited, "elapsed_seconds": round(elapsed, 3)})
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
