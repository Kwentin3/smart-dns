"""Bounded service-only apply/readback/restore for an existing disposable lab.

No installation, production deployment, daemon, credential database or ACL
mutation. Native AGH owns effective rules; renderer owns candidate representation.
Stop-first also interrupts optional DoT carried by this lab relay. Forward work
is bounded to 120 seconds, with a separate 60-second restore budget.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import base64

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.render import approved_rules, compile_config


class PolicyError(Exception):
    """A safe fixed diagnostic, without credential or response interpolation."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def validate_candidate(accepted, candidate, settings, catalog, origins=None):
    """Pure validation using the existing renderer, never a second HA grammar.

    Bootstrap hashes compare intended inputs, not all live native admin settings.
    The native AGH config in accepted may be normalized YAML and is not parsed.
    """
    accepted, candidate = Path(accepted), Path(candidate)
    old_manifest, new_manifest = (read_json(path / "snapshot.json") for path in (accepted, candidate))
    require(old_manifest["agh_bootstrap_sha256"] == new_manifest["agh_bootstrap_sha256"], "bootstrap infrastructure change rejected")
    try:
        expected = compile_config(approved_rules(catalog), settings, origins)
    except Exception:
        raise PolicyError("candidate renderer inputs rejected") from None
    for name, value in expected.items():
        if name == "compose.lab.json":
            continue
        actual = (candidate / name).read_text(encoding="utf-8")
        require((actual == value) if isinstance(value, str) else (json.loads(actual) == value), "candidate differs from native renderer output")
    bootstrap = read_json(candidate / "agh-conf/AdGuardHome.yaml")
    require(bootstrap.pop("user_rules") == new_manifest["service_rules"] and
            digest(bootstrap) == new_manifest["agh_bootstrap_sha256"], "candidate bootstrap/rules manifest mismatch")
    old_compose, new_compose = (read_json(path / "compose.lab.json") for path in (accepted, candidate))
    require(new_compose["services"]["relay"] == expected["compose.lab.json"]["services"]["relay"], "candidate relay differs from renderer")
    require("@sha256:" in new_compose["services"]["relay"]["image"], "immutable relay image required")
    old_infra, new_infra = json.loads(json.dumps(old_compose)), json.loads(json.dumps(new_compose))
    old_infra["services"]["relay"].pop("labels")
    new_infra["services"]["relay"].pop("labels")
    require(old_infra == new_infra, "non-service infrastructure change rejected")
    return old_manifest, new_manifest, old_compose, new_compose


def main():
    import fcntl  # Native Linux operation only; pure artifact checks work on Windows.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-only", action="store_true", required=True)
    parser.add_argument("--accepted", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True, help="Candidate service catalog")
    parser.add_argument("--origins", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--management-base", required=True)
    parser.add_argument("--admin-username", required=True)
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(bool(re.fullmatch(r"smart-dns-[a-z0-9][a-z0-9-]{0,48}", args.project)), "lab project name required")
    require(".local" in args.out.resolve().parts, "receipt must stay under a private .local directory")
    url = urllib.parse.urlsplit(args.management_base)
    try:
        address = ipaddress.IPv4Address(url.hostname)
        local = any(address in ipaddress.IPv4Network(net) for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        port = url.port
    except ValueError:
        local, port = False, None
    require(url.scheme == "http" and local and not url.username and not url.password and
            not url.query and not url.fragment and url.path in ("", "/") and
            (port is None or 0 < port < 65536), "management must be a literal private/loopback HTTP fixture")
    accepted, candidate = args.accepted.resolve(strict=True), args.candidate.resolve(strict=True)
    require(accepted != candidate, "accepted and candidate directories must differ")
    # One operator/project lock even when invoked from a different directory.
    lock_path = Path(tempfile.gettempdir()) / ("smart-dns-policy-" + str(os.getuid()) + "-" + args.project + ".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    require(os.fstat(descriptor).st_uid == os.getuid(), "project lock has another owner")
    lock = os.fdopen(descriptor, "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise PolicyError("another operation owns this lab project") from None
    args.out.parent.mkdir(parents=True, exist_ok=True)
    output = open(args.out, "x", encoding="utf-8")
    os.chmod(args.out, 0o600)
    report = {"status": "rejected", "project": args.project, "rollback": "not-needed"}
    deadline = time.monotonic() + 120
    mutated = False
    check_name = args.project + "-policy-check-" + str(os.getpid())
    check_token = str(time.time_ns())
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    password = args.admin_password_file.read_text(encoding="utf-8").rstrip("\r\n")
    authorization = "Basic " + base64.b64encode((args.admin_username + ":" + password).encode()).decode()

    def interrupt(signum, frame):
        raise PolicyError("operation interrupted")

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)

    def timeout():
        remaining = deadline - time.monotonic()
        require(remaining > 0, "operation deadline exceeded")
        return min(10, remaining)

    def docker(*command, check=True):
        result = subprocess.run(["docker", *command], capture_output=True, text=True, timeout=timeout())
        if check:
            require(result.returncode == 0, "bounded Docker operation failed")
        return result

    def api(endpoint, payload=None, authenticated=True):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = authorization
        request = urllib.request.Request(args.management_base.rstrip("/") + endpoint,
                                         data=None if payload is None else json.dumps(payload).encode(), headers=headers)
        try:
            with opener.open(request, timeout=timeout()) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def get(endpoint):
        status, body = api(endpoint)
        require(status == 200, "native AGH read failed")
        return json.loads(body)

    def rules():
        return get("/control/filtering/status")["user_rules"]

    def admission():
        profile = get("/control/profile")
        status, _ = api("/control/status", authenticated=False)
        require(status == 401, "anonymous native management was not denied")
        return get("/control/access/list"), profile["name"]

    def set_rules(values):
        status, _ = api("/control/filtering/set_rules", {"rules": values})
        require(status == 200 and rules() == values, "native rules write/readback failed")

    def containers():
        identifiers = docker("ps", "-aq", "--filter", "label=com.docker.compose.project=" + args.project).stdout.split()
        require(bool(identifiers), "existing disposable lab project required")
        return json.loads(docker("inspect", *identifiers).stdout)

    def relay():
        found = [item for item in containers() if item["Config"]["Labels"].get("com.docker.compose.service") == "relay"]
        require(len(found) == 1, "expected exactly one owned relay")
        return found[0]

    def protected():
        return sorted((item["Id"], item["State"]["StartedAt"]) for item in containers()
                      if item["Config"]["Labels"].get("com.docker.compose.service") != "relay")

    def compose(directory, *command):
        return docker("compose", "-p", args.project, "-f", str(directory / "compose.lab.json"), *command)

    def verify_relay(directory, configuration, wait=False):
        while True:
            current = relay()
            labels = current["Config"]["Labels"]
            expected = configuration["services"]["relay"]
            ready = current["State"]["Running"] and current["State"].get("Health", {}).get("Status", "healthy") == "healthy"
            if ready:
                break
            require(wait, "accepted relay is not ready")
            timeout()
            time.sleep(.25)
        require(current["Config"]["Image"] == expected["image"], "relay image reference drift")
        image = json.loads(docker("image", "inspect", expected["image"]).stdout)[0]
        require(current["Image"] == image["Id"], "running relay image identity drift")
        require({k: v for k, v in labels.items() if k.startswith("traefik.")} ==
                {k: v for k, v in expected["labels"].items() if k.startswith("traefik.")}, "actual relay routing label drift")
        for volume in expected["volumes"]:
            source, target, mode = volume.split(":")
            require(mode == "ro" and source in ("./haproxy.cfg", "./denied-v4.txt"), "unexpected relay mount")
            mounted = [m for m in current["Mounts"] if m["Destination"] == target]
            require(len(mounted) == 1 and not mounted[0]["RW"], "relay mount drift")
            actual_path = Path(mounted[0]["Source"]).resolve(strict=True)
            require(actual_path == (directory / source).resolve(strict=True), "relay mount source identity drift")
            manifest = old_manifest if directory == accepted else new_manifest
            require(hashlib.sha256(actual_path.read_bytes()).hexdigest() == manifest["relay_files_sha256"][Path(source).name],
                    "actual mounted relay bytes differ from accepted generation")
        if wait:
            addresses = [n["IPAddress"] for n in current["NetworkSettings"]["Networks"].values() if n["IPAddress"]]
            require(bool(addresses), "relay private address missing")
            while True:
                try:
                    with socket.create_connection((addresses[0], 8443), timeout=min(1, timeout())):
                        break
                except OSError:
                    timeout()
                    time.sleep(.25)
        return current

    try:
        old_manifest, new_manifest, old_compose, new_compose = validate_candidate(
            accepted, candidate, read_json(args.settings), read_json(args.rules),
            read_json(args.origins) if args.origins else None)
        old_rules, new_rules = old_manifest["service_rules"], new_manifest["service_rules"]
        dns = [item for item in containers() if item["Config"]["Labels"].get("com.docker.compose.service") == "dns"]
        require(len(dns) == 1, "exactly one owned DNS container required")
        native_port = str(read_json(candidate / "agh-conf/AdGuardHome.yaml")["http"]["address"].rsplit(":", 1)[1])
        direct = str(address) in {n["IPAddress"] for n in dns[0]["NetworkSettings"]["Networks"].values()} and str(port or 80) == native_port
        published = dns[0]["NetworkSettings"]["Ports"].get(native_port + "/tcp") or []
        forwarded = address.is_loopback and any(p["HostIp"] == "127.0.0.1" and p["HostPort"] == str(port or 80) for p in published)
        require(direct or forwarded, "management endpoint is not owned by this lab DNS container")
        require(rules() == old_rules, "actual native rules drift from accepted manifest")
        original_admission = admission()
        original_protected = protected()
        require(len(original_protected) >= 2, "existing DNS and edge services required")
        verify_relay(accepted, old_compose)
        mounts = []
        for volume in new_compose["services"]["relay"]["volumes"]:
            source, target, mode = volume.split(":")
            require(mode == "ro" and source in ("./haproxy.cfg", "./denied-v4.txt"), "unexpected relay mount")
            mounts += ["--mount", "type=bind,src=" + str((candidate / source).resolve(strict=True)) + ",dst=" + target + ",readonly"]
        try:
            docker("run", "--rm", "--pull", "never", "--name", check_name,
                   "--label", "smart-dns.policy-check=" + check_token, "--network", "none",
                   "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                   "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", *mounts,
                   "--entrypoint", "haproxy", new_compose["services"]["relay"]["image"],
                   "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
        finally:
            check = subprocess.run(["docker", "inspect", check_name], capture_output=True, text=True, timeout=5)
            if check.returncode == 0:
                leftover = json.loads(check.stdout)[0]
                require(leftover["Config"]["Labels"].get("smart-dns.policy-check") == check_token, "syntax-check ownership conflict")
                removed = subprocess.run(["docker", "rm", "-f", leftover["Id"]], capture_output=True, timeout=10)
                require(removed.returncode == 0, "syntax-check cleanup failed")
        require(admission() == original_admission and rules() == old_rules and protected() == original_protected,
                "native state changed during preparation")
        mutated = True  # stop can partly succeed even when its client reports an error.
        compose(accepted, "stop", "--timeout", "5", "relay")
        require(admission() == original_admission and rules() == old_rules, "native concurrent change conflict")
        set_rules(new_rules)
        compose(candidate, "up", "-d", "--no-deps", "--pull", "never", "relay")
        verify_relay(candidate, new_compose, wait=True)
        require(rules() == new_rules and admission() == original_admission, "native policy/admission readback conflict")
        require(protected() == original_protected, "DNS/edge/unrelated container identity changed")
        report.update(status="applied-and-readback", accepted_sha256=old_manifest["sha256"],
                      candidate_sha256=new_manifest["sha256"], protected_containers_unchanged=True,
                      admission_unchanged=True, product_wire_checks="external acceptance required")
    except BaseException as error:
        report["error"] = str(error) if isinstance(error, PolicyError) else type(error).__name__
        if mutated:
            report["status"] = "failed"
            deadline = time.monotonic() + 60
            closed = False
            try:
                compose(candidate, "stop", "--timeout", "5", "relay")
                closed = True
                require(admission() == original_admission, "native admission conflict; ACL is not restored")
                require(rules() in (old_rules, new_rules), "native concurrent rules conflict; relay left stopped")
                set_rules(old_rules)
                compose(accepted, "up", "-d", "--no-deps", "--pull", "never", "relay")
                closed = False
                verify_relay(accepted, old_compose, wait=True)
                require(rules() == old_rules and admission() == original_admission and protected() == original_protected,
                        "restored native state readback conflict")
                report["rollback"] = "restored-and-readback"
            except BaseException as restore_error:
                try:
                    compose(candidate, "stop", "--timeout", "5", "relay")
                    closed = True
                except BaseException:
                    closed = False
                report["rollback"] = {"status": "partial-failure", "relay_stopped": closed,
                                      "error": str(restore_error) if isinstance(restore_error, PolicyError) else type(restore_error).__name__}
    finally:
        json.dump(report, output, indent=2)
        output.write("\n")
        output.close()
        lock.close()
    print(json.dumps(report, indent=2))
    if report["status"] != "applied-and-readback":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
