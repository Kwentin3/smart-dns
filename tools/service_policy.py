"""Bounded service-only apply/readback/restore for an explicitly selected target.

No installation, daemon, credential database or ACL mutation. Production mode
operates only on a separately authorized existing Smart DNS project; it never
deploys or recreates its shared edge. Native AGH owns effective rules.
Stop-first also interrupts optional DoT carried by the relay. Forward work
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
from tools.render import catalog_rules, compile_config, compile_production


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


def management_address(base):
    url = urllib.parse.urlsplit(base)
    try:
        address, port = ipaddress.IPv4Address(url.hostname), url.port
        local = any(address in ipaddress.IPv4Network(net) for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    except ValueError:
        local, address, port = False, None, None
    require(url.scheme == "http" and local and not url.username and not url.password and
            not url.query and not url.fragment and url.path in ("", "/") and
            (port is None or 0 < port < 65536), "management must be a literal private/loopback HTTP endpoint")
    return address, port


def management_owned(address, port, dns, native_port):
    direct = str(address) in {n["IPAddress"] for n in dns["NetworkSettings"]["Networks"].values()} and str(port or 80) == native_port
    published = dns["NetworkSettings"]["Ports"].get(native_port + "/tcp") or []
    forwarded = address.is_loopback and any(p["HostIp"] == "127.0.0.1" and p["HostPort"] == str(port or 80) for p in published)
    require(direct or forwarded, "management endpoint is not owned by this Smart DNS container")


def relay_findings(current, expected, directory, manifest, image_id):
    """Same live image/label/mounted-byte contract for apply and read-only status."""
    findings = []
    if not current["State"]["Running"] or current["State"].get("Health", {}).get("Status", "healthy") != "healthy":
        findings.append("relay-not-ready")
    if current["Config"]["Image"] != expected["image"]:
        findings.append("relay-image-reference-drift")
    if current["Image"] != image_id:
        findings.append("relay-image-identity-drift")
    labels = current["Config"]["Labels"]
    # Renderer labels contain Compose's $$ escape; Docker stores the literal $.
    expected_labels = {k: v.replace("$$", "$") if isinstance(v, str) else v
                       for k, v in expected["labels"].items() if k.startswith("traefik.")}
    if {k: v for k, v in labels.items() if k.startswith("traefik.")} != expected_labels:
        findings.append("relay-routing-label-drift")
    for volume in expected["volumes"]:
        source, target, mode = volume.split(":")
        require(mode == "ro" and source in ("./haproxy.cfg", "./denied-v4.txt"), "unexpected relay mount")
        mounted = [m for m in current["Mounts"] if m["Destination"] == target]
        if len(mounted) != 1 or mounted[0]["RW"]:
            findings.append("relay-mount-drift")
            continue
        actual_path = Path(mounted[0]["Source"]).resolve(strict=True)
        if actual_path != (directory / source).resolve(strict=True):
            findings.append("relay-mount-source-drift")
        if hashlib.sha256(actual_path.read_bytes()).hexdigest() != manifest["relay_files_sha256"][Path(source).name]:
            findings.append("relay-mounted-bytes-drift")
    return sorted(set(findings))


def read_status(settings, catalog, *, project, management_base, admin_username, admin_password,
                production=False, registry=None, origins=None, docker_read=None, api_read=None):
    """Bounded service-policy observations, never a receipt or client-state owner.

    Injected boundaries return Docker stdout and (HTTP status, bytes). Only GET
    filtering/status and Docker ps/inspect/image inspect are issued. No files,
    locks, credentials, ACLs or native configuration are written.
    """
    pattern = r"smart-dns(?:-[a-z0-9][a-z0-9-]{0,48})?" if production else r"smart-dns-[a-z0-9][a-z0-9-]{0,48}"
    require(bool(re.fullmatch(pattern, project)), "Smart DNS project name required")
    address, port = management_address(management_base)
    deadline = time.monotonic() + 30
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def remaining():
        value = deadline - time.monotonic()
        require(value > 0, "status deadline exceeded")
        return min(5, value)

    def docker(*command):
        remaining()
        if docker_read is not None:
            return docker_read(*command)
        result = subprocess.run(["docker", *command], capture_output=True, text=True, timeout=remaining())
        require(result.returncode == 0, "native Docker status read failed")
        return result.stdout

    def native_rules():
        remaining()
        if api_read is not None:
            code, body = api_read("/control/filtering/status")
        else:
            authorization = base64.b64encode((admin_username + ":" + admin_password).encode()).decode()
            request = urllib.request.Request(management_base.rstrip("/") + "/control/filtering/status", headers={"Authorization": "Basic " + authorization}, method="GET")
            try:
                with opener.open(request, timeout=remaining()) as response:
                    code, body = response.status, response.read(2 * 1024 * 1024 + 1)
            except urllib.error.HTTPError:
                raise PolicyError("native AGH status read failed") from None
        require(code == 200 and len(body) <= 2 * 1024 * 1024, "native AGH status read failed")
        return json.loads(body)["user_rules"]

    def owned():
        identifiers = docker("ps", "-aq", "--filter", "label=com.docker.compose.project=" + project).split()
        require(bool(identifiers), "existing Smart DNS project required")
        items = json.loads(docker("inspect", *identifiers))
        services = {}
        for name in ("dns", "relay"):
            matches = [item for item in items if (item["Config"].get("Labels") or {}).get("com.docker.compose.project") == project and
                       item["Config"]["Labels"].get("com.docker.compose.service") == name]
            require(len(matches) == 1, "exactly one owned DNS and relay required")
            services[name] = matches[0]
        return services

    initial = owned()
    current = initial["relay"]
    mounts = [m for m in current["Mounts"] if m["Destination"] == "/usr/local/etc/haproxy/haproxy.cfg"]
    require(len(mounts) == 1 and not mounts[0]["RW"], "owned relay policy mount required")
    directory = Path(mounts[0]["Source"]).resolve(strict=True).parent
    manifest = read_json(directory / "snapshot.json")
    compose_name = "compose.production.json" if production else "compose.lab.json"
    configuration = read_json(directory / compose_name)
    expected = configuration["services"]["relay"]
    native_port = configuration["services"]["dns"]["labels"]["traefik.http.services.sd-doh.loadbalancer.server.port"]
    management_owned(address, port, initial["dns"], native_port)
    image_id = json.loads(docker("image", "inspect", expected["image"]))[0]["Id"]
    findings = relay_findings(current, expected, directory, manifest, image_id)
    effective = native_rules()
    if effective != manifest["service_rules"]:
        findings.append("native-rules-differ-from-mounted-generation")
    desired = (compile_production if production else compile_config)(catalog_rules(catalog, registry), settings, origins)
    desired_manifest = desired["snapshot.json"]
    if desired_manifest["sha256"] != manifest["sha256"]:
        findings.append("desired-generation-not-applied")
    if effective != desired_manifest["service_rules"]:
        findings.append("native-rules-differ-from-desired")
    if expected != desired[compose_name]["services"]["relay"]:
        findings.append("relay-configuration-differs-from-desired")
    for name, expected_hash in desired_manifest["relay_files_sha256"].items():
        if manifest["relay_files_sha256"].get(name) != expected_hash:
            findings.append("relay-policy-differs-from-desired")
    final = owned()
    findings.extend(relay_findings(final["relay"], expected, directory, manifest, image_id))
    identity = lambda value: [(name, item["Id"], item["State"]["StartedAt"]) for name, item in sorted(value.items())]
    if identity(initial) != identity(final) or native_rules() != effective:
        findings.append("native-state-changed-during-status")

    def services(states):
        return [{"id": state["id"], "enabled": state["enabled"],
                 "pending_scope": state.get("upstream_state", {}).get("pending_scope", []),
                 "partial": state.get("upstream_state", {}).get("partial", False)} for state in states]

    return {"status": "matches" if not findings else "drift", "scope": "service-policy-only",
            "desired_revision": catalog["revision"], "desired_generation": desired_manifest["sha256"],
            "actual_generation": manifest["sha256"], "actual_generation_source": "owned-relay-bind-mount",
            "desired_services": services(desired_manifest["desired_services"]),
            "actual_services": services(manifest.get("desired_services", [])), "findings": sorted(set(findings))}


def validate_candidate(accepted, candidate, settings, catalog, origins=None, *, production=False, registry=None):
    """Pure validation using the existing renderer, never a second HA grammar.

    Bootstrap hashes compare intended inputs, not all live native admin settings.
    The native AGH config in accepted may be normalized YAML and is not parsed.
    """
    accepted, candidate = Path(accepted), Path(candidate)
    old_manifest, new_manifest = (read_json(path / "snapshot.json") for path in (accepted, candidate))
    require(old_manifest["agh_bootstrap_sha256"] == new_manifest["agh_bootstrap_sha256"], "bootstrap infrastructure change rejected")
    try:
        compiler = compile_production if production else compile_config
        expected = compiler(catalog_rules(catalog, registry), settings, origins)
    except Exception:
        raise PolicyError("candidate renderer inputs rejected") from None
    for name, value in expected.items():
        if name == ("compose.production.json" if production else "compose.lab.json"):
            continue
        actual = (candidate / name).read_text(encoding="utf-8")
        require((actual == value) if isinstance(value, str) else (json.loads(actual) == value), "candidate differs from native renderer output")
    bootstrap = read_json(candidate / "agh-conf/AdGuardHome.yaml")
    require(bootstrap.pop("user_rules") == new_manifest["service_rules"] and
            digest(bootstrap) == new_manifest["agh_bootstrap_sha256"], "candidate bootstrap/rules manifest mismatch")
    compose_name = "compose.production.json" if production else "compose.lab.json"
    old_compose, new_compose = (read_json(path / compose_name) for path in (accepted, candidate))
    require(new_compose["services"]["relay"] == expected[compose_name]["services"]["relay"], "candidate relay differs from renderer")
    if production:
        require(new_compose == expected[compose_name], "production compose differs from renderer")
    require("@sha256:" in new_compose["services"]["relay"]["image"], "immutable relay image required")
    old_infra, new_infra = json.loads(json.dumps(old_compose)), json.loads(json.dumps(new_compose))
    old_infra["services"]["relay"].pop("labels")
    new_infra["services"]["relay"].pop("labels")
    require(old_infra == new_infra, "non-service infrastructure change rejected")
    return old_manifest, new_manifest, old_compose, new_compose


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--lab-only", action="store_true")
    target.add_argument("--production", action="store_true", help="Operate only on the separately authorized existing pilot")
    parser.add_argument("--accepted", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--status-only", action="store_true", help="Read actual owned policy and desired drift; no writes")
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True, help="Candidate service catalog")
    parser.add_argument("--registry", type=Path, default=Path(__file__).resolve().parents[1] / "rules/registry.json")
    parser.add_argument("--origins", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--management-base", required=True)
    parser.add_argument("--admin-username", required=True)
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.status_only:
        try:
            report = read_status(read_json(args.settings), read_json(args.rules), project=args.project,
                management_base=args.management_base, admin_username=args.admin_username,
                admin_password=args.admin_password_file.read_text(encoding="utf-8").rstrip("\r\n"), production=args.production,
                registry=read_json(args.registry) if args.registry.exists() else None,
                origins=read_json(args.origins) if args.origins else None)
        except Exception as error:
            report = {"status": "unavailable", "scope": "service-policy-only",
                      "error": str(error) if isinstance(error, PolicyError) else type(error).__name__}
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "matches" else 1
    if not (args.accepted and args.candidate and args.out):
        parser.error("apply requires --accepted, --candidate and --out")
    import fcntl  # Apply is a native Linux operation; status/pure checks also work on Windows.
    project_pattern = r"smart-dns(?:-[a-z0-9][a-z0-9-]{0,48})?" if args.production else r"smart-dns-[a-z0-9][a-z0-9-]{0,48}"
    require(bool(re.fullmatch(project_pattern, args.project)), "Smart DNS project name required")
    compose_name = "compose.production.json" if args.production else "compose.lab.json"
    require(".local" in args.out.resolve().parts, "receipt must stay under a private .local directory")
    address, port = management_address(args.management_base)
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
        raise PolicyError("another operation owns this Smart DNS project") from None
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

    def containers(all_host=False):
        selection = () if all_host else ("--filter", "label=com.docker.compose.project=" + args.project)
        identifiers = docker("ps", "-aq", *selection).stdout.split()
        require(bool(identifiers), "existing Smart DNS project required")
        return json.loads(docker("inspect", *identifiers).stdout)

    def relay():
        found = [item for item in containers() if item["Config"]["Labels"].get("com.docker.compose.service") == "relay"]
        require(len(found) == 1, "expected exactly one owned relay")
        return found[0]

    def protected():
        result = []
        for item in containers(all_host=args.production):
            labels = item["Config"].get("Labels") or {}
            owned_relay = labels.get("com.docker.compose.project") == args.project and labels.get("com.docker.compose.service") == "relay"
            owned_check = labels.get("smart-dns.policy-check") == check_token
            if not owned_relay and not owned_check:
                result.append((item["Id"], item["State"]["StartedAt"]))
        return sorted(result)

    def compose(directory, *command):
        return docker("compose", "-p", args.project, "-f", str(directory / compose_name), *command)

    def verify_relay(directory, configuration, wait=False):
        while True:
            current = relay()
            expected = configuration["services"]["relay"]
            ready = current["State"]["Running"] and current["State"].get("Health", {}).get("Status", "healthy") == "healthy"
            if ready:
                break
            require(wait, "accepted relay is not ready")
            timeout()
            time.sleep(.25)
        image = json.loads(docker("image", "inspect", expected["image"]).stdout)[0]
        findings = relay_findings(current, expected, directory, old_manifest if directory == accepted else new_manifest, image["Id"])
        require(not findings, "; ".join(findings))
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
            read_json(args.origins) if args.origins else None, production=args.production,
            registry=read_json(args.registry) if args.registry.exists() else None)
        old_rules, new_rules = old_manifest["service_rules"], new_manifest["service_rules"]
        dns = [item for item in containers() if item["Config"]["Labels"].get("com.docker.compose.service") == "dns"]
        require(len(dns) == 1, "exactly one owned DNS container required")
        native_port = str(read_json(candidate / "agh-conf/AdGuardHome.yaml")["http"]["address"].rsplit(":", 1)[1])
        management_owned(address, port, dns[0], native_port)
        require(rules() == old_rules, "actual native rules drift from accepted manifest")
        original_admission = admission()
        original_protected = protected()
        require(len(original_protected) >= (1 if args.production else 2), "protected existing services required")
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
    raise SystemExit(main())
