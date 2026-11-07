"""Run native policy acceptance only on a disposable Linux Docker runner."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import traceback

from tools.render import ROOT
from .prepare import PROJECT


def docker(*args, check=True, timeout=20):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("native Docker command failed: " + args[0])
    return result


def identities():
    identifiers = docker("ps", "-aq").stdout.split()
    if not identifiers:
        return []
    return sorted((item["Id"], item["State"]["StartedAt"])
                  for item in json.loads(docker("inspect", *identifiers).stdout))


def main():
    from .prepare import prepare
    from .probe import management_probe, probe, request

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("native fixture requires disposable Linux Docker")
    args.out = args.out.resolve()
    local = (ROOT / ".local").resolve()
    if not args.out.is_relative_to(local) or args.out == local:
        parser.error("output must be a new directory below repository .local")
    if args.out.exists():
        raise FileExistsError("new evidence directory required")
    os.environ["LOCAL_UID"] = str(os.getuid())
    os.environ["LOCAL_GID"] = str(os.getgid())
    selector = "label=com.docker.compose.project=" + PROJECT
    if docker("ps", "-aq", "--filter", selector).stdout.strip():
        raise RuntimeError("fixture project occupied; do not reuse")
    if docker("network", "ls", "-q", "--filter", selector).stdout.strip():
        raise RuntimeError("fixture networks already exist; inspect before retry")
    if docker("ps", "-aq", "--filter", "label=smart-dns.lab=true").stdout.strip():
        raise RuntimeError("another native lab is present; refuse shared Docker-provider discovery")
    reservations = []
    try:
        for port in (18443, 18444):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(listener)
            listener.bind(("127.0.0.1", port))
        compose = prepare(args.out, args.policy.resolve(), args.baseline.resolve(),
                          args.expected_policy_sha256)
        for service in compose["services"].values():
            docker("image", "inspect", service["image"])
    finally:
        for listener in reservations:
            listener.close()
    baseline = identities()
    (args.out / "before.private.json").write_text(json.dumps(baseline), encoding="utf-8")
    report = {"status": "FAIL", "scope": "native-policy-acceptance; product applications and production not checked"}
    command = ("compose", "-p", PROJECT, "-f", str(args.out / "compose.lab.json"))

    def stop_signal(signum, frame):
        raise TimeoutError("bounded native fixture interrupted")

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, stop_signal)
    signal.alarm(240)
    stage = "compose-config"
    try:
        docker(*command, "config", "-q")
        stage = "HAProxy-native-config"
        checked = docker("run", "--rm", "--pull", "never", "--name", PROJECT + "-syntax",
                         "--label", "com.docker.compose.project=" + PROJECT, "--network", "none",
                         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only",
                         "--memory", "128m", "--cpus", "0.5", "--pids-limit", "100",
                         "--mount", "type=bind,src=" + str(args.out / "haproxy.cfg") + ",dst=/usr/local/etc/haproxy/haproxy.cfg,readonly",
                         "--mount", "type=bind,src=" + str(args.out / "denied-v4.txt") + ",dst=/usr/local/etc/haproxy/denied-v4.txt,readonly",
                         "--entrypoint", "haproxy", compose["services"]["relay"]["image"],
                         "-c", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
        (args.out / "native-check.private.log").write_text(checked.stdout + checked.stderr, encoding="utf-8")
        stage = "compose-up"
        docker(*command, "up", "-d", "--pull", "never")
        stage = "Docker-provider-readiness"
        deadline = time.monotonic() + 35
        while True:
            try:
                status, body = request("existing.example.net")
                if status == 200 and b"Hostname:" in body:
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic() > deadline:
                raise TimeoutError("native Docker-provider HTTP readiness expired")
            time.sleep(.25)
        stage = "locked-image-readback"
        identifiers = docker(*command, "ps", "-q").stdout.split()
        containers = json.loads(docker("inspect", *identifiers).stdout)
        assert len(containers) == len(compose["services"]), "incomplete fixture service set"
        for container in containers:
            labels = container["Config"]["Labels"]
            assert labels["com.docker.compose.project"] == PROJECT
            expected = compose["services"][labels["com.docker.compose.service"]]["image"]
            image = json.loads(docker("image", "inspect", expected).stdout)[0]
            digest = expected.split("@", 1)[1]
            assert container["State"]["Running"] and container["Image"] == image["Id"]
            assert any(reference.endswith("@" + digest) for reference in image.get("RepoDigests", [])), "locked image digest mismatch"
        report["images"] = {"status": "PASS", "locked_running_services": len(containers)}
        stage = "native-wire-and-rule-readback"
        report["probes"] = probe(args.out, docker, PROJECT)
        stage = "native-product-management"
        report["management"] = management_probe(args.out, docker, PROJECT)
        report["status"] = "PASS"
    except BaseException as error:
        (args.out / "failure.private.log").write_text(traceback.format_exc(), encoding="utf-8")
        report["failure_type"] = type(error).__name__
        report["failure_stage"] = stage
    finally:
        signal.alarm(0)
        errors = []
        try:
            logs = docker(*command, "logs", "--no-color", check=False)
            (args.out / "compose.private.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
        except BaseException:
            errors.append("log-collection")
        try:
            stopped = docker(*command, "down", "--volumes", "--remove-orphans", check=False)
            (args.out / "cleanup.private.log").write_text(stopped.stdout + stopped.stderr, encoding="utf-8")
            assert stopped.returncode == 0
        except BaseException:
            errors.append("compose-down")
        try:
            remaining = docker("ps", "-aq", "--filter", selector).stdout.split()
            if remaining:
                docker("rm", "-f", *remaining)
            networks = docker("network", "ls", "-q", "--filter", selector).stdout.split()
            if networks:
                docker("network", "rm", *networks)
            assert not docker("ps", "-aq", "--filter", selector).stdout.strip()
            assert not docker("network", "ls", "-q", "--filter", selector).stdout.strip()
            after = identities()
            (args.out / "after.private.json").write_text(json.dumps(after), encoding="utf-8")
            assert after == baseline, "existing container identity or StartedAt changed"
        except BaseException:
            errors.append("resource-and-identity-readback")
        report["cleanup"] = "PASS" if not errors else errors
        if errors:
            report["status"] = "FAIL"
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
