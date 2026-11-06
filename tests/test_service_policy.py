"""Validate actual generated bundles before any native apply is attempted."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.render import approved_rules, compile_config, write_new
from tools.service_policy import PolicyError, read_status, validate_candidate


class ServicePolicyTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "revision": 2, "domain_policy": "exact", "excluded_zones": ["local", "google.com"],
            "excluded_domains": {}, "services": [
                {"id": "chatgpt", "name": "ChatGPT", "enabled": True, "reason": "Offline candidate",
                 "domains": ["chatgpt.com"], "source": "v2fly-service-catalog"},
                {"id": "claude", "name": "Claude", "enabled": True, "reason": "Offline candidate",
                 "domains": ["claude.ai"], "source": "v2fly-service-catalog"},
            ],
        }
        self.settings = {
            "own_zones": ["example.net"], "doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10",
            "client_ids": ["a" * 32], "admin_username": "labadmin",
            "admin_password_hash": "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56",
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "origin_dns": ["1.1.1.1"],
        }
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.accepted = self.bundle("accepted", self.catalog)
        self.changed = copy.deepcopy(self.catalog)
        self.changed["services"][0].update(enabled=False, reason="Disabled by operator")
        self.candidate = self.bundle("candidate", self.changed)

    def bundle(self, name, catalog, settings=None):
        out = self.root / name
        write_new(compile_config(approved_rules(catalog), settings or self.settings), out)
        return out

    def validate(self, settings=None, catalog=None):
        return validate_candidate(self.accepted, self.candidate, settings or self.settings, catalog or self.changed)

    def test_recorded_relay_hashes_match_published_bytes_on_windows_and_linux(self):
        manifest = json.loads((self.accepted / "snapshot.json").read_text(encoding="utf-8"))
        for name, expected in manifest["relay_files_sha256"].items():
            self.assertEqual(hashlib.sha256((self.accepted / name).read_bytes()).hexdigest(), expected)

    def mutate_json(self, filename, mutation):
        path = self.candidate / filename
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_real_service_toggle_is_accepted_without_mutating_any_input(self):
        before = {path: path.read_bytes() for folder in (self.accepted, self.candidate) for path in folder.rglob("*") if path.is_file()}
        settings = copy.deepcopy(self.settings)
        catalog = copy.deepcopy(self.changed)
        old, new, old_compose, new_compose = self.validate()
        self.assertEqual(old["domains"], ["chatgpt.com", "claude.ai"])
        self.assertEqual(new["domains"], ["claude.ai"])
        self.assertEqual(old_compose["services"]["dns"], new_compose["services"]["dns"])
        self.assertEqual(self.settings, settings)
        self.assertEqual(self.changed, catalog)
        self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))

    def test_all_off_candidate_is_valid_and_contains_no_tcp_router(self):
        changed = copy.deepcopy(self.changed)
        changed["services"][1].update(enabled=False, reason="Disabled by operator")
        self.candidate = self.bundle("all-off", changed)
        _, manifest, _, compose = self.validate(catalog=changed)
        self.assertEqual(manifest["domains"], [])
        labels = compose["services"]["relay"]["labels"]
        self.assertEqual(labels["traefik.enable"], "false")
        self.assertFalse(any(key.startswith("traefik.tcp.routers.") for key in labels))

    def test_manual_haproxy_guard_removal_cannot_be_approved_by_receipt_hash(self):
        path = self.candidate / "haproxy.cfg"
        original = path.read_text(encoding="utf-8")
        changed = "\n".join(line for line in original.splitlines() if "-f /usr/local/etc/haproxy/denied-v4.txt" not in line) + "\n"
        self.assertNotEqual(changed, original)
        path.write_text(changed, encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.validate()
        self.mutate_json("snapshot.json", lambda value: value.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        with self.assertRaises(PolicyError):
            self.validate()

    def test_manual_denied_destination_file_change_is_rejected(self):
        path = self.candidate / "denied-v4.txt"
        original = path.read_text(encoding="utf-8")
        self.assertIn("127.0.0.0/8", original)
        path.write_text(original.replace("127.0.0.0/8\n", ""), encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.validate()

    def test_catalog_not_caller_snapshot_owns_candidate_domains(self):
        self.mutate_json("snapshot.json", lambda value: value.update(domains=["other.example.org"]))
        with self.assertRaises(PolicyError):
            self.validate()

    def test_actual_infrastructure_change_is_rejected(self):
        self.mutate_json("compose.lab.json", lambda value: value["services"]["dns"].update(ports=["0.0.0.0:3000:3000"]))
        with self.assertRaises(PolicyError):
            self.validate()

    def test_validly_regenerated_client_or_admin_change_is_not_a_service_update(self):
        changes = [
            {"client_ids": ["b" * 32]},
            {"admin_username": "otheradmin"},
            {"upstream_dns": ["https://other.example.org/dns-query"]},
        ]
        for index, change in enumerate(changes):
            with self.subTest(change=next(iter(change))):
                settings = {**self.settings, **change}
                self.candidate = self.bundle("changed-infrastructure-" + str(index), self.changed, settings)
                with self.assertRaises(PolicyError):
                    self.validate(settings=settings)

    def status_boundaries(self, directory=None):
        directory = directory or self.accepted
        compose = json.loads((directory / "compose.lab.json").read_text(encoding="utf-8"))
        manifest = json.loads((directory / "snapshot.json").read_text(encoding="utf-8"))
        project = "smart-dns-status-test"
        relay = compose["services"]["relay"]
        records = [
            {"Id": "dns-fixture", "Config": {"Labels": {"com.docker.compose.project": project, "com.docker.compose.service": "dns"}},
             "State": {"Running": True, "StartedAt": "unchanged-dns"},
             "NetworkSettings": {"Networks": {"dns": {"IPAddress": "172.20.0.2"}},
                                 "Ports": {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13000"}]}}},
            {"Id": "relay-fixture", "Config": {"Image": relay["image"], "Labels": {**{key: value.replace("$$", "$") for key, value in relay["labels"].items()}, "com.docker.compose.project": project, "com.docker.compose.service": "relay"}},
             "Image": "sha256:fixture-image", "State": {"Running": True, "StartedAt": "unchanged-relay"},
             "Mounts": [{"Source": str((directory / source).resolve()), "Destination": target, "RW": False}
                        for source, target, mode in (volume.split(":") for volume in relay["volumes"])]},
        ]
        commands, endpoints = [], []
        live = {"rules": copy.deepcopy(manifest["service_rules"])}

        def docker(*command):
            commands.append(command)
            if command[:2] == ("ps", "-aq"):
                self.assertIn("label=com.docker.compose.project=" + project, command)
                return "dns-fixture relay-fixture"
            if command == ("inspect", "dns-fixture", "relay-fixture"):
                return json.dumps(records)
            if command == ("image", "inspect", relay["image"]):
                return json.dumps([{"Id": "sha256:fixture-image"}])
            self.fail("status attempted a command outside native read boundaries")

        def api(endpoint):
            endpoints.append(endpoint)
            self.assertEqual(endpoint, "/control/filtering/status")
            return 200, json.dumps({"user_rules": live["rules"]}).encode()

        kwargs = {"project": project, "management_base": "http://127.0.0.1:13000", "admin_username": "labadmin",
                  "admin_password": "fixture-private-admin-secret", "docker_read": docker, "api_read": api}
        return kwargs, live, records, commands, endpoints

    def test_status_binds_actual_generation_to_owned_mount_without_writes_or_secrets(self):
        kwargs, _, _, commands, endpoints = self.status_boundaries()
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = read_status(self.settings, self.catalog, **kwargs)
        self.assertEqual(result["status"], "matches")
        self.assertEqual(result["actual_generation_source"], "owned-relay-bind-mount")
        self.assertEqual(result["actual_generation"], json.loads((self.accepted / "snapshot.json").read_text())["sha256"])
        self.assertTrue(commands)
        self.assertEqual(endpoints, ["/control/filtering/status", "/control/filtering/status"])
        self.assertEqual({path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}, before)
        for value in (kwargs["admin_password"], self.settings["client_ids"][0], self.settings["admin_password_hash"]):
            self.assertNotIn(value, json.dumps(result))

    def test_suffix_native_docker_dollar_interpolation_matches_but_wrong_regex_drifts(self):
        catalog = copy.deepcopy(self.catalog)
        catalog["domain_policy"] = "exact-and-suffix"
        catalog["services"][0]["domain_suffixes"] = ["openai.com"]
        directory = self.bundle("suffix-status", catalog)
        kwargs, _, records, _, _ = self.status_boundaries(directory)
        key = "traefik.tcp.routers.sd-relay.rule"
        raw_rule = json.loads((directory / "compose.lab.json").read_text(encoding="utf-8"))["services"]["relay"]["labels"][key]
        native_rule = records[1]["Config"]["Labels"][key]
        self.assertIn("HostSNIRegexp", raw_rule)
        self.assertIn("$$", raw_rule)
        self.assertNotIn("$$", native_rule)
        self.assertEqual(native_rule, raw_rule.replace("$$", "$"))
        self.assertEqual(read_status(self.settings, catalog, **kwargs)["status"], "matches")
        records[1]["Config"]["Labels"][key] = native_rule.replace("openai", "unapproved")
        result = read_status(self.settings, catalog, **kwargs)
        self.assertEqual(result["status"], "drift")
        self.assertIn("relay-routing-label-drift", result["findings"])

    def test_status_ignores_stale_success_receipt_when_native_rules_drift(self):
        kwargs, live, _, _, _ = self.status_boundaries()
        (self.root / "last-success.json").write_text(json.dumps({"status": "applied-and-readback"}), encoding="utf-8")
        live["rules"] = []
        result = read_status(self.settings, self.catalog, **kwargs)
        self.assertEqual(result["status"], "drift")
        self.assertIn("native-rules-differ-from-mounted-generation", result["findings"])
        self.assertIn("native-rules-differ-from-desired", result["findings"])

    def test_status_detects_actual_mounted_bytes_change_with_unchanged_receipt(self):
        kwargs, _, _, _, _ = self.status_boundaries()
        path = self.accepted / "denied-v4.txt"
        original = path.read_text(encoding="utf-8")
        self.assertIn("127.0.0.0/8", original)
        path.write_text(original.replace("127.0.0.0/8\n", ""), encoding="utf-8", newline="\n")
        result = read_status(self.settings, self.catalog, **kwargs)
        self.assertEqual(result["status"], "drift")
        self.assertIn("relay-mounted-bytes-drift", result["findings"])

    def test_status_reports_desired_and_actual_services_separately(self):
        kwargs, _, _, _, _ = self.status_boundaries()
        result = read_status(self.settings, self.changed, **kwargs)
        self.assertEqual(result["status"], "drift")
        self.assertIn("desired-generation-not-applied", result["findings"])
        self.assertIs(result["desired_services"][0]["enabled"], False)
        self.assertIs(result["actual_services"][0]["enabled"], True)

    def test_status_final_relay_stop_or_unhealthy_without_restart_is_drift(self):
        for change in ({"Running": False}, {"Health": {"Status": "unhealthy"}}):
            with self.subTest(change=change):
                kwargs, _, records, _, _ = self.status_boundaries()
                original = kwargs["docker_read"]
                inspections = []
                def changed_native_observation(*command):
                    if command[:1] == ("inspect",):
                        inspections.append(command)
                        if len(inspections) == 2:
                            records[1]["State"].update(change)
                    return original(*command)
                kwargs["docker_read"] = changed_native_observation
                result = read_status(self.settings, self.catalog, **kwargs)
                self.assertEqual(result["status"], "drift")
                self.assertIn("relay-not-ready", result["findings"])
                self.assertNotIn("native-state-changed-during-status", result["findings"])

    def test_status_final_routing_label_change_without_restart_is_drift(self):
        kwargs, _, records, _, _ = self.status_boundaries()
        original = kwargs["docker_read"]
        inspections = []
        def changed_native_observation(*command):
            if command[:1] == ("inspect",):
                inspections.append(command)
                if len(inspections) == 2:
                    records[1]["Config"]["Labels"]["traefik.enable"] = "false"
            return original(*command)
        kwargs["docker_read"] = changed_native_observation
        result = read_status(self.settings, self.catalog, **kwargs)
        self.assertEqual(result["status"], "drift")
        self.assertIn("relay-routing-label-drift", result["findings"])
        self.assertNotIn("native-state-changed-during-status", result["findings"])

    def test_status_exposes_pending_source_scope_and_partial_coverage(self):
        from tools.registry import REPOSITORY, normalize_rules
        kwargs, _, _, _, _ = self.status_boundaries()
        catalog = copy.deepcopy(self.catalog)
        catalog["services"][0]["upstream"] = {"source": "metacubex-sing", "list": "openai", "approved_scope": {"exact": [], "suffix": []}}
        definition = normalize_rules({"version": 2, "rules": [{"domain_suffix": ["openai.com"], "domain_regex": "^unsupported$"}]})
        definition["source_blob"] = "b" * 40
        registry = {"schema_version": 1, "source": {"repository": REPOSITORY, "commit": "a" * 40},
                    "index": {"openai": {"blob_sha": "b" * 40}}, "definitions": {"openai": definition}}
        result = read_status(self.settings, catalog, registry=registry, **kwargs)
        self.assertEqual(result["desired_services"][0]["pending_scope"], [{"kind": "suffix", "name": "openai.com"}])
        self.assertTrue(result["desired_services"][0]["partial"])

    def test_status_rejects_management_endpoint_not_owned_by_dns_before_http(self):
        kwargs, _, _, _, endpoints = self.status_boundaries()
        kwargs["management_base"] = "http://127.0.0.1:9999"
        with self.assertRaises(PolicyError):
            read_status(self.settings, self.catalog, **kwargs)
        self.assertEqual(endpoints, [])

    def test_status_cli_needs_no_candidate_output_or_linux_mutation_lock(self):
        from tools import service_policy
        kwargs, live, _, commands, _ = self.status_boundaries()
        settings, catalog, password = (self.root / name for name in ("settings.json", "catalog.json", "admin-password"))
        settings.write_text(json.dumps(self.settings), encoding="utf-8")
        catalog.write_text(json.dumps(self.catalog), encoding="utf-8")
        password.write_text(kwargs["admin_password"], encoding="utf-8")
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}

        def native_docker(command, **options):
            self.assertEqual(command[0], "docker")
            self.assertLessEqual(options["timeout"], 5)
            return SimpleNamespace(returncode=0, stdout=kwargs["docker_read"](*command[1:]))

        class Response(io.BytesIO):
            status = 200

        def native_http(request, **options):
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.full_url, kwargs["management_base"] + "/control/filtering/status")
            self.assertLessEqual(options["timeout"], 5)
            return Response(json.dumps({"user_rules": live["rules"]}).encode())

        argv = ["service_policy", "--lab-only", "--status-only", "--settings", str(settings), "--rules", str(catalog),
                "--registry", str(self.root / "absent-registry.json"), "--project", kwargs["project"],
                "--management-base", kwargs["management_base"], "--admin-username", "labadmin", "--admin-password-file", str(password)]
        output = io.StringIO()
        with patch("sys.argv", argv), patch.object(service_policy.subprocess, "run", side_effect=native_docker), \
             patch.object(service_policy.urllib.request, "build_opener") as opener, contextlib.redirect_stdout(output):
            opener.return_value.open.side_effect = native_http
            self.assertEqual(service_policy.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "matches")
        self.assertNotIn(kwargs["admin_password"], output.getvalue())
        self.assertTrue(commands)
        self.assertEqual({path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}, before)


if __name__ == "__main__":
    unittest.main()
