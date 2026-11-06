"""Validate actual generated bundles before any native apply is attempted."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.render import approved_rules, compile_config, write_new
from tools.service_policy import PolicyError, validate_candidate


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


if __name__ == "__main__":
    unittest.main()
