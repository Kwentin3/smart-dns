"""Offline contracts for the approved two-service representation; never deploy."""
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from tools.render import approved_rules, compile_config, compile_production, write_new
from tools.service_policy import PolicyError, validate_candidate


class ProductionRepresentationTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "revision": 2, "domain_policy": "exact", "excluded_zones": ["local", "google.com"],
            "excluded_domains": {}, "services": [
                {"id": "chatgpt", "name": "ChatGPT", "enabled": True, "reason": "Reviewed candidate",
                 "domains": ["chatgpt.com"], "source": "v2fly-service-catalog"},
                {"id": "claude", "name": "Claude", "enabled": True, "reason": "Reviewed candidate",
                 "domains": ["claude.ai"], "source": "v2fly-service-catalog"},
            ],
        }
        self.settings = {
            "own_zones": ["example.net"], "doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10",
            "client_ids": ["a" * 32], "admin_username": "labadmin",
            "admin_password_hash": "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56",
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "origin_dns": ["1.1.1.1"],
            "dot": {"server_name": "dns.example.net", "certificate_path": "/certs/fullchain.pem", "private_key_path": "/certs/privkey.pem"},
        }

    def artifacts(self, catalog=None, settings=None):
        return compile_production(approved_rules(catalog or self.catalog), settings or self.settings)

    def bundle(self, root, name, catalog=None, settings=None):
        out = root / name
        write_new(self.artifacts(catalog, settings), out)
        return out

    def test_native_dns_relay_and_denied_destinations_reuse_existing_owner(self):
        before = copy.deepcopy((self.catalog, self.settings))
        lab = compile_config(approved_rules(self.catalog), self.settings)
        production = self.artifacts()
        self.assertEqual(set(production) - {"compose.production.json"}, set(lab) - {"compose.lab.json"})
        for name in production:
            if name != "compose.production.json":
                self.assertEqual(production[name], lab[name], name)
        self.assertEqual((self.catalog, self.settings), before)

    def test_only_two_bounded_components_with_private_management_and_native_edge_labels(self):
        compose = self.artifacts()["compose.production.json"]
        services = compose["services"]
        self.assertEqual(set(services), {"dns", "relay"})
        dns, relay = services["dns"], services["relay"]
        self.assertEqual(dns["ports"], ["127.0.0.1:13000:3000"])
        self.assertEqual(relay["ports"], ["0.0.0.0:853:8853"])
        self.assertEqual(dns["networks"], ["dns"])
        self.assertEqual(set(relay["networks"]), {"dns", "edge"})
        self.assertTrue(compose["networks"]["edge"]["external"])
        self.assertFalse(compose["networks"]["dns"].get("external", False))
        self.assertEqual(dns["labels"]["traefik.docker.network"], compose["networks"]["dns"]["name"])
        self.assertEqual(relay["labels"]["traefik.docker.network"], compose["networks"]["edge"]["name"])
        self.assertEqual(dns["labels"]["traefik.http.routers.sd-doh.tls.certresolver"], "le")
        self.assertEqual(dns["labels"]["traefik.http.routers.sd-doh.observability.accesslogs"], "false")
        sni = relay["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertEqual(set(re.findall(r"HostSNI\(`([^`]+)`\)", sni)), {"chatgpt.com", "claude.ai"})
        self.assertNotIn("*", sni)
        for service in services.values():
            self.assertRegex(service["mem_limit"], r"^[1-9][0-9]*[kmg]$")
            self.assertGreater(service["cpus"], 0)
            self.assertGreater(service["pids_limit"], 0)
            self.assertIn("@sha256:", service["image"])
            self.assertNotIn("docker.sock", json.dumps(service))
            self.assertNotIn("smart-dns.lab", service["labels"])
            self.assertIn("max-size", service["logging"]["options"])

    def test_native_dot_certificate_settings_are_mandatory(self):
        settings = dict(self.settings)
        del settings["dot"]
        with self.assertRaises(ValueError):
            self.artifacts(settings=settings)

    def test_production_toggle_and_all_off_validate_with_published_byte_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = self.bundle(root, "accepted")
            changed = copy.deepcopy(self.catalog)
            for index in range(2):
                changed["services"][index].update(enabled=False, reason="Operator disabled this service")
                candidate = self.bundle(root, "candidate-" + str(index), changed)
                _, snapshot, old, new = validate_candidate(accepted, candidate, self.settings, changed, production=True)
                self.assertEqual(old["services"]["dns"], new["services"]["dns"])
                self.assertEqual(snapshot["domains"], ["claude.ai"] if index == 0 else [])
                for name, expected in snapshot["relay_files_sha256"].items():
                    self.assertEqual(hashlib.sha256((candidate / name).read_bytes()).hexdigest(), expected)
                if index == 1:
                    labels = new["services"]["relay"]["labels"]
                    self.assertEqual(labels["traefik.enable"], "false")
                    self.assertFalse(any(key.startswith("traefik.tcp.routers.") for key in labels))
                accepted = candidate

    def test_production_validation_refuses_management_exposure_and_new_bootstrap_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = self.bundle(root, "accepted")
            candidate = self.bundle(root, "exposed")
            path = candidate / "compose.production.json"
            compose = json.loads(path.read_text(encoding="utf-8"))
            compose["services"]["dns"]["ports"] = ["0.0.0.0:13000:3000"]
            path.write_text(json.dumps(compose), encoding="utf-8")
            with self.assertRaises(PolicyError):
                validate_candidate(accepted, candidate, self.settings, self.catalog, production=True)
            settings = {**self.settings, "client_ids": ["b" * 32]}
            changed = self.bundle(root, "changed-clients", settings=settings)
            with self.assertRaises(PolicyError):
                validate_candidate(accepted, changed, settings, self.catalog, production=True)

    def test_manual_guard_change_is_rejected_even_with_updated_file_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = self.bundle(root, "accepted")
            candidate = self.bundle(root, "tampered")
            path = candidate / "haproxy.cfg"
            original = path.read_text(encoding="utf-8")
            changed = "\n".join(line for line in original.splitlines() if "-f /usr/local/etc/haproxy/denied-v4.txt" not in line) + "\n"
            self.assertNotEqual(original, changed)
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(changed)
            snapshot_path = candidate / "snapshot.json"
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            snapshot["relay_files_sha256"]["haproxy.cfg"] = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            with self.assertRaises(PolicyError):
                validate_candidate(accepted, candidate, self.settings, self.catalog, production=True)


if __name__ == "__main__":
    unittest.main()
