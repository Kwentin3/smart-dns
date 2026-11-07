"""Service catalogue contracts; compiled candidates are not live deployment."""
import copy
import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from tools.render import approved_rules, compile_config


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "revision": 2, "domain_policy": "exact",
            "excluded_zones": ["google.com", "microsoft.com", "local"],
            "excluded_domains": {},
            "services": [
                {"id": "chatgpt", "name": "ChatGPT", "enabled": True,
                 "reason": "Selected offline candidate", "domains": ["chatgpt.com", "shared.assets.net"],
                 "source": "v2fly-service-catalog"},
                {"id": "claude", "name": "Claude", "enabled": True,
                 "reason": "Selected offline candidate", "domains": ["claude.ai", "shared.assets.net"],
                 "source": "v2fly-service-catalog"},
            ],
        }
        self.settings = {
            "own_zones": ["operator.example.net"], "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32],
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "admin_username": "labadmin",
            "admin_password_hash": "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56",
        }

    def compile(self, catalog):
        rules = approved_rules(catalog)
        return rules, compile_config(rules, self.settings, {domain: "1.1.1.1" for domain in rules["domains"]})

    def assert_consumers(self, artifacts, expected):
        dns = artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"]
        dns_hosts = {re.fullmatch(r"\|([^|]+)\|\$.*", rule)[1] for rule in dns}
        haproxy = artifacts["haproxy.cfg"]
        relay_hosts = set(re.findall(r"^  acl policy_allowed req\.ssl_sni,lower -m str (\S+)$", haproxy, re.MULTILINE))
        labels = artifacts["compose.lab.json"]["services"]["relay"]["labels"]
        rule = labels.get("traefik.tcp.routers.sd-relay.rule", "")
        edge_hosts = set(re.findall(r"HostSNI\(`([^`]+)`\)", rule))
        self.assertEqual(dns_hosts, expected)
        self.assertEqual(relay_hosts, expected)
        self.assertEqual(edge_hosts, expected)
        self.assertNotIn("*", rule)
        if not expected:
            self.assertEqual(dns, [])
            self.assertEqual(labels["traefik.enable"], "false")
            self.assertFalse(any(key.startswith("traefik.tcp.routers.") for key in labels))
            self.assertIn("  tcp-request content reject\n", haproxy)
            self.assertNotIn("  server fixed ", haproxy)
            self.assertNotIn("  use_backend ", haproxy)

    def test_enable_disable_shared_domain_dedup_and_exact_consumer_parity(self):
        rules, artifacts = self.compile(self.catalog)
        self.assertEqual(rules["domains"], ["chatgpt.com", "claude.ai", "shared.assets.net"])
        self.assert_consumers(artifacts, set(rules["domains"]))
        self.catalog["services"][0]["enabled"] = False
        self.catalog["services"][0]["reason"] = "Operator disabled this candidate"
        rules, artifacts = self.compile(self.catalog)
        self.assertEqual(rules["domains"], ["claude.ai", "shared.assets.net"])
        self.assert_consumers(artifacts, {"claude.ai", "shared.assets.net"})
        self.assertNotIn("child.claude.ai", rules["domains"])
        self.catalog["services"][1]["enabled"] = False
        self.catalog["services"][1]["reason"] = "Operator disabled this candidate"
        rules, artifacts = self.compile(self.catalog)
        self.assertEqual(rules["domains"], [])
        self.assert_consumers(artifacts, set())

    def test_global_domain_exclusion_removes_shared_domain_from_every_service(self):
        self.catalog["excluded_domains"] = {"shared.assets.net": "Not accepted for this pilot"}
        rules, artifacts = self.compile(self.catalog)
        self.assertEqual(rules["domains"], ["chatgpt.com", "claude.ai"])
        self.assert_consumers(artifacts, {"chatgpt.com", "claude.ai"})

    def test_catalog_validation_does_not_mutate_the_reviewed_source(self):
        original = copy.deepcopy(self.catalog)
        first = approved_rules(self.catalog)
        self.assertEqual(first, approved_rules(self.catalog))
        self.assertEqual(self.catalog, original)
        self.assertIn("service_states", first)

    def test_candidate_preserves_explained_service_states_without_claiming_activation(self):
        self.catalog["services"][0].update(enabled=False, reason="Disabled by operator")
        rules, artifacts = self.compile(self.catalog)
        self.assertEqual(rules["service_states"][0]["reason"], "Disabled by operator")
        self.assertIs(rules["service_states"][0]["enabled"], False)
        snapshot = artifacts["snapshot.json"]
        self.assertEqual(snapshot["status"], "candidate-not-applied")
        self.assertEqual(snapshot["desired_services"], rules["service_states"])
        self.assertEqual(snapshot["domains"], ["claude.ai", "shared.assets.net"])

    def test_rejects_nonboolean_flags_duplicate_or_invalid_service_ids(self):
        for enabled in ("false", 0, 1, None):
            with self.subTest(enabled=enabled):
                catalog = copy.deepcopy(self.catalog)
                catalog["services"][0]["enabled"] = enabled
                with self.assertRaises(ValueError):
                    approved_rules(catalog)
        for service_id in ("", "ChatGPT", "with spaces", "../escape", "chatgpt"):
            with self.subTest(service_id=service_id):
                catalog = copy.deepcopy(self.catalog)
                catalog["services"][1]["id"] = service_id
                with self.assertRaises(ValueError):
                    approved_rules(catalog)

    def test_rejects_invalid_domain_even_in_disabled_service(self):
        for domain in ("*.claude.ai", ".claude.ai", "Claude.ai", "claude.ai.", "https://claude.ai", "1.1.1.1", "localhost"):
            for enabled in (True, False):
                with self.subTest(domain=domain, enabled=enabled):
                    catalog = copy.deepcopy(self.catalog)
                    catalog["services"][0].update(domains=[domain], enabled=enabled)
                    with self.assertRaises(ValueError):
                        approved_rules(catalog)

    def test_rejects_unexplained_disabled_state_or_domain_exclusion(self):
        for reason in ("", "   "):
            catalog = copy.deepcopy(self.catalog)
            catalog["services"][0].update(enabled=False, reason=reason)
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                approved_rules(catalog)
        for exclusions in ({"unknown.domain.net": "Not part of catalog"}, {"claude.ai": ""}, {"claude.ai": "   "}):
            with self.subTest(exclusions=exclusions):
                catalog = copy.deepcopy(self.catalog)
                catalog["excluded_domains"] = exclusions
                with self.assertRaises(ValueError):
                    approved_rules(catalog)

    def test_rejects_suffix_policy_instead_of_silently_expanding_hosts(self):
        self.catalog["domain_policy"] = "suffix"
        with self.assertRaises(ValueError):
            approved_rules(self.catalog)

    def test_enabled_service_requires_at_least_one_explicit_domain(self):
        self.catalog["services"][0]["domains"] = []
        with self.assertRaises(ValueError):
            approved_rules(self.catalog)

    def test_manual_baseline_cli_show_and_enable_never_fetch_upstream(self):
        from tools.catalog import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, registry = root / "pilot.json", root / "registry.json"
            catalog = copy.deepcopy(self.catalog)
            catalog["services"][0]["enabled"] = False
            policy.write_text(json.dumps(catalog), encoding="utf-8")
            registry.write_text(json.dumps({"schema_version": 1, "index": {}, "definitions": {}}), encoding="utf-8")
            registry_before, policy_before = registry.read_bytes(), policy.read_bytes()
            def invoke(command, *extras):
                output = io.StringIO()
                args = ["catalog", command, "chatgpt", "--rules", str(policy), "--registry", str(registry), *extras]
                with patch("sys.argv", args), contextlib.redirect_stdout(output):
                    main()
                return output.getvalue()
            with patch("tools.catalog.fetch_snapshot", side_effect=AssertionError("manual baseline must not fetch")):
                shown = json.loads(invoke("show"))
                self.assertEqual(shown["service"], catalog["services"][0])
                self.assertEqual(shown["status"], "desired-policy-only")
                self.assertEqual(policy.read_bytes(), policy_before)
                invoke("enable", "--reason", "Owner re-enabled frozen baseline")
            saved = json.loads(policy.read_text(encoding="utf-8"))
            self.assertTrue(saved["services"][0]["enabled"])
            self.assertEqual(saved["services"][0]["domains"], catalog["services"][0]["domains"])
            self.assertNotIn("upstream", saved["services"][0])
            self.assertEqual(saved["revision"], catalog["revision"] + 1)
            self.assertEqual(registry.read_bytes(), registry_before)
            self.assertEqual(approved_rules(saved)["domains"], ["chatgpt.com", "claude.ai", "shared.assets.net"])


if __name__ == "__main__":
    unittest.main()
