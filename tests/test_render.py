"""Offline config contracts; public fixture IPs are not verified service origins."""
import copy
import json
from pathlib import Path
import re
import unittest

from tools.render import compile_config


class RenderContractTests(unittest.TestCase):
    def setUp(self):
        self.rules = {
            "domains": ["chatgpt.com", "claude.ai"],
            "excluded_zones": ["google.com", "microsoft.com", "local", "internal", "localhost"],
        }
        self.settings = {
            "own_zones": ["operator.example.net"],
            "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10",
            "client_ids": ["0123456789abcdef0123456789abcdef"],
            "upstream_dns": ["https://dns.example.org/dns-query"],
            "bootstrap_dns": ["1.1.1.1"],
        }
        self.origins = {"chatgpt.com": "1.1.1.1", "claude.ai": "8.8.8.8"}

    def render(self):
        return compile_config(self.rules, self.settings, self.origins)

    def test_checked_in_pilot_and_source_pins(self):
        root = Path(__file__).resolve().parents[1]
        rules = json.loads((root / "rules/pilot.json").read_text(encoding="utf-8"))
        compile_config(rules, self.settings, {host: "1.1.1.1" for host in rules["domains"]})
        sources = json.loads((root / "rules/sources.json").read_text(encoding="utf-8"))
        self.assertIn("proposal-only", sources["policy"])
        for source in sources["sources"]:
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
            self.assertIn("/blob/" + source["commit"] + "/", source["reference"])
            self.assertIn("license", source)
            self.assertNotEqual(source["use"], "import")

    def test_three_generated_host_sets_have_exact_parity(self):
        artifacts = self.render()
        dns_rules = artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"]
        parsed_dns = [re.fullmatch(r"\|([^|]+)\|\$dnstype=(A|AAAA\|HTTPS\|SVCB),dnsrewrite=(.+)", rule) for rule in dns_rules]
        self.assertTrue(all(parsed_dns), dns_rules)
        dns_hosts = {match[1] for match in parsed_dns}
        haproxy = artifacts["haproxy.cfg"]
        relay_hosts = set(re.findall(r"^  acl host_\d+ req\.ssl_sni,lower -m str (\S+)$", haproxy, re.MULTILINE))
        tcp_rule = artifacts["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        edge_hosts = set(re.findall(r"HostSNI\(`([^`]+)`\)", tcp_rule))
        expected = set(self.rules["domains"])
        self.assertEqual(dns_hosts, expected)
        self.assertEqual(relay_hosts, expected)
        self.assertEqual(edge_hosts, expected)
        self.assertEqual(tcp_rule, " || ".join(f"HostSNI(`{host}`)" for host in self.rules["domains"]))
        self.assertNotIn("*", tcp_rule)
        self.assertNotIn("HostSNIRegexp", tcp_rule)
        self.assertNotIn("-m end", haproxy)
        self.assertNotRegex(haproxy, r"(?m)^\s*(?:resolvers|server-template)\b")
        self.assertNotRegex(haproxy, r"\b(?:resolvers|resolve-prefer|init-addr)\b")
        self.assertEqual(set(re.findall(r"^  server fixed (\S+):443$", haproxy, re.MULTILINE)), set(self.origins.values()))
        self.assertIn("  default_backend denied\nbackend denied\n  tcp-request content reject\n", haproxy)
        for host in expected:
            self.assertEqual(sum(match[1] == host for match in parsed_dns), 2)
            self.assertIn(f"|{host}|$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10", dns_rules)
            self.assertIn(f"|{host}|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;", dns_rules)
            self.assertNotIn("child." + host, dns_hosts | relay_hosts | edge_hosts)

    def test_doh_uses_actual_insecure_enabled_schema_and_client_ids(self):
        agh = self.render()["agh-conf/AdGuardHome.yaml"]
        self.assertIs(agh["http"]["doh"]["insecure_enabled"], True)
        self.assertNotIn("insecure", agh["http"]["doh"])
        self.assertEqual(agh["dns"]["allowed_clients"], self.settings["client_ids"])
        self.assertIs(agh["dns"]["serve_plain_dns"], True)
        self.assertNotIn("ports", self.render()["compose.lab.json"]["services"]["dns"])
        self.assertNotIn(self.settings["relay_ipv4"], agh["dns"]["allowed_clients"])
        self.assertNotIn("0.0.0.0/0", agh["dns"]["allowed_clients"])
        self.assertNotIn("127.0.0.1", agh["dns"]["allowed_clients"])

    def test_rejects_invalid_excluded_and_own_domains(self):
        bad_domains = [
            "*.chatgpt.com", ".chatgpt.com", "ChatGPT.com", "chatgpt.com.",
            "https://chatgpt.com", "chatgpt.com:443", "1.1.1.1", "localhost",
            "printer.local", "printer.internal", "google.com", "ai.google.com",
            "microsoft.com", "copilot.microsoft.com", "operator.example.net",
            "child.operator.example.net", "dns.example.net", "child.dns.example.net",
        ]
        for domain in bad_domains:
            with self.subTest(domain=domain):
                rules = copy.deepcopy(self.rules)
                rules["domains"] = [domain]
                with self.assertRaises(ValueError):
                    compile_config(rules, self.settings, {domain: "1.1.1.1"})

    def test_rejects_nonpublic_or_noncanonical_origins(self):
        for address in [
            "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "224.0.0.1", "239.1.2.3",
            "255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "::1", "2606:4700:4700::1111", "::ffff:1.1.1.1", "01.1.1.1",
            "chatgpt.com", "1.1.1.1:443",
        ]:
            with self.subTest(address=address):
                origins = {**self.origins, "chatgpt.com": address}
                with self.assertRaises(ValueError):
                    compile_config(self.rules, self.settings, origins)

    def test_rejects_missing_and_extra_origins(self):
        for origins in [{"chatgpt.com": "1.1.1.1"}, {**self.origins, "other.example.org": "1.1.1.1"}]:
            with self.subTest(origins=origins):
                with self.assertRaises(ValueError):
                    compile_config(self.rules, self.settings, origins)

    def test_rejects_own_ingress_and_provider_service(self):
        for address in ["168.63.129.16", "192.0.2.10"]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                compile_config(self.rules, self.settings, {**self.origins, "chatgpt.com": address})
        with self.assertRaises(ValueError):
            compile_config(self.rules, {**self.settings, "relay_ipv4": "1.1.1.1"}, self.origins)
        with self.assertRaises(ValueError):
            compile_config(self.rules, {**self.settings, "own_public_ipv4": ["1.1.1.1"]}, self.origins)

    def test_rejects_empty_unsorted_duplicate_or_oversized_domains(self):
        for domains in [[], ["claude.ai", "chatgpt.com"], ["chatgpt.com", "chatgpt.com"], sorted(f"host{i:02d}.example.org" for i in range(21))]:
            with self.subTest(domains=domains):
                rules = {**self.rules, "domains": domains}
                with self.assertRaises(ValueError):
                    compile_config(rules, self.settings, {host: "1.1.1.1" for host in domains})

    def test_rejects_missing_duplicate_or_invalid_client_ids(self):
        valid = self.settings["client_ids"][0]
        for ids in [[], [valid, valid], ["short"], ["A" * 32], ["g" * 32], ["a" * 31], ["a" * 65], ["127.0.0.1"], ["0.0.0.0/0"]]:
            with self.subTest(ids=ids):
                settings = {**self.settings, "client_ids": ids}
                with self.assertRaises(ValueError):
                    compile_config(self.rules, settings, self.origins)

    def test_generation_is_deterministic_and_does_not_mutate_inputs(self):
        before = copy.deepcopy((self.rules, self.settings, self.origins))
        first = self.render()
        self.assertEqual(first, self.render())
        self.assertEqual((self.rules, self.settings, self.origins), before)
        self.assertEqual(first["snapshot.json"]["domains"], self.rules["domains"])
        self.assertEqual(first["snapshot.json"]["origins"], self.origins)


if __name__ == "__main__":
    unittest.main()
