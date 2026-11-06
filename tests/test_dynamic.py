"""Offline contracts for opt-in native dynamic-origin rendering."""
import copy
import ipaddress
import re
import unittest

from tools.render import compile_config

LAB_HASH = "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56"


class DynamicOriginTests(unittest.TestCase):
    def setUp(self):
        self.rules = {"domains": ["chatgpt.com", "claude.ai"], "excluded_zones": ["local", "internal"]}
        self.settings = {"doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32],
                         "own_zones": ["example.net"], "own_public_ipv4": ["8.8.4.4"],
                         "admin_username": "labadmin", "admin_password_hash": LAB_HASH,
                         "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
                         "origin_dns": ["9.9.9.9", "1.1.1.1"]}

    def render(self, settings=None, rules=None, origins=None):
        return compile_config(self.rules if rules is None else rules, self.settings if settings is None else settings, origins)

    def test_dynamic_mode_needs_no_fixed_snapshot_and_retains_candidate_identity(self):
        result = self.render()
        self.assertEqual(result["snapshot.json"]["origin_mode"], "dynamic-ipv4")
        self.assertEqual(result["snapshot.json"]["origins"], {})
        self.assertEqual(result["snapshot.json"]["origin_dns"], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(result["snapshot.json"]["status"], "candidate-not-applied")

    def test_dynamic_and_fixed_origin_inputs_are_not_silently_combined(self):
        with self.assertRaises(ValueError):
            self.render(origins={"chatgpt.com": "1.0.0.1", "claude.ai": "1.0.0.1"})
        fixed = copy.deepcopy(self.settings)
        del fixed["origin_dns"]
        with self.assertRaises(ValueError):
            self.render(settings=fixed)
        self.assertNotIn("denied-v4.txt", self.render(settings=fixed, origins={host: "1.0.0.1" for host in self.rules["domains"]}))

    def test_independent_resolvers_must_be_unique_public_literals(self):
        unsafe = [[], None, "9.9.9.9", ["9.9.9.9", "9.9.9.9"], [None], ["dns.example.org"],
                  ["9.9.9.9:53"], ["https://dns.example.org/dns-query"], ["::1"], ["10.1.2.3"],
                  ["127.0.0.1"], ["169.254.169.254"], ["100.64.0.1"], ["192.0.2.1"], ["224.0.0.1"],
                  ["168.63.129.16"], [self.settings["relay_ipv4"]], ["8.8.4.4"],
                  ["9.9.9.9\n  server injected 127.0.0.1:80"], ["9.9.9.9\0"]]
        for servers in unsafe:
            with self.subTest(servers=servers), self.assertRaises(ValueError):
                self.render(settings=dict(self.settings, origin_dns=servers))

    def test_denied_destinations_are_published_and_mounted_read_only(self):
        result = self.render()
        entries = result["denied-v4.txt"].splitlines()
        networks = [ipaddress.IPv4Network(entry) for entry in entries]
        for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "168.63.129.16", "100.64.0.1", "224.0.0.1"):
            self.assertTrue(any(ipaddress.IPv4Address(address) in network for network in networks), address)
        for own in (self.settings["relay_ipv4"], *self.settings["own_public_ipv4"]):
            self.assertIn(own + "/32", entries)
        self.assertFalse(any(ipaddress.IPv4Address("1.0.0.1") in network for network in networks))
        relay = result["compose.lab.json"]["services"]["relay"]
        self.assertIn("./denied-v4.txt:/usr/local/etc/haproxy/denied-v4.txt:ro", relay["volumes"])
        self.assertTrue(relay["read_only"])

    def test_resolver_or_denied_ingress_change_changes_snapshot_identity(self):
        before = self.render()["snapshot.json"]["sha256"]
        changed_resolver = self.render(settings=dict(self.settings, origin_dns=["1.0.0.1"]))
        changed_ingress = self.render(settings=dict(self.settings, own_public_ipv4=["8.8.4.4", "8.8.8.8"]))
        self.assertNotEqual(before, changed_resolver["snapshot.json"]["sha256"])
        self.assertNotEqual(before, changed_ingress["snapshot.json"]["sha256"])
        self.assertIn("8.8.8.8/32", changed_ingress["denied-v4.txt"].splitlines())

    def test_dynamic_path_uses_same_exact_host_set_and_all_off_is_safe(self):
        result = self.render()
        dns_hosts = {rule.split("|", 2)[1] for rule in result["agh-conf/AdGuardHome.yaml"]["user_rules"]}
        hap_hosts = set(re.findall(r"^  acl policy_allowed req\.ssl_sni,lower -m str (\S+)$", result["haproxy.cfg"], re.M))
        labels = result["compose.lab.json"]["services"]["relay"]["labels"]
        edge_hosts = set(re.findall(r"HostSNI\(`([^`]+)`\)", labels["traefik.tcp.routers.sd-relay.rule"]))
        self.assertEqual(dns_hosts, set(self.rules["domains"]))
        self.assertEqual(hap_hosts, dns_hosts)
        self.assertEqual(edge_hosts, dns_hosts)
        disabled = self.render(rules=dict(self.rules, domains=[]))
        self.assertEqual(disabled["agh-conf/AdGuardHome.yaml"]["user_rules"], [])
        self.assertEqual(disabled["compose.lab.json"]["services"]["relay"]["labels"]["traefik.enable"], "false")
        self.assertIn("default_backend denied", disabled["haproxy.cfg"])
        self.assertNotIn("backend origin_dynamic", disabled["haproxy.cfg"])
        self.assertEqual(disabled["agh-conf/AdGuardHome.yaml"]["dns"]["allowed_clients"], self.settings["client_ids"])


if __name__ == "__main__":
    unittest.main()
