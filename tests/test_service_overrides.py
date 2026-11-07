"""Individual preferences over real GEO projection; synthetic transport only."""
import copy
import unittest

from test_geoblock_registry import fixture
from test_render import LAB_PASSWORD_HASH
from tools.bootstrap_geoblock import prepare
from tools.render import approved_rules, catalog_rules, compile_config


def service(identifier, *, enabled=True, domains=(), suffixes=(), kind=None):
    result = {"id": identifier, "name": identifier, "enabled": enabled,
              "reason": "Explicit local test preference", "domains": sorted(domains),
              "domain_suffixes": sorted(suffixes)}
    if kind is not None:
        result["kind"] = kind
    return result


class ServiceOverrideTests(unittest.TestCase):
    def setUp(self):
        self.base = {"revision": 1, "domain_policy": "exact-and-suffix", "excluded_zones": [],
            "excluded_domains": {}, "services": [
                service("chatgpt", suffixes=["chatgpt.com", "openai.com"]),
                service("claude", suffixes=["claude.ai"])]}
        self.artifacts = prepare(self.base, None, fetch=fixture(
            geoblock="chatgpt.com\nclaude.ai\nopenai.com\nvideo.example\n",
            google_ai="gemini.google.com\n").__getitem__)
        self.catalog = self.artifacts["rules/pilot.json"]
        self.registry = self.artifacts["rules/registry.json"]
        self.settings = {"own_zones": ["operator.example.net"], "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32], "origin_dns": ["9.9.9.9"],
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "admin_username": "labadmin", "admin_password_hash": LAB_PASSWORD_HASH}

    def compile(self, catalog=None):
        return compile_config(catalog_rules(catalog or self.catalog, self.registry), self.settings)

    def assert_suffix_positive(self, artifacts, root, present=True):
        dns = artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"]
        self.assertEqual(f"||{root}^$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10" in dns, present)
        self.assertEqual(f"  acl policy_allowed req.ssl_sni,lower -m end .{root}" in artifacts["haproxy.cfg"], present)
        labels = artifacts["compose.lab.json"]["services"]["relay"]["labels"]
        allow = labels.get("traefik.tcp.routers.sd-relay.rule", "").split(" && !(", 1)[0]
        self.assertEqual(f"HostSNI(`{root}`)" in allow, present)

    def test_service_off_overrides_geo_without_withdrawing_claude_or_gemini_then_reenables(self):
        groups = [s for s in self.catalog["services"] if "upstream" in s]
        self.assertEqual({s["id"]: s.get("kind") for s in groups}, {"geoblock": "group", "google-ai": "group"})
        chatgpt = self.catalog["services"][0]
        chatgpt["enabled"] = False
        before = copy.deepcopy((self.catalog, self.registry))
        output = self.compile()
        for root in ("chatgpt.com", "openai.com"):
            self.assert_suffix_positive(output, root, False)
        for root in ("claude.ai", "gemini.google.com", "video.example"):
            self.assert_suffix_positive(output, root)
        self.assertEqual((self.catalog, self.registry), before)
        chatgpt["enabled"] = True
        restored = self.compile()
        for root in ("chatgpt.com", "openai.com", "claude.ai", "gemini.google.com"):
            self.assert_suffix_positive(restored, root)

    def test_group_off_withdraws_only_bulk_grant_and_keeps_baseline(self):
        for item in self.catalog["services"]:
            if "upstream" in item:
                item["enabled"] = False
        output = self.compile()
        for root in ("chatgpt.com", "openai.com", "claude.ai"):
            self.assert_suffix_positive(output, root)
        for root in ("video.example", "gemini.google.com"):
            self.assert_suffix_positive(output, root, False)

    def test_exact_service_off_inside_bulk_suffix_uses_native_exception(self):
        catalog = {**self.base, "services": [
            service("off", enabled=False, domains=["chat.shared.example"]),
            service("bulk", suffixes=["shared.example"], kind="group")]}
        output = compile_config(approved_rules(catalog), self.settings)
        self.assert_suffix_positive(output, "shared.example")
        self.assertIn("@@|chat.shared.example|$dnsrewrite", output["agh-conf/AdGuardHome.yaml"]["user_rules"])
        self.assertIn("acl policy_excluded req.ssl_sni,lower -m str chat.shared.example", output["haproxy.cfg"])
        edge = output["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertIn("HostSNI(`chat.shared.example`)", edge.split(" && !(", 1)[1])

    def test_shared_exact_and_suffix_dependencies_remain_routed_and_explained(self):
        cases = [
            (service("off", enabled=False, domains=["assets.example"]), service("on", domains=["assets.example"]),
             {"domains": ["assets.example"], "domain_suffixes": []}),
            (service("off", enabled=False, domains=["assets.shared.example"]), service("on", suffixes=["shared.example"]),
             {"domains": ["assets.shared.example"], "domain_suffixes": []}),
            (service("off", enabled=False, suffixes=["shared.example"]), service("on", domains=["api.shared.example"]),
             {"domains": [], "domain_suffixes": ["shared.example"]}),
            (service("off", enabled=False, suffixes=["shared.example"]), service("on", suffixes=["api.shared.example"]),
             {"domains": [], "domain_suffixes": ["shared.example"]}),
        ]
        for off, on, expected in cases:
            with self.subTest(off=off, on=on):
                catalog = {**self.base, "services": [off, on,
                    service("bulk", suffixes=["shared.example"], kind="group")]}
                before = copy.deepcopy(catalog)
                rules = approved_rules(catalog)
                self.assertEqual(rules["service_states"][0]["shared_routing"], expected)
                self.assertEqual(rules["excluded_domains"], {})
                self.assertEqual(rules["excluded_zones"], [])
                output = compile_config(rules, self.settings)
                self.assert_suffix_positive(output, "shared.example")
                if on["domains"] == ["assets.example"]:
                    self.assertIn("|assets.example|$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10",
                                  output["agh-conf/AdGuardHome.yaml"]["user_rules"])
                self.assertFalse(any(rule.startswith("@@") for rule in output["agh-conf/AdGuardHome.yaml"]["user_rules"]))
                self.assertNotIn("acl policy_excluded", output["haproxy.cfg"])
                self.assertEqual(catalog, before)

    def test_global_zone_removes_root_and_descendants_but_narrow_exception_keeps_parent(self):
        raw = {"domains": ["blocked.example", "child.blocked.example", "keep.example"],
               "domain_suffixes": ["blocked.example", "child.blocked.example", "wide.example"],
               "excluded_zones": ["blocked.example", "private.wide.example"]}
        output = compile_config(raw, self.settings)
        self.assertEqual(output["snapshot.json"]["wire_scope"],
                         {"domains": ["keep.example"], "domain_suffixes": ["wide.example"]})
        self.assert_suffix_positive(output, "blocked.example", False)
        self.assert_suffix_positive(output, "child.blocked.example", False)
        self.assert_suffix_positive(output, "wide.example")
        self.assertIn("@@||private.wide.example^$dnsrewrite", output["agh-conf/AdGuardHome.yaml"]["user_rules"])
        self.assertIn("acl policy_excluded req.ssl_sni,lower -m end .private.wide.example", output["haproxy.cfg"])
        edge = output["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertIn("HostSNI(`private.wide.example`)", edge.split(" && !(", 1)[1])

    def test_invalid_kind_rejected_without_mutating_catalog(self):
        for kind in (None, "", "bulk", True, 1, []):
            catalog = copy.deepcopy(self.base)
            catalog["services"][0]["kind"] = kind
            before = copy.deepcopy(catalog)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                approved_rules(catalog)
            self.assertEqual(catalog, before)

    def test_exclusion_does_not_bypass_raw_budget_or_fixed_origin_validation(self):
        raw = {"domains": ["blocked.example", "keep.example"], "excluded_zones": ["blocked.example"]}
        with self.assertRaisesRegex(ValueError, "pattern budget"):
            compile_config(raw, {**self.settings, "max_policy_entries": 1})
        fixed = dict(self.settings)
        fixed.pop("origin_dns")
        for unsafe in ("127.0.0.1", "10.0.0.1", "192.0.2.10", "168.63.129.16"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                compile_config(raw, fixed, {"blocked.example": unsafe, "keep.example": "1.1.1.1"})
        with self.assertRaisesRegex(ValueError, "exactly cover"):
            compile_config(raw, fixed, {"keep.example": "1.1.1.1"})
        output = compile_config(raw, fixed, {"blocked.example": "8.8.8.8", "keep.example": "1.1.1.1"})
        self.assertNotIn("8.8.8.8:443", output["haproxy.cfg"])
        self.assertIn("1.1.1.1:443", output["haproxy.cfg"])


if __name__ == "__main__":
    unittest.main()
