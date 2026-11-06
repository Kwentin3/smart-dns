"""Typed native policy contracts; runtime suffix behavior needs native probes."""
import copy
import re
import unittest

from tools.render import approved_rules, compile_config


class SuffixPolicyTests(unittest.TestCase):
    def test_large_policy_keeps_every_haproxy_directive_below_native_word_limit(self):
        domains = ["host%04d.fixture.org" % index for index in range(2048)]
        rules = {"domains": domains, "excluded_zones": []}
        for dynamic in (False, True):
            settings = dict(self.settings)
            if not dynamic:
                settings.pop("origin_dns")
            artifacts = compile_config(rules, settings, None if dynamic else {name: "1.1.1.1" for name in domains})
            directives = [line for line in artifacts["haproxy.cfg"].splitlines() if not line.startswith("#")]
            self.assertLessEqual(max(len(line.split()) for line in directives), 64)
            self.assertEqual(sum(line.startswith("  acl policy_allowed ") for line in directives), len(domains))

    def setUp(self):
        self.catalog = {
            "revision": 3, "domain_policy": "exact-and-suffix",
            "excluded_zones": ["local", "private.example.com"],
            "excluded_domains": {"skip.example.com": "Keep this exact name direct",
                                 "child.disabled.example.org": "Keep direct if its service is enabled later"},
            "services": [
                {"id": "selected", "name": "Selected", "enabled": True, "reason": "Reviewed local approval",
                 "domains": ["only.example.net"], "domain_suffixes": ["example.com"]},
                {"id": "disabled", "name": "Disabled", "enabled": False, "reason": "Not enabled for this pilot",
                 "domains": [], "domain_suffixes": ["disabled.example.org"]},
            ],
        }
        self.settings = {
            "own_zones": ["ops.example.com"], "doh_host": "dns.ops.example.com",
            "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32],
            "admin_username": "labadmin",
            "admin_password_hash": "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56",
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "origin_dns": ["9.9.9.9"],
        }

    def compile(self, catalog=None, settings=None):
        return compile_config(approved_rules(catalog or self.catalog), settings or self.settings)

    @staticmethod
    def edge_rule(artifacts):
        return artifacts["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]

    def test_exact_suffix_and_global_exception_use_distinct_native_patterns(self):
        artifacts = self.compile()
        dns = artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"]
        self.assertEqual(set(dns), {
            "|only.example.net|$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10",
            "|only.example.net|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;",
            "||example.com^$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10",
            "||example.com^$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;",
            "@@|skip.example.com|$dnsrewrite",
            "@@||private.example.com^$dnsrewrite",
            "@@||ops.example.com^$dnsrewrite",
            "@@||dns.ops.example.com^$dnsrewrite",
        })
        hap = artifacts["haproxy.cfg"]
        self.assertIn("req.ssl_sni,lower -m str only.example.net", hap)
        self.assertIn("req.ssl_sni,lower -m str example.com", hap)
        self.assertIn("req.ssl_sni,lower -m end .example.com", hap)
        self.assertNotIn("-m end example.com", hap)
        self.assertIn("acl policy_excluded req.ssl_sni,lower -m str skip.example.com", hap)
        allow, deny = self.edge_rule(artifacts).split(" && !(", 1)
        self.assertIn("HostSNI(`only.example.net`)", allow)
        self.assertIn("HostSNI(`example.com`)", allow)
        self.assertIn("HostSNI(`skip.example.com`)", deny)
        # Execute the emitted restricted regular-expression atom, not a mock
        # Traefik matcher or a replacement routing implementation.
        patterns = re.findall(r"HostSNIRegexp\(`([^`]+)`\)", allow)
        self.assertEqual(len(patterns), 1)
        descendant = re.compile(patterns[0].replace("$$", "$"))
        for name in ("a.example.com", "deep.a.example.com"):
            self.assertIsNotNone(descendant.fullmatch(name), name)
        for name in ("example.com", "badexample.com", "example.com.evil.test"):
            self.assertIsNone(descendant.fullmatch(name), name)
        self.assertNotIn("HostSNI(`*`)", self.edge_rule(artifacts))

    def test_minimal_positive_union_prevents_overlap_without_erasing_desired_types(self):
        catalog = copy.deepcopy(self.catalog)
        selected = catalog["services"][0]
        selected["domains"] = ["a.example.com", "example.com", "only.example.net"]
        selected["domain_suffixes"] = ["a.example.com", "deep.a.example.com", "example.com"]
        selected["upstream_state"] = {"status": "approved", "reason": "Preserve provenance"}
        before = copy.deepcopy(catalog)
        artifacts = self.compile(catalog)
        snapshot = artifacts["snapshot.json"]
        self.assertEqual(snapshot["domains"], selected["domains"])
        self.assertEqual(snapshot["domain_suffixes"], selected["domain_suffixes"])
        self.assertEqual(snapshot["wire_scope"], {"domains": ["only.example.net"], "domain_suffixes": ["example.com"]})
        self.assertEqual(snapshot["desired_services"][0]["upstream_state"], selected["upstream_state"])
        positives = [line for line in artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"] if not line.startswith("@@")]
        self.assertEqual(len(positives), 4)
        self.assertEqual(sum("dnstype=A," in line for line in positives), 2)
        self.assertFalse(any(line.startswith("|example.com|") or line.startswith("|a.example.com|") or
                             line.startswith("||a.example.com^") for line in positives))
        hap = artifacts["haproxy.cfg"]
        self.assertNotIn("-m str a.example.com\n", hap)
        self.assertNotIn("-m end .a.example.com\n", hap)
        self.assertNotIn("HostSNI(`a.example.com`)", self.edge_rule(artifacts))
        self.assertEqual(catalog, before)

    def test_optional_empty_suffix_field_preserves_exact_wire_configuration(self):
        rules = {"domains": ["a.example.net", "b.example.net"], "excluded_zones": ["local"]}
        settings = dict(self.settings)
        settings.pop("origin_dns")
        origins = {"a.example.net": "1.1.1.1", "b.example.net": "8.8.8.8"}
        legacy = compile_config(rules, settings, origins)
        explicit_empty = compile_config({**rules, "domain_suffixes": []}, settings, origins)
        for name in ("agh-conf/AdGuardHome.yaml", "compose.lab.json"):
            self.assertEqual(legacy[name], explicit_empty[name])
        # Typed desired-input identity changes the receipt comment, not native HA.
        self.assertEqual(legacy["haproxy.cfg"].split("\n", 1)[1], explicit_empty["haproxy.cfg"].split("\n", 1)[1])
        self.assertNotIn("wire_scope", legacy["snapshot.json"])
        self.assertFalse(any(line.startswith("@@") for line in legacy["agh-conf/AdGuardHome.yaml"]["user_rules"]))
        self.assertNotIn("HostSNIRegexp", self.edge_rule(legacy))

    def test_suffix_requires_dynamic_resolution_of_actual_requested_hostname(self):
        rules = approved_rules(self.catalog)
        fixed = dict(self.settings)
        fixed.pop("origin_dns")
        with self.assertRaisesRegex(ValueError, "suffix routing requires"):
            compile_config(rules, fixed, {name: "1.1.1.1" for name in rules["domains"]})
        hap = self.compile()["haproxy.cfg"]
        self.assertIn("do-resolve(sess.ip,origin_dns,ipv4) var(sess.host)", hap)
        self.assertIn("set-dst var(sess.ip)", hap)
        self.assertNotRegex(hap, r"(?m)^  server fixed ")

    def test_own_https_exclusions_apply_before_forwarding_and_do_not_consume_http(self):
        artifacts = self.compile()
        snapshot = artifacts["snapshot.json"]
        self.assertEqual(snapshot["policy_exclusions"]["domain_suffixes"],
                         ["dns.ops.example.com", "ops.example.com", "private.example.com"])
        hap = artifacts["haproxy.cfg"]
        self.assertLess(hap.index("policy_excluded\n"), hap.index("do-resolve("))
        self.assertLess(hap.index("policy_excluded\n"), hap.index(" } !policy_allowed"))
        allow, deny = self.edge_rule(artifacts).split(" && !(", 1)
        self.assertNotIn("HostSNI(`dns.ops.example.com`)", allow)
        self.assertIn("HostSNI(`dns.ops.example.com`)", deny)
        self.assertIn("HostSNI(`ops.example.com`)", deny)
        for blocked in ("ops.example.com", "child.ops.example.com", "private.example.com"):
            with self.subTest(blocked=blocked):
                rules = {"domains": [], "domain_suffixes": [blocked], "excluded_zones": ["private.example.com"]}
                with self.assertRaisesRegex(ValueError, "excluded or own domain"):
                    compile_config(rules, self.settings)

    def test_typed_validation_reasons_disabled_scope_and_explicit_raw_budget(self):
        projected = approved_rules(self.catalog)
        self.assertEqual(projected["domain_suffixes"], ["example.com"])
        self.assertIn("child.disabled.example.org", projected["excluded_domains"])
        invalid = []
        for root in ("*.example.com", ".example.com", "^.*$", "Example.com"):
            catalog = copy.deepcopy(self.catalog)
            catalog["services"][0]["domain_suffixes"] = [root]
            invalid.append(catalog)
        missing_reason = copy.deepcopy(self.catalog)
        missing_reason["excluded_domains"]["skip.example.com"] = ""
        invalid.append(missing_reason)
        outside = copy.deepcopy(self.catalog)
        outside["excluded_domains"]["outside.example.org"] = "Not approved by any declared pattern"
        invalid.append(outside)
        for catalog in invalid:
            with self.subTest(catalog=catalog):
                with self.assertRaises(ValueError):
                    approved_rules(catalog)
        names = [f"host{i:04d}.example.net" for i in range(21)]
        rules = {"domains": names, "excluded_zones": []}
        self.assertEqual(compile_config(rules, self.settings)["snapshot.json"]["domains"], names)
        with self.assertRaisesRegex(ValueError, "pattern budget"):
            compile_config(rules, {**self.settings, "max_policy_entries": 20})
        with self.assertRaisesRegex(ValueError, "pattern budget"):
            compile_config({"domains": [f"host{i:04d}.example.net" for i in range(2049)], "excluded_zones": []}, self.settings)
        with self.assertRaisesRegex(ValueError, "pattern budget"):
            compile_config({"domains": ["a.example.com"], "domain_suffixes": ["example.com"], "excluded_zones": []},
                           {**self.settings, "max_policy_entries": 1})


if __name__ == "__main__":
    unittest.main()
