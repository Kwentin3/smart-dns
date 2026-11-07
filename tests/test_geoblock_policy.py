"""Private GEO policy contracts; synthetic Git transport, real policy owners."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_geoblock_registry import fixture, RAW, PIN
from test_source_proposals import upstream, OLD
from tools.bootstrap_geoblock import prepare
from tools.catalog import main as catalog_main, project_catalog
from tools.registry import FANCY_SOURCE_ID, GEO_SOURCE_ID, fetch_snapshot
from tools.render import catalog_rules, compile_config, hostname
from tools.source_proposals import produce


class GeoBlockPolicyTests(unittest.TestCase):
    def setUp(self):
        self.base_registry = fetch_snapshot(["openai"], fetch=upstream(OLD).__getitem__)
        self.base = {"revision": 1, "domain_policy": "exact", "excluded_zones": ["local"],
            "excluded_domains": {"auth.openai.com": "Local exclusion remains authoritative"},
            "services": [{"id": "baseline", "name": "Baseline", "enabled": True,
                "reason": "Previously approved", "domains": ["manual.example"],
                "upstream": {"source": "metacubex-sing", "list": "openai",
                    "approved_scope": {"exact": ["auth.openai.com"], "suffix": ["openai.com"]}}}]}
        self.original_inputs = copy.deepcopy((self.base, self.base_registry))
        self.artifacts = prepare(self.base, self.base_registry, fetch=fixture().__getitem__)
        self.catalog = self.artifacts["rules/pilot.json"]
        self.registry = self.artifacts["rules/registry.json"]

    def test_bootstrap_freezes_projected_baseline_and_compiles_complete_private_groups(self):
        frozen = self.catalog["services"][0]
        self.assertNotIn("upstream", frozen)
        self.assertNotIn("upstream_state", frozen)
        self.assertEqual(frozen["domains"], ["auth.openai.com", "manual.example"])
        self.assertEqual(frozen["domain_suffixes"], ["openai.com"])
        projected = project_catalog(self.catalog, self.registry, hostname)
        for name in ("geoblock", "google-ai"):
            service = next(s for s in projected["services"] if s["id"] == name)
            self.assertTrue(service["enabled"])
            self.assertEqual(service["upstream"]["source"], GEO_SOURCE_ID)
            self.assertEqual(service["domain_suffixes"], self.registry["definitions"][name]["suffix"])
            self.assertEqual(service["upstream_state"]["pending_scope"], [])
        rules = catalog_rules(self.catalog, self.registry)
        settings = {"own_zones": ["operator.example.net"], "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32], "origin_dns": ["9.9.9.9"],
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "admin_username": "labadmin",
            "admin_password_hash": "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56"}
        output = compile_config(rules, settings)
        dns = output["agh-conf/AdGuardHome.yaml"]
        self.assertIn("@@|auth.openai.com|$dnsrewrite", dns["user_rules"])
        self.assertIn("acl policy_excluded req.ssl_sni,lower -m str auth.openai.com", output["haproxy.cfg"])
        edge_rule = output["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertIn("!(HostSNI(`auth.openai.com`))", edge_rule)
        self.assertNotIn("auth.openai.com", rules["domains"])
        self.assertIn("manual.example", rules["domains"])
        for root in ("media.example", "assistant.example", "openai.com"):
            self.assertIn(f"||{root}^$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10", dns["user_rules"])
            self.assertIn(f"-m end .{root}", output["haproxy.cfg"])
        self.assertEqual(dns["dns"]["allowed_clients"], settings["client_ids"])
        self.assertEqual((self.base, self.base_registry), self.original_inputs)

    def test_foreign_repository_and_missing_private_marker_fail_projection(self):
        for source in ({"repository": self.base_registry["source"]["repository"]}, {"private_only": False}):
            snapshot = copy.deepcopy(self.registry)
            snapshot["source"].update(source)
            with self.subTest(source=source), self.assertRaises(ValueError):
                catalog_rules(self.catalog, snapshot)

    def test_fancy_candidate_preserves_existing_geo_baseline_and_native_match_types(self):
        from test_fancy_registry import fancy_fixture
        artifacts = prepare(self.catalog, self.registry, fetch=fancy_fixture().__getitem__, source_id=FANCY_SOURCE_ID)
        catalog, registry = artifacts["rules/pilot.json"], artifacts["rules/registry.json"]
        rules = catalog_rules(catalog, registry)
        for old in self.catalog["services"]:
            kept = next(service for service in catalog["services"] if service["id"] == old["id"])
            self.assertEqual(kept["enabled"], old["enabled"])
            if "upstream" in old:
                self.assertNotIn("upstream", kept)
                self.assertIn(self.registry["source"]["commit"], kept["source_path"])
        self.assertEqual(catalog["excluded_domains"], self.catalog["excluded_domains"])
        self.assertTrue(set(catalog_rules(self.catalog, self.registry)["domain_suffixes"]) <= set(rules["domain_suffixes"]))
        new = next(service for service in rules["service_states"] if service["id"] == "community-geo")
        self.assertEqual(new["domains"], registry["definitions"]["community-geo"]["exact"])
        self.assertEqual(new["domain_suffixes"], registry["definitions"]["community-geo"]["suffix"])
        self.assertEqual(new["upstream"]["source"], FANCY_SOURCE_ID)
        self.assertEqual(new["upstream_state"]["pending_scope"], [])

    def test_fancy_source_proposal_is_private_and_keeps_native_types(self):
        from test_fancy_registry import fancy_fixture
        from tools.source_proposals import proposal
        artifacts = prepare(self.catalog, self.registry, fetch=fancy_fixture().__getitem__, source_id=FANCY_SOURCE_ID)
        before = copy.deepcopy(artifacts)
        result = proposal(artifacts["rules/sources.json"], artifacts["rules/registry.json"],
                          artifacts["rules/pilot.json"], fetch=fancy_fixture().__getitem__)
        self.assertFalse(result["changed"])
        self.assertFalse(result["review_required"])
        self.assertEqual(result["selected_lists"], ["community-geo"])
        self.assertTrue(result["source"]["private_only"])
        self.assertEqual(artifacts, before)

    def test_upstream_new_root_is_pending_while_approved_descendant_can_update(self):
        new = fetch_snapshot(["geoblock", "google-ai"], self.registry,
            fetch=fixture(geoblock="media.example\nnew.media.example\nunapproved.example\n").__getitem__)
        projected = project_catalog(self.catalog, new, hostname)
        service = next(s for s in projected["services"] if s["id"] == "geoblock")
        self.assertIn("new.media.example", service["domain_suffixes"])
        self.assertNotIn("unapproved.example", service["domain_suffixes"])
        self.assertEqual(service["upstream_state"]["pending_scope"], [{"kind": "suffix", "name": "unapproved.example"}])
        self.assertNotIn("unapproved.example", catalog_rules(self.catalog, new)["domain_suffixes"])

    def write_inputs(self, root):
        for name, data in self.artifacts.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
        return root / "rules/sources.json", root / "rules/registry.json", root / "rules/pilot.json"

    def test_private_late_failure_keeps_accepted_files_and_latest_complete_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, catalog = self.write_inputs(root)
            before = {p: p.read_bytes() for p in (sources, registry, catalog)}
            output = root / ".local/source-proposals/latest.json"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"previous complete private proposal")
            replies, calls = fixture(geoblock="changed.example\n", google_ai="changed-ai.example\n"), []
            def fetch(url):
                calls.append(url)
                if url == RAW + "/" + PIN + "/Services/google_ai.lst":
                    raise OSError("transport failed late")
                return replies[url]
            with self.assertRaises(ValueError):
                produce(sources, output, fetch=fetch, registry_path=registry, catalog_path=catalog)
            self.assertIn(RAW + "/" + PIN + "/Categories/geoblock.lst", calls)
            self.assertEqual(output.read_bytes(), b"previous complete private proposal")
            self.assertEqual(list(output.parent.iterdir()), [output])
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)

    def test_public_geo_artifact_is_refused_before_fetch_or_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, catalog = self.write_inputs(root)
            before = {p: p.read_bytes() for p in (sources, registry, catalog)}
            calls = []
            def fetch(url):
                calls.append(url)
                raise OSError("must not fetch")
            output = root / ".local/source-proposals/latest.json"
            with self.assertRaisesRegex(ValueError, "private GEO"):
                produce(sources, output, fetch=fetch, registry_path=registry, catalog_path=catalog, public_artifact=True)
            self.assertEqual(calls, [])
            self.assertFalse(output.parent.exists())
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)

    def test_native_catalog_cli_infers_geo_source_from_private_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, registry, policy = self.write_inputs(root)
            empty = {**self.base, "excluded_domains": {}, "services": []}
            policy.write_text(json.dumps(empty), encoding="utf-8")
            before = registry.read_bytes()
            args = ["catalog", "enable", "google-ai", "--rules", str(policy), "--registry", str(registry),
                    "--reason", "Explicit private GEO selection"]
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                catalog_main()
            saved = json.loads(policy.read_text(encoding="utf-8"))
            service = saved["services"][0]
            self.assertEqual(service["upstream"]["source"], GEO_SOURCE_ID)
            self.assertEqual(service["upstream"]["approved_scope"]["suffix"], self.registry["definitions"]["google-ai"]["suffix"])
            self.assertEqual(registry.read_bytes(), before)
            self.assertEqual(project_catalog(saved, self.registry, hostname)["services"][0]["upstream_state"]["status"], "current")


if __name__ == "__main__":
    unittest.main()
