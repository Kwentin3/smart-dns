"""Local source bounds remain distinct from discovered upstream membership."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.catalog import configure, project_catalog
from tools.registry import REPOSITORY, normalize_rules
from tools.render import approved_rules, hostname


class CatalogSourceTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "revision": 3, "domain_policy": "exact", "excluded_zones": ["google.com", "local"],
            "excluded_domains": {"auth0.openai.com": "Explicit local exclusion"},
            "services": [{"id": "chatgpt", "name": "ChatGPT", "enabled": True, "reason": "Manual baseline",
                          "domains": ["auth.openai.com", "auth0.openai.com", "chat.openai.com", "chatgpt.com"]},
                         {"id": "claude", "name": "Claude", "enabled": True, "reason": "Manual baseline", "domains": ["claude.ai"]}],
        }

    def snapshot(self, rules, list_id="spotify"):
        definition = normalize_rules({"version": 2, "rules": rules})
        definition["source_blob"] = "b" * 40
        return {"schema_version": 1, "source": {"repository": REPOSITORY, "commit": "a" * 40},
                "index": {list_id: {"blob_sha": "b" * 40, "path": "geo/geosite/" + list_id + ".json", "kind": "service-candidate"}},
                "definitions": {list_id: definition}}

    def attach(self, catalog, list_id="spotify", exact=None, suffix=None, partial=False):
        service = {"id": "spotify", "name": "Spotify", "enabled": True, "reason": "Explicit local approval", "domains": [],
                   "upstream": {"source": "metacubex-sing", "list": list_id,
                                "approved_scope": {"exact": exact or [], "suffix": suffix or []}}}
        if partial:
            service["upstream"]["accept_partial"] = True
        catalog["services"].append(service)
        return service

    def test_empty_source_scopes_preserve_manual_baseline_and_expose_pending_coverage(self):
        snapshot = self.snapshot([{"domain_suffix": ["openai.com"], "domain_regex": "^unsupported$"}], "openai")
        self.catalog["services"][0]["upstream"] = {"source": "metacubex-sing", "list": "openai", "approved_scope": {"exact": [], "suffix": []}}
        original = copy.deepcopy((self.catalog, snapshot))
        projected = project_catalog(self.catalog, snapshot, hostname)
        self.assertEqual(approved_rules(projected)["domains"], ["auth.openai.com", "chat.openai.com", "chatgpt.com", "claude.ai"])
        state = projected["services"][0]["upstream_state"]
        self.assertTrue(state["partial"])
        self.assertTrue(state["unsupported"])
        self.assertEqual(state["pending_scope"], [{"kind": "suffix", "name": "openai.com"}])
        self.assertEqual((self.catalog, snapshot), original)

    def test_exact_approval_never_authorizes_same_name_as_suffix(self):
        snapshot = self.snapshot([{"domain": ["login.spotify.com", "spotify.com"], "domain_suffix": ["spotify.com"]}])
        self.attach(self.catalog, exact=["spotify.com"])
        projected = project_catalog(self.catalog, snapshot, hostname)
        service = projected["services"][-1]
        self.assertEqual(service["domains"], ["spotify.com"])
        self.assertEqual(service.get("domain_suffixes", []), [])
        self.assertIn({"kind": "suffix", "name": "spotify.com"}, service["upstream_state"]["pending_scope"])
        self.assertNotIn("login.spotify.com", approved_rules(projected)["domains"])

    def test_suffix_approval_is_label_bounded_and_new_roots_stay_pending(self):
        snapshot = self.snapshot([{"domain": ["evilspotify.com", "login.spotify.com"],
                                   "domain_suffix": ["assets.spotify.com", "evilspotify.com", "spotify.com"]}])
        self.attach(self.catalog, suffix=["spotify.com"])
        projected = project_catalog(self.catalog, snapshot, hostname)
        service = projected["services"][-1]
        self.assertEqual(service["domains"], ["login.spotify.com"])
        self.assertEqual(service["domain_suffixes"], ["assets.spotify.com", "spotify.com"])
        self.assertEqual({item["name"] for item in service["upstream_state"]["pending_scope"]}, {"evilspotify.com"})
        self.assertEqual(approved_rules(projected)["domain_suffixes"], ["assets.spotify.com", "spotify.com"])

    def test_enable_ready_service_explicitly_accepts_current_scope_without_losing_local_preferences(self):
        snapshot = self.snapshot([{"domain": "audio.spotifycdn.com", "domain_suffix": ["scdn.co", "spotify.com"]}])
        configured = configure(self.catalog, snapshot, "spotify", True, "Enable reviewed Spotify")
        self.assertEqual(configured["services"][:2], self.catalog["services"])
        self.assertEqual(configured["excluded_domains"], self.catalog["excluded_domains"])
        self.assertEqual(configured["excluded_zones"], self.catalog["excluded_zones"])
        self.assertEqual(configured["services"][-1]["upstream"]["approved_scope"],
                         {"exact": ["audio.spotifycdn.com"], "suffix": ["scdn.co", "spotify.com"]})
        self.assertEqual(approved_rules(project_catalog(configured, snapshot, hostname))["domain_suffixes"], ["scdn.co", "spotify.com"])
        disabled = configure(configured, snapshot, "spotify", False, "User disabled Spotify")
        self.assertIs(disabled["services"][-1]["enabled"], False)
        self.assertEqual(approved_rules(project_catalog(disabled, snapshot, hostname))["domain_suffixes"], [])

    def test_partial_source_requires_literal_only_consent_and_keeps_unsupported_visible(self):
        snapshot = self.snapshot([{"domain_suffix": ["spotify.com"], "domain_regex": "^audio.*$"}])
        with self.assertRaises(ValueError):
            configure(self.catalog, snapshot, "spotify", True, "Enable without hiding omissions")
        configured = configure(self.catalog, snapshot, "spotify", True, "Explicit partial coverage", accept_partial=True)
        projected = project_catalog(configured, snapshot, hostname)
        self.assertEqual(approved_rules(projected)["domain_suffixes"], ["spotify.com"])
        self.assertEqual(projected["services"][-1]["upstream_state"]["unsupported"], snapshot["definitions"]["spotify"]["unsupported"])
        self.assertEqual(projected["services"][-1]["upstream_state"]["status"], "review-required")

    def test_disabling_newly_partial_source_does_not_require_new_import_consent(self):
        snapshot = self.snapshot([{"domain_suffix": ["spotify.com"], "domain_regex": "^new-upstream-rule$"}])
        self.attach(self.catalog, suffix=["spotify.com"])
        disabled = configure(self.catalog, snapshot, "spotify", False, "Disable source while reviewing new unsupported rule")
        projected = project_catalog(disabled, snapshot, hostname)
        self.assertEqual(approved_rules(projected)["domain_suffixes"], [])
        self.assertTrue(projected["services"][-1]["upstream_state"]["partial"])

    def test_foreign_source_misbound_blob_and_invalid_approval_are_rejected(self):
        snapshot = self.snapshot([{"domain_suffix": ["spotify.com"]}])
        self.attach(self.catalog, suffix=["spotify.com"])
        foreign = copy.deepcopy(snapshot)
        foreign["source"]["repository"] = "https://github.com/other/source"
        with self.assertRaises(ValueError):
            project_catalog(self.catalog, foreign, hostname)
        misbound = copy.deepcopy(snapshot)
        misbound["definitions"]["spotify"]["source_blob"] = "c" * 40
        with self.assertRaises(ValueError):
            project_catalog(self.catalog, misbound, hostname)
        invalid = copy.deepcopy(self.catalog)
        invalid["services"][-1]["upstream"]["approved_scope"]["suffix"] = ["*.spotify.com"]
        with self.assertRaises(ValueError):
            project_catalog(invalid, snapshot, hostname)

    def test_direct_script_list_reads_wide_index_without_network_or_writes(self):
        snapshot = self.snapshot([{"domain_suffix": ["spotify.com"]}])
        snapshot["index"]["netflix"] = {"kind": "service-candidate", "path": "geo/geosite/netflix.json"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules_path, registry_path = root / "rules.json", root / "registry.json"
            rules_path.write_text(json.dumps(self.catalog), encoding="utf-8")
            registry_path.write_text(json.dumps(snapshot), encoding="utf-8")
            before = (rules_path.read_bytes(), registry_path.read_bytes())
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "tools/catalog.py"), "list", "--rules", str(rules_path), "--registry", str(registry_path)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("spotify\tOFF", result.stdout)
            self.assertIn("netflix\tOFF", result.stdout)
            self.assertEqual((rules_path.read_bytes(), registry_path.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
