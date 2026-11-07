"""The native lab binds real compiler inputs; it cannot bless a changed baseline."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_fancy_registry import fancy_fixture
from test_geoblock_registry import fixture
from tools.bootstrap_geoblock import prepare as bootstrap
from tools.native_lab.prepare import enforcement_scope, prepare
from tools.registry import FANCY_SOURCE_ID
from tools.render import catalog_rules
from tools.source_proposals import checksum


class NativeLabPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        base = {"revision": 1, "domain_policy": "exact", "excluded_domains": {}, "excluded_zones": ["local"],
                "services": [{"id": "local", "name": "Local", "enabled": False, "reason": "Owner OFF",
                              "domains": ["local.example"]}]}
        self.baseline = bootstrap(base, {}, fetch=fixture().__getitem__)
        self.candidate = bootstrap(self.baseline["rules/pilot.json"], self.baseline["rules/registry.json"],
                                   fetch=fancy_fixture().__getitem__, source_id=FANCY_SOURCE_ID)
        self.save(self.baseline, "baseline")
        self.save(self.candidate, "candidate")

    def save(self, artifacts, folder):
        for name, value in artifacts.items():
            path = self.root / folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")

    def expected(self, artifacts=None):
        artifacts = artifacts or self.candidate
        return checksum(enforcement_scope(catalog_rules(artifacts["rules/pilot.json"], artifacts["rules/registry.json"])))

    def run_prepare(self, expected=None):
        return prepare(self.root / "evidence", self.root / "candidate/rules", self.root / "baseline/rules",
                       expected or self.expected())

    def test_full_generated_docker_labels_and_candidate_scope_remain_intact(self):
        before = {path: path.read_bytes() for path in self.root.rglob("*.json")}
        compose = self.run_prepare()
        self.assertIn("--providers.docker=true", compose["services"]["edge"]["command"])
        self.assertFalse(any("providers.file" in argument for argument in compose["services"]["edge"]["command"]))
        label = compose["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertIn("HostSNI", label)
        self.assertIn("$$", label)
        receipts = json.loads((self.root / "evidence/inputs.json").read_text())
        self.assertEqual(receipts["policy_sha256"], self.expected())
        self.assertEqual(receipts["native_label_bytes"], len(label.replace("$$", "$").encode()))
        self.assertEqual(receipts["max_policy_entries"], 4096)
        self.assertEqual(receipts["production"], "not-checked")
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_wrong_candidate_identity_fails_before_writing_native_artifacts(self):
        with self.assertRaisesRegex(ValueError, "frozen scope"):
            self.run_prepare("0" * 64)
        self.assertFalse((self.root / "evidence").exists())

    def test_recomputed_scope_hash_cannot_hide_changed_owner_off_state(self):
        changed = copy.deepcopy(self.candidate)
        changed["rules/pilot.json"]["services"][0]["enabled"] = True
        self.save(changed, "candidate")
        with self.assertRaisesRegex(ValueError, "baseline service"):
            self.run_prepare(self.expected(changed))
        self.assertFalse((self.root / "evidence").exists())

    def test_recomputed_scope_hash_cannot_hide_removed_owner_exclusion(self):
        changed = copy.deepcopy(self.candidate)
        changed["rules/pilot.json"]["excluded_zones"] = []
        self.save(changed, "candidate")
        with self.assertRaisesRegex(ValueError, "owner exclusions"):
            self.run_prepare(self.expected(changed))
        self.assertFalse((self.root / "evidence").exists())
