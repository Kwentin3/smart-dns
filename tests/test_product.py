"""Operator transactions over real compiled generations, with native IO injected."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_render import LAB_PASSWORD_HASH
from test_source_proposals import upstream, source, OLD, NEW, LICENSE
from tools import product
from tools.catalog import write_json
from tools.render import catalog_rules, compile_config
from tools.registry import fetch_snapshot
from tools.service_policy import PolicyError


class ProductTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.deployment = {"mode": "lab", "project": "smart-dns-product-test",
            "management_base": "http://127.0.0.1:13000", "releases": root / ".local/releases",
            "receipts": root / ".local/receipts", "dot_cert_dir": root / "certs",
            "admin_password_file": root / "password"}
        self.deployment["admin_password_file"].write_text("disposable-fixture-only", encoding="utf-8")
        inputs = {"settings": {"own_zones": ["operator.example.net"], "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32], "origin_dns": ["9.9.9.9"],
            "upstream_dns": ["https://dns.example.org/dns-query"], "bootstrap_dns": ["1.1.1.1"],
            "admin_username": "labadmin", "admin_password_hash": LAB_PASSWORD_HASH},
            "catalog": {"revision": 1, "domain_policy": "exact", "excluded_zones": [],
                "excluded_domains": {}, "services": [{"id": "manual", "name": "Manual baseline",
                    "enabled": True, "reason": "Accepted baseline", "domains": ["service.example"]}]},
            "registry": {"schema_version": 1, "index": {}, "definitions": {}},
            "sources": {"schema_version": 1, "sources": []}}
        for key, name in product.INPUT_NAMES.items():
            if key not in inputs:
                continue
            path = root / "canonical" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(inputs[key]), encoding="utf-8")
            self.deployment[key] = path
        self.initial = copy.deepcopy(inputs)
        self.original = self.canonical_bytes()
        self.actual = root / "accepted"
        product.prepare(self.deployment, inputs, self.actual)
        self.accepted = self.actual
        self.calls = []
        self.reads = 0

    def canonical_bytes(self):
        return {key: self.deployment[key].read_bytes() for key in product.INPUT_NAMES if key in self.deployment}

    def reader(self, settings, catalog, **kwargs):
        self.reads += 1
        desired = compile_config(catalog_rules(catalog, kwargs["registry"]), settings)["snapshot.json"]["sha256"]
        actual = json.loads((self.actual / "snapshot.json").read_text())["sha256"]
        return {"status": "matches" if desired == actual else "drift", "actual_directory": str(self.actual),
                "desired_generation": desired, "actual_generation": actual}

    def native(self, arguments, environment):
        self.calls.append((arguments, self.canonical_bytes()))
        self.actual = Path(arguments[arguments.index("--candidate") + 1])
        self.assertTrue((self.actual / "agh-conf/AdGuardHome.yaml").is_file())
        self.assertEqual(environment["DOT_CERT_DIR"], str(self.deployment["dot_cert_dir"]))
        return True

    def operate(self, command="off", **kwargs):
        return product.operate(self.deployment, command, status_reader=self.reader,
            native=kwargs.pop("native", self.native), **({"service_id": "manual", "reason": "Operator preference"}
                                                     if command in ("on", "off") else {}), **kwargs)

    def test_success_publishes_only_after_native_apply_and_matches_actual(self):
        result = self.operate()
        self.assertEqual(self.calls[0][1], self.original)
        self.assertEqual(result["status"], "matches")
        self.assertFalse(product.read_inputs(self.deployment)["catalog"]["services"][0]["enabled"])
        self.assertEqual(product.status(self.deployment, product.read_inputs(self.deployment), status_reader=self.reader)["status"], "matches")
        for key in ("settings", "registry", "sources"):
            self.assertEqual(self.deployment[key].read_bytes(), self.original[key])

    def test_native_failure_leaves_all_canonical_inputs_and_actual_unchanged(self):
        def fail(arguments, environment):
            self.assertEqual(self.canonical_bytes(), self.original)
            return False
        with self.assertRaises(PolicyError):
            self.operate(native=fail)
        self.assertEqual(self.canonical_bytes(), self.original)
        self.assertEqual(self.actual, self.accepted)

    def test_publication_failure_restores_native_generation_and_canonical(self):
        with patch("tools.product.write_json", side_effect=OSError("storage unavailable")), self.assertRaises(PolicyError):
            self.operate()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.canonical_bytes(), self.original)
        self.assertEqual(json.loads((self.actual / "snapshot.json").read_text())["sha256"],
                         json.loads((self.accepted / "snapshot.json").read_text())["sha256"])

    def test_failed_readback_restores_published_preferences_and_actual(self):
        normal_reader = self.reader
        def mismatched(*args, **kwargs):
            result = normal_reader(*args, **kwargs)
            if self.reads == 2:
                result["status"] = "drift"
            return result
        self.reader = mismatched
        with self.assertRaises(PolicyError):
            self.operate()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(product.read_inputs(self.deployment), self.initial)
        self.assertEqual(product.status(self.deployment, product.read_inputs(self.deployment), status_reader=self.reader)["status"], "matches")

    def test_external_edit_during_apply_is_preserved_while_native_restores(self):
        edited = copy.deepcopy(self.initial["catalog"])
        edited["services"][0]["reason"] = "Concurrent owner's edit"
        def concurrent(arguments, environment):
            result = self.native(arguments, environment)
            if len(self.calls) == 1:
                write_json(self.deployment["catalog"], edited)
            return result
        with self.assertRaisesRegex(PolicyError, "external edits preserved"):
            self.operate(native=concurrent)
        self.assertEqual(json.loads(self.deployment["catalog"].read_text()), edited)
        self.assertEqual(len(self.calls), 2)
        restored = json.loads((self.actual / "inputs/rules/pilot.json").read_text())
        self.assertEqual(restored, self.initial["catalog"])

    def test_external_edit_after_publication_is_not_overwritten_by_recovery(self):
        edited = copy.deepcopy(self.initial["catalog"])
        edited["services"][0]["reason"] = "Concurrent edit after publication"
        normal_reader = self.reader
        def concurrent_readback(*args, **kwargs):
            result = normal_reader(*args, **kwargs)
            if self.reads == 2:
                self.assertFalse(json.loads(self.deployment["catalog"].read_text())["services"][0]["enabled"])
                write_json(self.deployment["catalog"], edited)
                result["status"] = "drift"
            return result
        self.reader = concurrent_readback
        with self.assertRaisesRegex(PolicyError, "external edits preserved"):
            self.operate()
        self.assertEqual(json.loads(self.deployment["catalog"].read_text()), edited)
        self.assertEqual(json.loads((self.actual / "inputs/rules/pilot.json").read_text()), self.initial["catalog"])

    def test_external_edit_between_atomic_write_and_return_is_not_claimed_as_own(self):
        edited = copy.deepcopy(self.initial["catalog"])
        edited["services"][0]["reason"] = "External edit immediately after atomic replace"
        publications = []
        def raced_write(path, value):
            own_bytes = write_json(path, value)
            publications.append(path)
            if len(publications) == 1:
                self.assertIsInstance(own_bytes, bytes)
                write_json(path, edited)
            return own_bytes
        with patch("tools.product.write_json", side_effect=raced_write), self.assertRaises(PolicyError):
            self.operate()
        self.assertEqual(publications, [self.deployment["catalog"]])
        self.assertEqual(json.loads(self.deployment["catalog"].read_text()), edited)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(json.loads((self.actual / "inputs/rules/pilot.json").read_text()), self.initial["catalog"])

    def test_rollback_selects_archived_inputs_and_restore_uses_actual_not_drifted_desired(self):
        target = copy.deepcopy(self.initial)
        target["catalog"]["services"][0]["enabled"] = False
        self.deployment["releases"].mkdir(parents=True)
        product.prepare(self.deployment, target, self.deployment["releases"] / "previous")
        drift = copy.deepcopy(self.initial["catalog"])
        drift["services"][0]["domains"] = ["desired-only.example"]
        write_json(self.deployment["catalog"], drift)
        normal_reader = self.reader
        def fail_readback(*args, **kwargs):
            result = normal_reader(*args, **kwargs)
            if self.reads == 2:
                result["status"] = "drift"
            return result
        self.reader = fail_readback
        with self.assertRaises(PolicyError):
            self.operate("rollback", to="previous")
        self.assertEqual(len(self.calls), 2)
        first_candidate = Path(self.calls[0][0][self.calls[0][0].index("--candidate") + 1])
        self.assertEqual(json.loads((first_candidate / "inputs/rules/pilot.json").read_text()), target["catalog"])
        self.assertEqual(json.loads((self.actual / "inputs/rules/pilot.json").read_text()), self.initial["catalog"])
        self.assertEqual(json.loads(self.deployment["catalog"].read_text()), drift)

    def test_readonly_status_creates_no_archives_or_changes(self):
        root = self.deployment["catalog"].parents[2]
        before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
        self.assertEqual(product.status(self.deployment, product.read_inputs(self.deployment), status_reader=self.reader)["status"], "matches")
        self.assertEqual({p: p.read_bytes() for p in root.rglob("*") if p.is_file()}, before)
        self.assertFalse(self.deployment["releases"].exists())
        self.assertFalse(self.deployment["receipts"].exists())

    def test_invalid_scope_fails_before_native_or_archive_creation(self):
        for domain in ("*.bad.example", "operator.example.net", "1.1.1.1"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                self.operate("add", service_id="new", reason="Explicit addition", domains=[domain])
            self.assertEqual(self.calls, [])
            self.assertEqual(self.canonical_bytes(), self.original)
            self.assertFalse(self.deployment["releases"].exists())

    def refresh_fixture(self):
        self.initial["registry"] = fetch_snapshot(["openai"], fetch=upstream(OLD).__getitem__)
        self.initial["sources"] = source()
        self.initial["catalog"]["services"].append({"id": "openai", "name": "OpenAI", "enabled": True,
            "reason": "Previously approved source boundary", "domains": [], "upstream": {
                "source": "metacubex-sing", "list": "openai", "approved_scope": {
                    "exact": ["auth.openai.com"], "suffix": ["openai.com"]}}})
        for key, value in self.initial.items():
            self.deployment[key].write_text(json.dumps(value), encoding="utf-8")
        self.original = self.canonical_bytes()
        self.actual = self.accepted.parent / "refresh-accepted"
        product.prepare(self.deployment, self.initial, self.actual)
        self.accepted = self.actual
        return {"version": 2, "rules": [{"domain": ["auth.openai.com", "new.api.openai.com"],
                                         "domain_suffix": ["openai.com", "pending.example"]}]}

    def test_refresh_accepts_addition_after_native_and_keeps_new_root_pending(self):
        additive = self.refresh_fixture()
        result = self.operate("refresh", fetch=upstream(openai=additive).__getitem__)
        self.assertEqual(result["status"], "matches")
        self.assertEqual(self.calls[0][1], self.original)
        saved = product.read_inputs(self.deployment)
        self.assertEqual(saved["registry"]["source"]["commit"], NEW)
        for key in ("catalog", "settings", "sources"):
            self.assertEqual(self.deployment[key].read_bytes(), self.original[key])
        rules = catalog_rules(saved["catalog"], saved["registry"])
        selected = next(s for s in rules["service_states"] if s["id"] == "openai")
        self.assertEqual(selected["upstream_state"]["pending_scope"], [{"kind": "suffix", "name": "pending.example"}])
        self.assertIn("new.api.openai.com", selected["domains"])
        self.assertNotIn("pending.example", rules["domain_suffixes"])
        native_dns = json.loads((self.actual / "agh-conf/AdGuardHome.yaml").read_text())["user_rules"]
        self.assertFalse(any("pending.example" in rule for rule in native_dns))

    def test_refresh_removal_or_license_change_leaves_canonical_and_runtime_unchanged(self):
        additive = self.refresh_fixture()
        for replies, reason in ((upstream(), "selected-rule-removal"),
                                (upstream(openai=additive, license_text=LICENSE + "New notice\n"), "license-change")):
            with self.subTest(reason=reason):
                result = self.operate("refresh", fetch=replies.__getitem__)
                self.assertEqual(result["status"], "review-required")
                self.assertIn(reason, result["review_reasons"])
                self.assertEqual(self.calls, [])
                self.assertEqual(self.actual, self.accepted)
                self.assertEqual(self.canonical_bytes(), self.original)
                self.assertFalse(self.deployment["releases"].exists())
                saved_proposal = json.loads((self.deployment["receipts"] / "source-proposals/latest.json").read_text())
                self.assertTrue(saved_proposal["review_required"])

    def test_refresh_fetch_failure_or_malformed_source_never_changes_inputs_or_runtime(self):
        self.refresh_fixture()
        calls = []
        def unavailable(url):
            calls.append(url)
            raise OSError("transport unavailable")
        with self.assertRaisesRegex(PolicyError, "source refresh failed"):
            self.operate("refresh", fetch=unavailable)
        self.assertTrue(calls)
        self.assertEqual(self.canonical_bytes(), self.original)
        malformed = copy.deepcopy(self.initial["sources"])
        malformed["sources"][0]["commit"] = "main"
        write_json(self.deployment["sources"], malformed)
        before = self.canonical_bytes()
        calls.clear()
        with self.assertRaisesRegex(PolicyError, "source refresh failed"):
            self.operate("refresh", fetch=unavailable)
        self.assertEqual(calls, [])
        self.assertEqual(self.canonical_bytes(), before)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.actual, self.accepted)
        self.assertFalse(self.deployment["receipts"].exists())

    def test_unchanged_source_still_reconciles_native_drift(self):
        self.refresh_fixture()
        drifted = copy.deepcopy(self.initial)
        drifted["catalog"]["services"][0]["enabled"] = False
        self.actual = self.accepted.parent / "drifted-actual"
        product.prepare(self.deployment, drifted, self.actual)
        result = self.operate("refresh", fetch=upstream(OLD).__getitem__)
        self.assertEqual(result["status"], "matches")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.canonical_bytes(), self.original)
        self.assertEqual(json.loads((self.actual / "inputs/rules/pilot.json").read_text()), self.initial["catalog"])

    def test_refresh_readback_failure_restores_prior_registry_and_native_generation(self):
        additive = self.refresh_fixture()
        normal_reader = self.reader
        def failed(*args, **kwargs):
            result = normal_reader(*args, **kwargs)
            if self.reads == 2:
                self.assertEqual(product.read_inputs(self.deployment)["registry"]["source"]["commit"], NEW)
                result["status"] = "drift"
            return result
        self.reader = failed
        with self.assertRaises(PolicyError):
            self.operate("refresh", fetch=upstream(openai=additive).__getitem__)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(product.read_inputs(self.deployment), self.initial)
        self.assertEqual(json.loads((self.actual / "inputs/rules/registry.json").read_text()), self.initial["registry"])

    def test_exclude_and_include_publish_exact_exception_within_selected_suffix(self):
        self.refresh_fixture()
        result = self.operate("exclude", service_id="api.openai.com", reason="Explicit owner exception")
        self.assertEqual(result["status"], "matches")
        self.assertEqual(self.calls[0][1], self.original)
        saved = product.read_inputs(self.deployment)
        self.assertEqual(saved["catalog"]["excluded_domains"], {"api.openai.com": "Explicit owner exception"})
        self.assertEqual(saved["catalog"]["revision"], self.initial["catalog"]["revision"] + 1)
        dns = json.loads((self.actual / "agh-conf/AdGuardHome.yaml").read_text())["user_rules"]
        self.assertIn("@@|api.openai.com|$dnsrewrite", dns)
        self.assertIn("||openai.com^$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10", dns)
        self.assertIn("acl policy_excluded req.ssl_sni,lower -m str api.openai.com", (self.actual / "haproxy.cfg").read_text())
        compose = json.loads((self.actual / "compose.lab.json").read_text())
        route = compose["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        self.assertIn("HostSNI(`api.openai.com`)", route.split(" && !(", 1)[1])
        result = self.operate("include", service_id="api.openai.com", reason="Owner removed manual exception")
        self.assertEqual(result["status"], "matches")
        restored = product.read_inputs(self.deployment)
        self.assertEqual(restored["catalog"]["excluded_domains"], {})
        self.assertEqual(restored["catalog"]["revision"], self.initial["catalog"]["revision"] + 2)
        self.assertEqual(restored["registry"], self.initial["registry"])
        self.assertNotIn("@@|api.openai.com|$dnsrewrite", json.loads((self.actual / "agh-conf/AdGuardHome.yaml").read_text())["user_rules"])

    def test_invalid_or_outside_exclusion_fails_before_native_and_keeps_inputs(self):
        for name, reason in (("outside.example", "Not selected"), ("*.service.example", "Invalid matcher"),
                             ("Service.example", "Invalid case"), ("service.example", "")):
            with self.subTest(name=name, reason=reason), self.assertRaises(ValueError if reason else PolicyError):
                self.operate("exclude", service_id=name, reason=reason)
            self.assertEqual(self.calls, [])
            self.assertEqual(self.canonical_bytes(), self.original)
            self.assertFalse(self.deployment["releases"].exists())

    def test_include_cannot_remove_service_off_derived_exclusion(self):
        self.operate("off")
        before = self.canonical_bytes()
        self.assertEqual(product.read_inputs(self.deployment)["catalog"]["excluded_domains"], {})
        with self.assertRaisesRegex(PolicyError, "no manual exclusion"):
            self.operate("include", service_id="service.example", reason="Cannot override service OFF")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.canonical_bytes(), before)
        self.assertFalse(product.read_inputs(self.deployment)["catalog"]["services"][0]["enabled"])


if __name__ == "__main__":
    unittest.main()
