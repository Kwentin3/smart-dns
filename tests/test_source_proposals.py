"""Proposal publication uses the actual registry owner; only HTTP is replaced."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.registry import API, RAW, REPOSITORY, fetch_snapshot
from tools.source_proposals import produce, proposal

OLD, NEW, MASTER, LICENSE_ROOT = (value * 40 for value in "ab34")
LICENSE = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\nFixture license\n"


def blob(body):
    data = body.encode()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source():
    return {"sources": [{"id": "metacubex-sing", "repository": REPOSITORY, "branch": "sing",
                         "commit": OLD, "license": "GPL-3.0", "license_reference": REPOSITORY + "/blob/" + MASTER + "/LICENSE"}]}


def catalog(two=False):
    values = ["openai", "anthropic"] if two else ["openai"]
    return {"services": [{"id": value, "enabled": True, "upstream": {"source": "metacubex-sing", "list": value}} for value in values]}


def upstream(pin=NEW, *, openai=None, license_text=LICENSE):
    old = pin == OLD
    root, geo, index = (value * 40 for value in ("cde" if old else "f12"))
    documents = {
        "openai": {"version": 2, "rules": [{"domain": ["auth.openai.com"], "domain_suffix": ["openai.com"]}]},
        "anthropic": {"version": 2, "rules": [{"domain_suffix": ["anthropic.com"]}]},
        "spotify" if old else "netflix": {"version": 2, "rules": [{"domain_suffix": ["spotify.com" if old else "netflix.com"]}]},
    }
    if not old:
        documents["openai"] = {"version": 2, "rules": [{"domain_suffix": ["auth.openai.com", "openai.com"], "domain_regex": "^unsafe.example$"}]}
        documents["anthropic"] = {"version": 2, "rules": [{"domain_suffix": ["anthropic.com", "claude.ai"]}]}
    if openai is not None:
        documents["openai"] = openai
    bodies = {key: json.dumps(value) for key, value in documents.items()}
    tree = lambda entries: json.dumps({"tree": entries, "truncated": False})
    replies = {
        API + "/commits/sing": json.dumps({"sha": pin, "commit": {"tree": {"sha": root}}}),
        API + "/git/trees/" + root: tree([{"path": "geo", "type": "tree", "sha": geo}]),
        API + "/git/trees/" + geo: tree([{"path": "geosite", "type": "tree", "sha": index}]),
        API + "/git/trees/" + index: tree([{"path": key + ".json", "type": "blob", "sha": blob(body), "size": len(body.encode())} for key, body in bodies.items()]),
        API + "/commits/master": json.dumps({"sha": MASTER, "commit": {"tree": {"sha": LICENSE_ROOT}}}),
        API + "/git/trees/" + LICENSE_ROOT: tree([{"path": "LICENSE", "type": "blob", "sha": blob(license_text)}]),
        RAW + "/" + MASTER + "/LICENSE": license_text,
    }
    replies.update({RAW + "/" + pin + "/geo/geosite/" + key + ".json": value for key, value in bodies.items()})
    return replies


class SourceProposalTests(unittest.TestCase):
    def setUp(self):
        self.previous = fetch_snapshot(["openai"], fetch=upstream(OLD).__getitem__)

    def files(self, root, two=False):
        rules = root / "rules"
        rules.mkdir()
        paths = [rules / name for name in ("sources.json", "registry.json", "pilot.json")]
        previous = fetch_snapshot(["openai", "anthropic"], fetch=upstream(OLD).__getitem__) if two else self.previous
        for path, value in zip(paths, (source(), previous, catalog(two))):
            path.write_text(json.dumps(value), encoding="utf-8")
        return paths

    def test_full_index_and_type_changes_are_visible_without_activating_candidates(self):
        before = copy.deepcopy(self.previous)
        result = proposal(source(), self.previous, catalog(), fetch=upstream().__getitem__)
        candidate = result["candidate_registry"]
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["accepted_commit"], OLD)
        self.assertEqual(result["proposed_commit"], NEW)
        self.assertIn("netflix", result["index_changes"]["added"])
        self.assertIn("spotify", result["index_changes"]["removed"])
        change = result["selected_rule_changes"]["openai"]
        self.assertIn("auth.openai.com", change["exact"]["removed"])
        self.assertIn("auth.openai.com", change["suffix"]["added"])
        self.assertTrue(change["unsupported"]["added"])
        self.assertTrue(candidate["definitions"]["openai"]["partial"])
        self.assertEqual(set(candidate["definitions"]), {"openai"})
        self.assertEqual(candidate["source"]["license_text"], LICENSE)
        self.assertEqual(self.previous, before)
        self.assertTrue(result["review_required"])
        self.assertIn("selected-rule-removal", result["review_reasons"])

    def test_additions_are_proposals_but_removal_and_license_changes_require_review(self):
        original = copy.deepcopy(self.previous)
        additive = {"version": 2, "rules": [{"domain": ["auth.openai.com", "api.openai.com"],
                                             "domain_suffix": ["openai.com", "new-root.example"]}]}
        result = proposal(source(), self.previous, catalog(), fetch=upstream(openai=additive).__getitem__)
        self.assertTrue(result["changed"])
        self.assertFalse(result["review_required"])
        self.assertEqual(result["review_reasons"], [])
        self.assertEqual(result["selected_rule_changes"]["openai"]["suffix"]["added"], ["new-root.example"])
        changed_license = LICENSE + "Additional upstream license notice\n"
        licensed = proposal(source(), self.previous, catalog(),
                            fetch=upstream(openai=additive, license_text=changed_license).__getitem__)
        self.assertTrue(licensed["review_required"])
        self.assertEqual(licensed["review_reasons"], ["license-change"])
        self.assertEqual(self.previous, original)

    def test_wrong_source_owner_or_malformed_pin_is_rejected_before_network(self):
        for changes in ({"repository": "https://github.com/other/repository"}, {"license": "MIT"}, {"commit": "sing"}):
            document = source()
            document["sources"][0].update(changes)
            calls = []
            def unexpected(url):
                calls.append(url)
                raise OSError("network should not run")
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                proposal(document, self.previous, catalog(), fetch=unexpected)
            self.assertEqual(calls, [])

    def test_late_fetch_failure_preserves_all_accepted_inputs_and_previous_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, policy = self.files(root, two=True)
            before = {path: path.read_bytes() for path in (sources, registry, policy)}
            output = root / ".local/source-proposals/latest.json"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"previous atomic proposal and embedded candidate")
            replies, fetched = upstream(), []
            def fail(url):
                fetched.append(url)
                if url.endswith("openai.json"):
                    raise OSError("synthetic-credential-bearing-network-error")
                return replies[url]
            with self.assertRaises(ValueError) as error:
                produce(sources, output, fetch=fail, registry_path=registry, catalog_path=policy)
            self.assertNotIn("synthetic-credential", str(error.exception))
            self.assertTrue(any(url.endswith("anthropic.json") for url in fetched))
            self.assertEqual(output.read_bytes(), b"previous atomic proposal and embedded candidate")
            self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))

    def test_single_atomic_proposal_contains_the_exact_candidate_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, policy = self.files(root)
            before = {path: path.read_bytes() for path in (sources, registry, policy)}
            output = root / ".local/source-proposals/latest.json"
            result = produce(sources, output, fetch=upstream().__getitem__, registry_path=registry, catalog_path=policy)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved, result)
            expected = fetch_snapshot(["openai"], self.previous, fetch=upstream().__getitem__)
            self.assertEqual(saved["candidate_registry"], expected)
            self.assertEqual(list(output.parent.iterdir()), [output])
            self.assertTrue(all(path.read_bytes() == value for path, value in before.items()))

    def test_publish_failure_keeps_previous_complete_proposal_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, policy = self.files(root)
            output = root / ".local/source-proposals/latest.json"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"prior complete proposal")
            with patch.object(Path, "replace", side_effect=OSError("simulated output storage failure")), self.assertRaises(OSError):
                produce(sources, output, fetch=upstream().__getitem__, registry_path=registry, catalog_path=policy)
            self.assertEqual(output.read_bytes(), b"prior complete proposal")
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_output_cannot_overwrite_accepted_or_private_runtime_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, registry, policy = self.files(root)
            for target in (registry, sources, policy, root / ".local/settings.json", root / ".local/accepted/compose.production.json"):
                target.parent.mkdir(parents=True, exist_ok=True)
                before = target.read_bytes() if target.exists() else b"accepted private input"
                target.write_bytes(before)
                calls = []
                def unexpected(url):
                    calls.append(url)
                    raise OSError("network should not run")
                with self.subTest(target=target.name), self.assertRaises(ValueError):
                    produce(sources, target, fetch=unexpected, registry_path=registry, catalog_path=policy)
                self.assertEqual(calls, [])
                self.assertEqual(target.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
