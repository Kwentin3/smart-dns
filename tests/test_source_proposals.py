"""Proposal evidence preserves upstream syntax without mutating accepted state."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.source_proposals import PATHS, REPOSITORY, fetch_text, produce, proposal, raw_url

OLD, NEW = "a" * 40, "b" * 40
LICENSE = "MIT License\nCopyright fixture\nPermission fixture\n"


def source():
    return {"sources": [{"id": "v2fly-service-catalog", "repository": REPOSITORY, "commit": OLD,
                         "paths": list(PATHS), "license": "MIT", "license_reference": f"{REPOSITORY}/blob/{OLD}/LICENSE"}]}


def upstream():
    replies = {"https://api.github.com/repos/v2fly/domain-list-community/commits/HEAD": json.dumps({"sha": NEW})}
    for pin in (OLD, NEW):
        for path in PATHS:
            replies[raw_url(pin, path)] = "domain:example.com\nfull:old.example.com @telemetry\n"
        replies[raw_url(pin, "LICENSE")] = LICENSE
    replies[raw_url(NEW, PATHS[0])] = "full:example.com\nregexp:^new.* @ads\ninclude:another @cn\n"
    return replies


class SourceProposalTests(unittest.TestCase):
    def test_add_remove_and_rule_type_changes_remain_raw_evidence(self):
        result = proposal(source(), upstream().__getitem__)
        diff = result["files"][0]["diff"]
        for line in ("-domain:example.com", "+full:example.com", "-full:old.example.com @telemetry", "+regexp:^new.* @ads", "+include:another @cn"):
            self.assertIn(line, diff)
        self.assertEqual(result["license"]["proposed_text"], LICENSE)
        self.assertFalse(result["files"][1]["changed"])
        self.assertEqual(result["proposed_commit"], NEW)

    def test_malformed_accepted_pin_rejected_before_network(self):
        document = source()
        document["sources"][0]["commit"] = "master"
        with self.assertRaises(ValueError):
            proposal(document, lambda _: self.fail("network must not run"))

    def test_mutable_or_malformed_upstream_commit_rejected(self):
        for pin in ("main", "b" * 39, "B" * 40, "../data/openai"):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                proposal(source(), lambda _: json.dumps({"sha": pin}))

    def test_fetch_failure_preserves_accepted_and_prior_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = root / "rules/sources.json"
            accepted.parent.mkdir()
            accepted.write_text(json.dumps(source()), encoding="utf-8")
            original = accepted.read_bytes()
            output = root / ".local/source-proposals/latest.json"
            def fail(url):
                if url == raw_url(NEW, PATHS[1]):
                    raise OSError("fixture unavailable after earlier files fetched")
                return upstream()[url]
            with self.assertRaises(OSError):
                produce(accepted, output, fail)
            self.assertFalse(output.exists())
            output.parent.mkdir(parents=True)
            output.write_bytes(b"previous proposal")
            with self.assertRaises(OSError):
                produce(accepted, output, fail)
            self.assertEqual(output.read_bytes(), b"previous proposal")
            self.assertEqual(accepted.read_bytes(), original)
            produce(accepted, output, upstream().__getitem__)
            self.assertEqual(json.loads(output.read_text())["proposed_commit"], NEW)
            self.assertEqual(accepted.read_bytes(), original)

    def test_output_cannot_target_accepted_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            accepted = Path(directory) / "rules/sources.json"
            with self.assertRaises(ValueError):
                produce(accepted, accepted, lambda _: self.fail("must not fetch"))

    def test_output_cannot_overwrite_private_settings_or_runtime_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = root / "rules/sources.json"
            accepted.parent.mkdir()
            accepted.write_text(json.dumps(source()), encoding="utf-8")
            for target in (".local/settings.json", ".local/origins.json", ".local/accepted/compose.lab.json", ".local/source-proposal.json"):
                output = root / target
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"accepted private input")
                with self.subTest(target=target), self.assertRaises(ValueError):
                    produce(accepted, output, lambda _: self.fail("must refuse before network"))
                self.assertEqual(output.read_bytes(), b"accepted private input")

    def test_binary_nul_rejected_by_actual_fetch_decoder(self):
        import io
        response = io.BytesIO(b"MIT License\0binary")
        with patch("tools.source_proposals.urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "NUL"):
                fetch_text(raw_url(OLD, "LICENSE"))


if __name__ == "__main__":
    unittest.main()
