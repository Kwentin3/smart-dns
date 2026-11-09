"""Accepted native policy publication against a real, disposable Git remote."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import test_product
from test_source_proposals import OLD, upstream
from tools import product
from tools.catalog import write_json
from tools.policy_git import PolicyGit, PolicyGitError
from tools.service_policy import PolicyError


class ProductGitTests(unittest.TestCase):
    def setUp(self):
        # Compose the existing real renderer/native-IO fixture without inheriting
        # its tests (which unittest would discover a second time).
        self.fixture = test_product.ProductTests("test_success_publishes_only_after_native_apply_and_matches_actual")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.deployment = self.fixture.deployment
        self.directory = self.deployment["catalog"].parents[1]
        settings = self.directory.parent / "private-settings.json"
        self.deployment["settings"].replace(settings)
        self.deployment["settings"] = settings
        self.fixture.original = self.fixture.canonical_bytes()
        self.remote = self.directory.parent / "policy-remote.git"
        self.git("init", "--bare", "--initial-branch=main", str(self.remote), cwd=self.directory.parent)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Disposable policy test")
        self.git("config", "user.email", "policy-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("remote", "add", "origin", str(self.remote))
        self.deployment["policy_git"] = {"directory": self.directory, "remote": "origin", "branch": "main"}
        self.save_baseline()

    def git(self, *arguments, cwd=None):
        result = subprocess.run(["git", *arguments], cwd=cwd or self.directory,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def save_baseline(self):
        self.git("add", "--", "rules/pilot.json", "rules/registry.json", "rules/sources.json")
        self.git("commit", "-m", "Accepted fixture baseline")
        self.git("push", "origin", "HEAD:refs/heads/main")
        self.baseline_head = self.remote_head()

    def remote_head(self):
        return self.git("--git-dir=" + str(self.remote), "rev-parse", "refs/heads/main").strip()

    def remote_bytes(self, key):
        return self.git("--git-dir=" + str(self.remote), "show", "refs/heads/main:" + product.INPUT_NAMES[key])

    def reject_pushes(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_bytes(b"#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        return hook

    def assert_remote_matches_canonical(self):
        for key in ("catalog", "registry", "sources"):
            self.assertEqual(self.remote_bytes(key), self.deployment[key].read_bytes(), key)
        paths = self.git("--git-dir=" + str(self.remote), "ls-tree", "-r", "--name-only", "main").splitlines()
        self.assertEqual(set(paths), {b"rules/pilot.json", b"rules/registry.json", b"rules/sources.json"})

    def assert_pending(self, report):
        self.assertEqual(report["status"], "git-sync-pending")
        self.assertEqual(report["runtime_status"], "matches")
        self.assertEqual(report["policy_git"]["status"], "pending")
        self.assertTrue(report["policy_git"]["reason"])

    def test_success_publishes_exact_accepted_bytes_without_private_inputs(self):
        report = self.fixture.operate()
        self.assertEqual(report["status"], "matches")
        self.assertEqual(report["runtime_status"], "matches")
        self.assertEqual(report["policy_git"]["status"], "synced")
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertEqual(self.fixture.calls[0][1], self.fixture.original)
        self.assertNotEqual(self.remote_head(), self.baseline_head)
        self.assert_remote_matches_canonical()

    def test_rejected_push_keeps_native_acceptance_and_retry_adds_no_commit(self):
        hook = self.reject_pushes()
        report = self.fixture.operate()
        self.assert_pending(report)
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertFalse(product.read_inputs(self.deployment)["catalog"]["services"][0]["enabled"])
        self.assertEqual(self.fixture.reader(**self.native_status_arguments())["status"], "matches")
        self.assertEqual(self.remote_head(), self.baseline_head)
        accepted_head = self.git("rev-parse", "HEAD").strip()
        hook.unlink()

        def forbidden_fetch(_url):
            self.fail("git-sync must not fetch policy sources")

        for _ in range(2):
            repaired = self.fixture.operate("git-sync", fetch=forbidden_fetch)
            self.assertEqual(repaired["status"], "matches")
            self.assertEqual(repaired["policy_git"]["status"], "synced")
            self.assertEqual(self.git("rev-parse", "HEAD").strip(), accepted_head)
            self.assertEqual(len(self.fixture.calls), 1)
            self.assert_remote_matches_canonical()

    def native_status_arguments(self):
        inputs = product.read_inputs(self.deployment)
        return {"settings": inputs["settings"], "catalog": inputs["catalog"], "registry": inputs["registry"]}

    def test_unchanged_refresh_repairs_publication_without_reapplying(self):
        self.fixture.refresh_fixture()
        self.save_baseline()
        hook = self.reject_pushes()
        self.assert_pending(self.fixture.operate())
        accepted_head = self.git("rev-parse", "HEAD").strip()
        hook.unlink()
        report = self.fixture.operate("refresh", fetch=upstream(OLD).__getitem__)
        self.assertEqual(report["status"], "matches")
        self.assertEqual(report["policy_git"]["status"], "synced")
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), accepted_head)
        self.assert_remote_matches_canonical()

    def test_native_failure_does_not_publish(self):
        with self.assertRaises(PolicyError):
            self.fixture.operate(native=lambda _arguments, _environment: False)
        self.assertEqual(self.fixture.canonical_bytes(), self.fixture.original)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.baseline_head)

    def test_failed_readback_restores_native_and_never_publishes(self):
        reader = self.fixture.reader

        def drift(*args, **kwargs):
            report = reader(*args, **kwargs)
            if self.fixture.reads == 2:
                report["status"] = "drift"
            return report

        self.fixture.reader = drift
        with self.assertRaises(PolicyError):
            self.fixture.operate()
        self.assertEqual(len(self.fixture.calls), 2)
        self.assertEqual(product.read_inputs(self.deployment), self.fixture.initial)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.baseline_head)

    def test_review_required_refresh_never_publishes_candidate(self):
        self.fixture.refresh_fixture()
        self.save_baseline()
        report = self.fixture.operate("refresh", fetch=upstream().__getitem__)
        self.assertEqual(report["status"], "review-required")
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual(self.fixture.canonical_bytes(), self.fixture.original)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.baseline_head)

    def test_unrelated_repository_dirt_blocks_before_native_mutation(self):
        (self.directory / "foreign.txt").write_text("another owner's work", encoding="utf-8")
        with self.assertRaises(PolicyGitError):
            self.fixture.operate()
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual(self.fixture.canonical_bytes(), self.fixture.original)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertFalse(self.deployment["releases"].exists())

    def test_status_reports_pending_without_mutating_files_or_commits(self):
        hook = self.reject_pushes()
        self.assert_pending(self.fixture.operate())
        before = {path: path.read_bytes() for path in self.directory.parent.rglob("*") if path.is_file()}
        report = product.operator_status(self.deployment, status_reader=self.fixture.reader)
        self.assert_pending(report)
        after = {path: path.read_bytes() for path in self.directory.parent.rglob("*") if path.is_file()}
        self.assertEqual(after, before)
        hook.unlink()

    def test_edit_after_owner_readback_is_preserved_without_git_publication(self):
        reader = self.fixture.reader
        foreign = copy.deepcopy(self.fixture.initial["catalog"])
        foreign["services"][0].update(enabled=False, reason="Concurrent owner after native readback")

        def edit_after_readback(*args, **kwargs):
            report = reader(*args, **kwargs)
            if self.fixture.reads == 2:
                self.assertEqual(report["status"], "matches")
                write_json(self.deployment["catalog"], foreign)
            return report

        self.fixture.reader = edit_after_readback
        report = self.fixture.operate()
        self.assertEqual(report["status"], "git-sync-pending")
        self.assertEqual(report["runtime_status"], "not-rechecked")
        self.assertEqual(report["policy_git"]["reason"], "inputs-changed")
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertEqual(json.loads(self.deployment["catalog"].read_bytes()), foreign)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.baseline_head)

    def test_edit_during_failed_publication_invalidates_native_claim_without_rollback(self):
        native_git = PolicyGit._git
        foreign = b'{"external": "edit during real Git staging"}\n'

        def edit_after_staging(adapter, arguments, **kwargs):
            result = native_git(adapter, arguments, **kwargs)
            if arguments[0] == "add":
                self.deployment["catalog"].write_bytes(foreign)
            return result

        with patch.object(PolicyGit, "_git", new=edit_after_staging):
            report = self.fixture.operate()
        self.assertEqual(report["status"], "git-sync-pending")
        self.assertEqual(report["runtime_status"], "not-rechecked")
        self.assertEqual(report["policy_git"]["reason"], "inputs-changed")
        self.assertEqual(len(self.fixture.calls), 1)
        self.assertEqual(self.deployment["catalog"].read_bytes(), foreign)
        self.assertEqual(self.remote_head(), self.baseline_head)
        self.assertEqual(self.git("diff", "--cached", "--name-only"), b"")

    def manifest(self):
        path = self.directory.parent / ".local/deployment.json"
        path.parent.mkdir(exist_ok=True)
        value = {"schema_version": 1, **self.deployment,
                 "policy_git": {**self.deployment["policy_git"], "directory": "../" + self.directory.name}}
        path.write_text(json.dumps(value, default=str), encoding="utf-8")
        return path

    def test_manifest_resolves_opt_in_directory_and_rejects_unknown_config_fields(self):
        path = self.manifest()
        loaded = product.load_deployment(path)
        self.assertEqual(loaded["policy_git"]["directory"], self.directory)
        self.assertEqual(product.operator_status(loaded, status_reader=self.fixture.reader)["status"], "matches")
        value = json.loads(path.read_text(encoding="utf-8"))
        value["policy_git"]["unverified_visibility"] = "private"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(PolicyError):
            product.load_deployment(path)

    def test_status_cli_exit_code_distinguishes_synced_from_git_pending(self):
        path = self.manifest()
        read_status = product.operator_status

        def invoke():
            output = io.StringIO()
            with patch("sys.argv", ["product.py", "--deployment", str(path), "status"]), redirect_stdout(output), \
                    patch.object(product, "operator_status", side_effect=lambda deployment:
                                 read_status(deployment, status_reader=self.fixture.reader)):
                exit_code = product.main()
            return exit_code, json.loads(output.getvalue())

        exit_code, report = invoke()
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["policy_git"]["status"], "synced")
        self.git("remote", "set-url", "origin", str(self.directory.parent / "unavailable.git"))
        exit_code, report = invoke()
        self.assertEqual(exit_code, 1)
        self.assert_pending(report)

    def test_disabled_feature_preserves_native_operation_without_git_executable(self):
        del self.deployment["policy_git"]
        with patch.dict(os.environ, {"PATH": ""}):
            report = self.fixture.operate()
        self.assertEqual(report["status"], "matches")
        self.assertNotIn("policy_git", report)
        self.assertEqual(len(self.fixture.calls), 1)


if __name__ == "__main__":
    unittest.main()
