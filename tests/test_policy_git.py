"""Publication contract exercised through real working repositories and a bare remote."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.policy_git import PolicyGit, PolicyGitError, POLICY_KEYS


class PolicyGitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo = self.base / "policy"
        self.remote = self.base / "remote.git"
        self.repo.mkdir()
        self.git("init", "--bare", str(self.remote), cwd=self.base)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Policy publication test")
        self.git("config", "user.email", "policy-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("remote", "add", "origin", str(self.remote))
        self.deployment = {"policy_git": {"directory": self.repo, "remote": "origin", "branch": "main"},
                           "settings": self.base / "private/settings.json",
                           "admin_password_file": self.base / "private/password",
                           "releases": self.base / "private/releases",
                           "receipts": self.base / "private/receipts"}
        for key, name in zip(POLICY_KEYS, ("pilot.json", "registry.json", "sources.json")):
            path = self.repo / "rules" / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(json.dumps({"role": key}, ensure_ascii=False).encode() + b"\n")
            self.deployment[key] = path
        self.adapter = PolicyGit(self.deployment)

    def git(self, *arguments, cwd=None, allowed=(0,)):
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        result = subprocess.run(["git", "-C", str(cwd or self.repo), *arguments],
                                capture_output=True, env=environment, timeout=10)
        if result.returncode not in allowed:
            self.fail("Fixture Git command failed: " + result.stderr.decode(errors="replace"))
        return result.stdout

    def snapshot(self):
        return {key: self.deployment[key].read_bytes() for key in POLICY_KEYS}

    def count(self):
        return int(self.git("rev-list", "--count", "HEAD").strip())

    def assert_remote_bytes(self, receipt):
        self.assertEqual(receipt["status"], "synced")
        self.assertEqual(receipt["commit"], receipt["remote_commit"])
        self.assertEqual(self.git("rev-parse", "refs/heads/main", cwd=self.remote).decode().strip(), receipt["commit"])
        paths = self.git("ls-tree", "-r", "--name-only", receipt["commit"], cwd=self.remote).decode().splitlines()
        self.assertEqual(set(paths), {self.deployment[key].relative_to(self.repo).as_posix() for key in POLICY_KEYS})
        for key in POLICY_KEYS:
            name = self.deployment[key].relative_to(self.repo).as_posix()
            self.assertEqual(self.git("show", receipt["commit"] + ":" + name, cwd=self.remote), self.deployment[key].read_bytes())

    def test_preflight_is_local_and_does_not_stage_or_create_commit(self):
        self.git("remote", "set-url", "origin", str(self.base / "not-yet-available.git"))
        self.assertEqual(self.adapter.preflight()["status"], "ready")
        self.assertEqual(self.git("ls-files"), b"")
        self.assertEqual(self.git("rev-parse", "--verify", "HEAD", allowed=(128,)), b"")

    def test_first_publication_repeat_and_changed_content_are_exact(self):
        expected = self.snapshot()
        first = self.adapter.publish(expected=expected)
        self.assertTrue(first["created_commit"])
        self.assert_remote_bytes(first)
        again = self.adapter.publish(expected=expected)
        self.assertFalse(again["created_commit"])
        self.assertEqual(again["commit"], first["commit"])
        self.assertEqual(again["content_sha256"], first["content_sha256"])
        self.assertEqual(self.count(), 1)
        self.deployment["catalog"].write_bytes(b'{"accepted":"changed"}\n')
        changed = self.adapter.publish(expected=self.snapshot())
        self.assertTrue(changed["created_commit"])
        self.assertNotEqual(changed["content_sha256"], first["content_sha256"])
        self.assertEqual(self.count(), 2)
        self.assert_remote_bytes(changed)
        self.assertEqual(self.adapter.check()["status"], "synced")

    def test_rejected_push_keeps_commit_and_retry_does_not_duplicate_it(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_bytes(b"#!/bin/sh\nprintf '%s' sensitive-token-fixture >&2\nexit 1\n")
        hook.chmod(0o700)
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.publish()
        receipt = caught.exception.receipt
        self.assertEqual(receipt["reason"], "push_failed")
        self.assertTrue(receipt["created_commit"])
        retained = self.git("rev-parse", "HEAD").decode().strip()
        self.assertEqual(retained, receipt["commit"])
        self.assertNotIn("sensitive-token-fixture", str(caught.exception) + json.dumps(receipt))
        self.assertEqual(self.git("diff", "--cached", "--name-only"), b"")
        hook.unlink()
        retried = self.adapter.publish()
        self.assertFalse(retried["created_commit"])
        self.assertEqual(retried["commit"], retained)
        self.assertEqual(self.count(), 1)
        self.assert_remote_bytes(retried)

    def test_divergent_remote_is_not_overwritten_and_retry_needs_reconciliation(self):
        first = self.adapter.publish()
        other = self.base / "other"
        self.git("clone", "--branch", "main", str(self.remote), str(other), cwd=self.base)
        self.git("config", "user.name", "Other accepted policy", cwd=other)
        self.git("config", "user.email", "other@example.invalid", cwd=other)
        (other / "rules/pilot.json").write_bytes(b'{"other":"accepted"}\n')
        self.git("add", "--", "rules/pilot.json", cwd=other)
        self.git("commit", "-m", "Other publisher", cwd=other)
        self.git("push", "origin", "main", cwd=other)
        remote = self.git("rev-parse", "refs/heads/main", cwd=self.remote)
        self.deployment["catalog"].write_bytes(b'{"local":"pending"}\n')
        for _ in range(2):
            with self.assertRaises(PolicyGitError) as caught:
                self.adapter.publish()
            self.assertEqual(caught.exception.receipt["reason"], "remote_diverged")
        self.assertEqual(self.git("rev-parse", "refs/heads/main", cwd=self.remote), remote)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), first["commit"])
        self.assertEqual(self.deployment["catalog"].read_bytes(), b'{"local":"pending"}\n')

    def test_foreign_staged_tracked_and_ignored_files_are_rejected(self):
        self.adapter.publish()
        foreign = self.repo / "password"
        foreign.write_bytes(b"never-publish-this-fixture")
        self.git("add", "--", "password")
        with self.assertRaises(PolicyGitError):
            self.adapter.publish()
        self.git("commit", "-m", "Foreign data must be rejected")
        with self.assertRaises(PolicyGitError):
            self.adapter.preflight()
        self.git("rm", "--", "password")
        self.git("commit", "-m", "Removing it does not sanitize history")
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.preflight()
        self.assertEqual(caught.exception.receipt["reason"], "unexpected_history_file")

    def test_ignored_foreign_file_is_rejected_without_index_changes(self):
        self.adapter.publish()
        (self.repo / ".git/info/exclude").write_text("private-secret\n", encoding="utf-8")
        (self.repo / "private-secret").write_bytes(b"ignored-but-still-private")
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.preflight()
        self.assertEqual(caught.exception.receipt["reason"], "unexpected_repository_file")
        self.assertEqual(self.git("diff", "--cached", "--name-only"), b"")

    def test_foreign_branch_and_preexisting_policy_staging_are_rejected(self):
        self.git("add", "--", "rules/pilot.json")
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.preflight()
        self.assertEqual(caught.exception.receipt["reason"], "staged_changes")
        self.git("read-tree", "--empty")
        self.adapter.publish()
        self.git("checkout", "-b", "foreign")
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.publish()
        self.assertEqual(caught.exception.receipt["reason"], "foreign_branch")

    def test_private_and_outside_paths_are_rejected(self):
        self.deployment["settings"] = self.repo / "not-yet-created-settings.json"
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.preflight()
        self.assertEqual(caught.exception.receipt["reason"], "private_path_overlap")
        self.deployment["settings"] = self.base / "settings.json"
        outside = self.base / "outside.json"
        outside.write_bytes(b"{}")
        self.deployment["catalog"] = outside
        with self.assertRaises(PolicyGitError) as caught:
            PolicyGit(self.deployment).preflight()
        self.assertEqual(caught.exception.receipt["reason"], "policy_outside_repository")

    def test_stale_owner_bytes_cannot_publish_a_real_file_mutation(self):
        owner = self.snapshot()
        self.deployment["catalog"].write_bytes(b'{"concurrent":"unaccepted"}\n')
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.publish(expected=owner)
        self.assertEqual(caught.exception.receipt["reason"], "owner_bytes_mismatch")
        self.assertEqual(self.git("ls-files"), b"")
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/main"), b"")

    def test_actual_mutation_during_staging_stops_publication_and_cleans_own_index(self):
        # Empty final indexed bytes must not suppress the cleanup guard.
        self.deployment["sources"].write_bytes(b"")
        original = self.adapter._git
        def mutate_after_real_add(arguments, **kwargs):
            result = original(arguments, **kwargs)
            if arguments[0] == "add":
                self.deployment["catalog"].write_bytes(b'{"raced":"real bytes"}\n')
            return result
        with patch.object(self.adapter, "_git", side_effect=mutate_after_real_add):
            with self.assertRaises(PolicyGitError) as caught:
                self.adapter.publish(expected=self.snapshot())
        self.assertEqual(caught.exception.receipt["reason"], "policy_changed_during_publication")
        self.assertEqual(self.git("ls-files"), b"")
        self.assertEqual(self.git("ls-remote", "origin", "refs/heads/main"), b"")
        self.assertEqual(self.deployment["catalog"].read_bytes(), b'{"raced":"real bytes"}\n')

    def test_git_newline_transform_is_rejected_before_commit_and_retry_works(self):
        self.git("config", "core.autocrlf", "true")
        self.deployment["catalog"].write_bytes(b'{\r\n  "crlf": true\r\n}\r\n')
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.publish()
        self.assertEqual(caught.exception.receipt["reason"], "staged_bytes_mismatch")
        self.assertEqual(self.git("ls-files"), b"")
        self.git("config", "core.autocrlf", "false")
        self.assert_remote_bytes(self.adapter.publish())

    def test_check_observes_real_bytes_and_remote_without_writes(self):
        published = self.adapter.publish()
        before = self.git("status", "--porcelain")
        def metadata():
            return {str(path.relative_to(self.repo)): path.read_bytes()
                    for path in (self.repo / ".git").rglob("*") if path.is_file()}
        git_before = metadata()
        self.assertEqual(self.adapter.check()["status"], "synced")
        self.assertEqual(metadata(), git_before)
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.deployment["sources"].write_bytes(b'{"new":"not committed"}\n')
        check = self.adapter.check()
        self.assertEqual(check["status"], "pending")
        self.assertEqual(check["reason"], "content_not_committed")
        self.assertNotEqual(check["content_sha256"], published["content_sha256"])
        self.assertEqual(self.count(), 1)
        self.git("remote", "set-url", "origin", str(self.base / "unavailable.git"))
        self.assertEqual(self.adapter.check()["reason"], "remote_unavailable")

    def test_raw_sensitive_remote_diagnostics_never_cross_adapter_boundary(self):
        sensitive = "sensitive-token-fixture"
        self.git("remote", "set-url", "origin", str(self.base / sensitive / "absent.git"))
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.publish()
        text = str(caught.exception) + json.dumps(caught.exception.receipt)
        self.assertNotIn(sensitive, text)
        self.assertNotIn(str(self.base), text)
        self.assertEqual(caught.exception.receipt["reason"], "remote_unavailable")

    def test_remote_config_requires_one_identical_fetch_and_push_identity(self):
        self.git("remote", "set-url", "--push", "origin", str(self.base / "other.git"))
        with self.assertRaises(PolicyGitError) as caught:
            self.adapter.preflight()
        self.assertEqual(caught.exception.receipt["reason"], "ambiguous_remote")

    def test_invalid_remote_and_branch_config_are_sanitized(self):
        for key, value in (("remote", ["origin"]), ("remote", "--upload-pack=secret"),
                           ("branch", None), ("branch", "main..bad")):
            with self.subTest(key=key, value=value):
                config = {**self.deployment, "policy_git": {**self.deployment["policy_git"], key: value}}
                with self.assertRaises(PolicyGitError):
                    PolicyGit(config).preflight()


if __name__ == "__main__":
    unittest.main()
