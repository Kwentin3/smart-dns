"""Publish the native owner's three policy files as bytes in a dedicated Git repo."""
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess


POLICY_KEYS = ("catalog", "registry", "sources")
TIMEOUT = 30


class PolicyGitError(Exception):
    """Only safe reason codes cross the product boundary, never Git diagnostics."""

    def __init__(self, reason, **details):
        self.receipt = {"status": "pending", "reason": reason, **details}
        super().__init__(f"policy Git pending: {reason}")


class PolicyGit:
    def __init__(self, deployment):
        self.deployment = deployment
        config = deployment.get("policy_git")
        if not isinstance(config, dict) or set(config) != {"directory", "remote", "branch"}:
            raise PolicyGitError("invalid_config")
        if not isinstance(config["directory"], (str, Path)):
            raise PolicyGitError("invalid_directory")
        self.root = Path(config["directory"]).absolute()
        self.remote, self.branch = config["remote"], config["branch"]
        if not isinstance(self.remote, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.remote):
            raise PolicyGitError("invalid_remote")
        if not isinstance(self.branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,127}", self.branch):
            raise PolicyGitError("invalid_branch")
        self.ref = "refs/heads/" + self.branch
        self.paths = {}
        for key in POLICY_KEYS:
            path = deployment.get(key)
            if not isinstance(path, (str, Path)):
                raise PolicyGitError("invalid_policy_path")
            self.paths[key] = Path(path).absolute()

    def _git(self, arguments, *, allowed=(0,), reason="git_failed"):
        # An ambient GIT_INDEX_FILE/GIT_DIR must never redirect this operation.
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        environment.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GCM_INTERACTIVE="never",
                           GIT_SSH_COMMAND="ssh -oBatchMode=yes -oConnectTimeout=10")
        command = ["git", "--no-optional-locks", "--literal-pathspecs", "-C", str(self.root), "-c", "core.fsmonitor=false",
                   "-c", "commit.gpgSign=false", "-c", "push.gpgSign=false", *arguments]
        # -c config is propagated to a local receive-pack. Disable local hooks
        # only on local commands so server hooks remain the publication owner.
        if arguments[0] not in ("push", "ls-remote"):
            command[5:5] = ["-c", "core.hooksPath="]
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        try:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=environment, **options)
            try:
                output, _ = child.communicate(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                else:
                    os.killpg(child.pid, signal.SIGKILL)
                child.kill()
                child.communicate(timeout=10)
                raise PolicyGitError("git_timeout") from None
        except FileNotFoundError:
            raise PolicyGitError("git_unavailable") from None
        except (OSError, subprocess.SubprocessError):
            raise PolicyGitError(reason) from None
        if child.returncode not in allowed:
            raise PolicyGitError(reason)
        return child.returncode, output

    def _text(self, arguments, **kwargs):
        try:
            return self._git(arguments, **kwargs)[1].decode("utf-8", errors="strict").strip()
        except UnicodeError:
            raise PolicyGitError("git_output_invalid") from None

    def _snapshot(self):
        try:
            if any(not path.is_file() or path.is_symlink() for path in self.paths.values()):
                raise PolicyGitError("invalid_policy_file")
            return {key: path.read_bytes() for key, path in self.paths.items()}
        except OSError:
            raise PolicyGitError("policy_read_failed") from None

    @staticmethod
    def _hash(snapshot):
        digest = hashlib.sha256()
        for key in POLICY_KEYS:
            content = snapshot[key]
            digest.update(key.encode("ascii") + b"\0" + len(content).to_bytes(8, "big") + content)
        return digest.hexdigest()

    def _unchanged(self, snapshot):
        if self._snapshot() != snapshot:
            raise PolicyGitError("policy_changed_during_publication")

    def _head(self):
        code, value = self._git(["rev-parse", "--verify", "HEAD"], allowed=(0, 128))
        return value.decode("ascii").strip() if code == 0 else None

    def _tree(self, revision):
        entries = self._git(["ls-tree", "-rz", revision])[1].split(b"\0")
        tree = {}
        for entry in filter(None, entries):
            metadata, path = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split(b" ")
            if mode not in (b"100644", b"100755") or kind != b"blob":
                raise PolicyGitError("unexpected_tracked_file")
            tree[path] = oid.decode("ascii")
        return tree

    def _validate(self):
        try:
            resolved = self.root.resolve(strict=True)
            if resolved != self.root or self.root == Path(self.root.anchor) or not self.root.is_dir():
                raise PolicyGitError("unsafe_repository_root")
            names = {}
            for key, path in self.paths.items():
                if path.resolve(strict=True) != path or self.root not in path.parents:
                    raise PolicyGitError("policy_outside_repository")
                relative = path.relative_to(self.root)
                if any(part.lower() == ".git" for part in relative.parts):
                    raise PolicyGitError("unsafe_policy_path")
                names[key] = relative.as_posix().encode("utf-8")
            if len(set(names.values())) != len(POLICY_KEYS):
                raise PolicyGitError("overlapping_policy_paths")
            # Private deployment artifacts may not be inside the publication tree,
            # even if they have not been created yet.
            for key in ("settings", "origins", "admin_password_file", "releases", "receipts", "dot_cert_dir"):
                if key in self.deployment:
                    path = Path(self.deployment[key]).resolve()
                    if path == self.root or self.root in path.parents or path in self.root.parents:
                        raise PolicyGitError("private_path_overlap")
            top = Path(self._text(["rev-parse", "--show-toplevel"], reason="not_policy_repository")).resolve()
            if top != self.root or self._text(["rev-parse", "--is-bare-repository"]) != "false":
                raise PolicyGitError("not_policy_repository")
            self._git(["check-ref-format", self.ref], reason="invalid_branch")
            if self._text(["symbolic-ref", "--quiet", "HEAD"], reason="foreign_branch") != self.ref:
                raise PolicyGitError("foreign_branch")
            fetch = self._text(["remote", "get-url", "--all", self.remote], reason="remote_not_configured").splitlines()
            push = self._text(["remote", "get-url", "--push", "--all", self.remote], reason="remote_not_configured").splitlines()
            if len(fetch) != 1 or fetch != push:
                raise PolicyGitError("ambiguous_remote")
            allowed = set(names.values())
            for arguments in (["ls-files", "--cached", "-z"], ["ls-files", "--others", "-z"]):
                if set(filter(None, self._git(arguments)[1].split(b"\0"))) - allowed:
                    raise PolicyGitError("unexpected_repository_file")
            if self._git(["diff", "--cached", "--quiet", "--exit-code"], allowed=(0, 1))[0]:
                raise PolicyGitError("staged_changes")
            head = self._head()
            if head:
                if set(self._tree(head)) - allowed:
                    raise PolicyGitError("unexpected_tracked_file")
                history = self._git(["log", "--format=", "--name-only", "-z", "--root", "-m", "HEAD"])[1]
                if set(filter(None, history.split(b"\0"))) - allowed:
                    raise PolicyGitError("unexpected_history_file")
            self._git(["var", "GIT_AUTHOR_IDENT"], reason="git_identity_missing")
            self._git(["var", "GIT_COMMITTER_IDENT"], reason="git_identity_missing")
            self.names = names
            self._snapshot()
            return head
        except (OSError, ValueError, UnicodeError):
            raise PolicyGitError("invalid_repository") from None

    def preflight(self):
        """Validate local scope without staging, committing, fetching or network IO."""
        head = self._validate()
        return {"status": "ready", "commit": head}

    def _remote_head(self):
        output = self._text(["ls-remote", "--refs", self.remote, self.ref], reason="remote_unavailable")
        if not output:
            return None
        lines = output.splitlines()
        fields = lines[0].split("\t")
        if len(lines) != 1 or len(fields) != 2 or fields[1] != self.ref or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields[0]):
            raise PolicyGitError("remote_identity_invalid")
        return fields[0]

    def _matches(self, head, snapshot):
        if not head:
            return False
        tree = self._tree(head)
        if set(tree) != set(self.names.values()):
            return False
        return all(self._git(["cat-file", "blob", tree[self.names[key]]])[1] == content
                   for key, content in snapshot.items())

    def check(self):
        """Report actual current bytes and remote identity, with no local mutation."""
        head = self._validate()
        snapshot = self._snapshot()
        receipt = {"status": "pending", "content_sha256": self._hash(snapshot),
                   "commit": head, "remote_commit": None, "created_commit": False}
        try:
            receipt["remote_commit"] = self._remote_head()
            matches = self._matches(head, snapshot)
            self._unchanged(snapshot)
            if matches and head == receipt["remote_commit"]:
                receipt["status"] = "synced"
            else:
                receipt["reason"] = "content_not_committed" if not matches else "remote_not_synced"
        except PolicyGitError as error:
            receipt.update(error.receipt)
        return receipt

    def publish(self, expected=None):
        """Commit/push only the actual canonical bytes; keep failed pushes retryable."""
        head = self._validate()
        snapshot = self._snapshot()
        if expected is not None and (not isinstance(expected, dict) or set(expected) != set(POLICY_KEYS)
                                     or any(type(value) is not bytes for value in expected.values())
                                     or expected != snapshot):
            raise PolicyGitError("owner_bytes_mismatch")
        receipt = {"content_sha256": self._hash(snapshot), "commit": head,
                   "remote_commit": None, "created_commit": False}
        staged = False
        try:
            remote = self._remote_head()
            receipt["remote_commit"] = remote
            if remote and (not head or self._git(["merge-base", "--is-ancestor", remote, head], allowed=(0, 1, 128))[0]):
                raise PolicyGitError("remote_diverged")
            self._unchanged(snapshot)
            if not self._matches(head, snapshot):
                staged = True
                self._git(["add", "--", *(name.decode("utf-8") for name in self.names.values())], reason="stage_failed")
                # Git attributes, autocrlf and filters cannot silently change bytes.
                for key, content in snapshot.items():
                    indexed_content = self._git(["show", ":" + self.names[key].decode("utf-8")])[1]
                    if indexed_content != content:
                        raise PolicyGitError("staged_bytes_mismatch")
                self._unchanged(snapshot)
                self._git(["commit", "--no-gpg-sign", "-m", "Publish policy " + receipt["content_sha256"]], reason="commit_failed")
                head = self._head()
                staged = False
                receipt.update(commit=head, created_commit=True)
            if not self._matches(head, snapshot):
                raise PolicyGitError("committed_bytes_mismatch")
            self._unchanged(snapshot)
            if remote != head:
                self._git(["push", "--no-verify", "--porcelain", self.remote, head + ":" + self.ref], reason="push_failed")
            receipt["remote_commit"] = self._remote_head()
            if receipt["remote_commit"] != head:
                raise PolicyGitError("remote_not_synced")
            self._unchanged(snapshot)
            return {"status": "synced", **receipt}
        except PolicyGitError as error:
            if staged:
                # Preflight required an empty index. Undo only our own staging;
                # leave canonical files intact, including any concurrent edit.
                try:
                    if head:
                        self._git(["reset", "--quiet", head, "--", *(name.decode("utf-8") for name in self.names.values())])
                    else:
                        self._git(["rm", "--cached", "--force", "--ignore-unmatch", "--",
                                   *(name.decode("utf-8") for name in self.names.values())])
                except PolicyGitError:
                    raise PolicyGitError("index_cleanup_failed", **receipt) from None
            raise PolicyGitError(error.receipt["reason"], **receipt) from None
