"""Real OpenSSL validation and persisted rollback; only wire readback injected."""
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.certificate_deploy import DeployError, deploy, fingerprint, served_fingerprint


@unittest.skipUnless(shutil.which("openssl"), "native OpenSSL required")
class CertificateDeployTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "openssl.cnf"
        self.config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
        self.ca = self.root / "ca.pem"
        self.command("req", "-config", self.config, "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-subj", "/CN=Local fixture CA", "-keyout", self.root / "ca.key", "-out", self.ca)
        self.old = self.issue("old")
        self.new = self.issue("new")
        self.destination = self.root / "mounted"
        self.destination.mkdir()
        for name in ("fullchain.pem", "privkey.pem"):
            shutil.copyfile(self.old / name, self.destination / name)
        (self.destination / "privkey.pem").chmod(0o640)
        self.before = {name: (self.destination / name).read_bytes() for name in ("fullchain.pem", "privkey.pem")}
        self.options = dict(lab_ca=self.ca, min_valid_days=7, timeout=1)

    def command(self, *arguments):
        result = subprocess.run(["openssl", *map(str, arguments)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, "native fixture OpenSSL command failed")

    def issue(self, name, sans="DNS:dns.example.test,DNS:*.dns.example.test", days=20):
        directory = self.root / name
        directory.mkdir()
        extensions = directory / "extensions.cnf"
        extensions.write_text("subjectAltName=" + sans + "\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        self.command("req", "-config", self.config, "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=dns.example.test",
                     "-keyout", directory / "privkey.pem", "-out", directory / "request.pem")
        self.command("x509", "-req", "-in", directory / "request.pem", "-CA", self.ca,
                     "-CAkey", self.root / "ca.key", "-set_serial", str(len(list(self.root.iterdir())) + 10),
                     "-days", str(days), "-extfile", extensions, "-out", directory / "fullchain.pem")
        return directory

    def assert_untouched(self):
        for name, data in self.before.items():
            self.assertEqual((self.destination / name).read_bytes(), data)
        self.assertEqual(sorted(p.name for p in self.destination.iterdir() if p.name != ".certificate-deploy.lock"), sorted(self.before))

    def test_mismatched_pair_rejects_before_destination_or_wire_touch(self):
        shutil.copyfile(self.old / "privkey.pem", self.new / "privkey.pem")
        with patch("tools.certificate_deploy.wait_served") as wire:
            with self.assertRaisesRegex(DeployError, "do not match"):
                deploy(self.new, self.destination, "dns.example.test", "127.0.0.1", **self.options)
            wire.assert_not_called()
        self.assert_untouched()

    def test_expiring_missing_wildcard_and_untrusted_pairs_reject_untouched(self):
        for name, sans, days in (("short", "DNS:dns.example.test,DNS:*.dns.example.test", 1),
                                 ("no-wildcard", "DNS:dns.example.test", 20)):
            candidate = self.issue(name, sans, days)
            with self.subTest(name=name), self.assertRaises(DeployError):
                deploy(candidate, self.destination, "dns.example.test", "127.0.0.1", **self.options)
            self.assert_untouched()
        # Removing explicit fixture trust exercises real chain validation.
        with self.assertRaises(DeployError):
            deploy(self.new, self.destination, "dns.example.test", "127.0.0.1", timeout=1)
        self.assert_untouched()

    def test_success_publishes_exact_pair_preserves_metadata_and_checks_wire_identity(self):
        metadata = {name: (self.destination / name).stat() for name in self.before}
        observed = []
        def wire(expected, *args):
            observed.append(expected)
            self.assertEqual(fingerprint((self.destination / "fullchain.pem").read_bytes()), expected)
        with patch("tools.certificate_deploy.wait_served", side_effect=wire):
            result = deploy(self.new, self.destination, "dns.example.test", "127.0.0.1", **self.options)
        self.assertEqual(result["status"], "deployed")
        self.assertEqual(observed, [fingerprint(self.before["fullchain.pem"]), result["fingerprint_sha256"]])
        for name in self.before:
            target = self.destination / name
            self.assertEqual(target.read_bytes(), (self.new / name).read_bytes())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), stat.S_IMODE(metadata[name].st_mode))
            if hasattr(os, "getuid"):
                self.assertEqual((target.stat().st_uid, target.stat().st_gid), (metadata[name].st_uid, metadata[name].st_gid))

    def test_post_publish_failure_restores_exact_old_pair_then_verifies_old_identity(self):
        identities = []
        def wire(expected, *args):
            identities.append(expected)
            if len(identities) == 2:
                self.assertEqual((self.destination / "privkey.pem").read_bytes(), (self.new / "privkey.pem").read_bytes())
                raise DeployError("fixture new-certificate readback failure")
            self.assertEqual(fingerprint((self.destination / "fullchain.pem").read_bytes()), expected)
        with patch("tools.certificate_deploy.wait_served", side_effect=wire):
            with self.assertRaises(DeployError) as caught:
                deploy(self.new, self.destination, "dns.example.test", "127.0.0.1", **self.options)
        self.assertTrue(caught.exception.rollback_verified)
        self.assertEqual(identities[0], identities[2])
        self.assertEqual(len(identities), 3)
        self.assert_untouched()

    def test_failed_rollback_readback_is_explicit_not_success(self):
        with patch("tools.certificate_deploy.wait_served", side_effect=[None, DeployError("new"), DeployError("old")]):
            with self.assertRaises(DeployError) as caught:
                deploy(self.new, self.destination, "dns.example.test", "127.0.0.1", **self.options)
        self.assertIs(caught.exception.rollback_verified, False)
        self.assert_untouched()

    def test_real_tls_readback_verifies_chain_hostname_and_der_fingerprint(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.old / "fullchain.pem", self.old / "privkey.pem")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        failures = []
        def serve():
            try:
                for _ in range(2):
                    raw, _ = listener.accept()
                    raw.settimeout(3)
                    try:
                        with context.wrap_socket(raw, server_side=True):
                            pass
                    except OSError:
                        raw.close()  # Expected alert from wrong-hostname control.
            except BaseException as error:
                failures.append(type(error).__name__)
            finally:
                listener.close()
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            self.assertEqual(served_fingerprint("dns.example.test", "127.0.0.1", port, 3, self.ca),
                             fingerprint(self.before["fullchain.pem"]))
            with self.assertRaises(ssl.SSLCertVerificationError):
                served_fingerprint("wrong.example.test", "127.0.0.1", port, 3, self.ca)
        finally:
            listener.close()
            worker.join(6)
        self.assertFalse(worker.is_alive(), "fixture TLS listener did not stop")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
