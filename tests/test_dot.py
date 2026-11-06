"""DoT stream framing must tolerate ordinary fragmented TCP reads."""
import unittest
import copy
from pathlib import Path
import sys

# Probe scripts share the CLI tools directory as their import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tools.probe_dot import receive_exact, PASSWORD_HASH
from tools.render import compile_config


class FragmentedStream:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def recv(self, size):
        return next(self.chunks, b"")


class DotFramingTests(unittest.TestCase):
    def test_fragmented_length_and_payload_are_read_completely(self):
        stream = FragmentedStream([b"\0", b"\x03", b"a", b"bc"])
        self.assertEqual(receive_exact(stream, 2), b"\0\x03")
        self.assertEqual(receive_exact(stream, 3), b"abc")

    def test_eof_mid_frame_fails_instead_of_accepting_partial_dns(self):
        with self.assertRaises(EOFError):
            receive_exact(FragmentedStream([b"a"]), 3)


class NativeDotConfigTests(unittest.TestCase):
    def setUp(self):
        self.settings = {"doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32],
                         "own_zones": ["example.net"], "admin_username": "labadmin", "admin_password_hash": PASSWORD_HASH,
                         "upstream_dns": ["127.0.0.1:15354"], "bootstrap_dns": []}
        self.dot = {"server_name": "dns.example.net", "certificate_path": "/fixture/certificate.pem", "private_key_path": "/fixture/key.pem"}

    def config(self, settings):
        return compile_config({"domains": ["chatgpt.com"], "excluded_zones": []}, settings, {"chatgpt.com": "1.1.1.1"})["agh-conf/AdGuardHome.yaml"]

    def test_optional_dot_enables_native_encryption_without_changing_admission(self):
        before = self.config(self.settings)
        self.assertFalse(before["tls"]["enabled"])
        self.assertTrue(before["dns"]["serve_plain_dns"])
        after = self.config(dict(self.settings, dot=self.dot))
        self.assertTrue(after["tls"]["enabled"])
        self.assertTrue(after["tls"]["strict_sni_check"])
        self.assertEqual(after["tls"]["server_name"], self.settings["doh_host"])
        self.assertEqual(after["tls"]["port_dns_over_tls"], 853)
        self.assertEqual(after["tls"]["port_https"], 0)
        self.assertEqual(after["tls"]["port_dns_over_quic"], 0)
        self.assertFalse(after["dns"]["serve_plain_dns"])
        self.assertEqual(after["dns"]["allowed_clients"], before["dns"]["allowed_clients"])
        self.assertEqual(after["users"], before["users"])

    def test_mismatched_base_name_and_unusable_certificate_paths_rejected(self):
        variants = [{"server_name": "other.example.net"}, {"server_name": "*.dns.example.net"},
                    {"certificate_path": ""}, {"private_key_path": ""},
                    {"certificate_path": "bad\0path"}, {"private_key_path": None}]
        for change in variants:
            dot = copy.deepcopy(self.dot)
            dot.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.config(dict(self.settings, dot=dot))


if __name__ == "__main__":
    unittest.main()
