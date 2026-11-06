"""Offline config contracts; public fixture IPs are not verified service origins."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.render import compile_config, write_new


# Public disposable fixture only; never a deployment credential.
LAB_PASSWORD_HASH = "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56"


class RenderContractTests(unittest.TestCase):
    def setUp(self):
        self.rules = {
            "domains": ["chatgpt.com", "claude.ai"],
            "excluded_zones": ["google.com", "microsoft.com", "local", "internal", "localhost"],
        }
        self.settings = {
            "own_zones": ["operator.example.net"],
            "doh_host": "dns.example.net",
            "relay_ipv4": "192.0.2.10",
            "client_ids": ["0123456789abcdef0123456789abcdef"],
            "upstream_dns": ["https://dns.example.org/dns-query"],
            "bootstrap_dns": ["1.1.1.1"],
            "admin_username": "labadmin",
            "admin_password_hash": LAB_PASSWORD_HASH,
        }
        self.origins = {"chatgpt.com": "1.1.1.1", "claude.ai": "8.8.8.8"}

    def render(self):
        return compile_config(self.rules, self.settings, self.origins)

    def test_checked_in_pilot_and_source_pins(self):
        root = Path(__file__).resolve().parents[1]
        rules = json.loads((root / "rules/pilot.json").read_text(encoding="utf-8"))
        compile_config(rules, self.settings, {host: "1.1.1.1" for host in rules["domains"]})
        sources = json.loads((root / "rules/sources.json").read_text(encoding="utf-8"))
        self.assertIn("proposal-only", sources["policy"])
        for source in sources["sources"]:
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
            self.assertIn("/blob/" + source["commit"] + "/", source["reference"])
            self.assertIn("license", source)
            self.assertNotEqual(source["use"], "import")

    def test_three_generated_host_sets_have_exact_parity(self):
        artifacts = self.render()
        dns_rules = artifacts["agh-conf/AdGuardHome.yaml"]["user_rules"]
        parsed_dns = [re.fullmatch(r"\|([^|]+)\|\$dnstype=(A|AAAA\|HTTPS\|SVCB),dnsrewrite=(.+)", rule) for rule in dns_rules]
        self.assertTrue(all(parsed_dns), dns_rules)
        dns_hosts = {match[1] for match in parsed_dns}
        haproxy = artifacts["haproxy.cfg"]
        relay_hosts = set(re.findall(r"^  acl host_\d+ req\.ssl_sni,lower -m str (\S+)$", haproxy, re.MULTILINE))
        tcp_rule = artifacts["compose.lab.json"]["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
        edge_hosts = set(re.findall(r"HostSNI\(`([^`]+)`\)", tcp_rule))
        expected = set(self.rules["domains"])
        self.assertEqual(dns_hosts, expected)
        self.assertEqual(relay_hosts, expected)
        self.assertEqual(edge_hosts, expected)
        self.assertEqual(tcp_rule, " || ".join(f"HostSNI(`{host}`)" for host in self.rules["domains"]))
        self.assertNotIn("*", tcp_rule)
        self.assertNotIn("HostSNIRegexp", tcp_rule)
        self.assertNotIn("-m end", haproxy)
        self.assertNotRegex(haproxy, r"(?m)^\s*(?:resolvers|server-template)\b")
        self.assertNotRegex(haproxy, r"\b(?:resolvers|resolve-prefer|init-addr)\b")
        self.assertEqual(set(re.findall(r"^  server fixed (\S+):443$", haproxy, re.MULTILINE)), set(self.origins.values()))
        self.assertIn("  default_backend denied\nbackend denied\n  tcp-request content reject\n", haproxy)
        for host in expected:
            self.assertEqual(sum(match[1] == host for match in parsed_dns), 2)
            self.assertIn(f"|{host}|$dnstype=A,dnsrewrite=NOERROR;A;192.0.2.10", dns_rules)
            self.assertIn(f"|{host}|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;", dns_rules)
            self.assertNotIn("child." + host, dns_hosts | relay_hosts | edge_hosts)

    def test_doh_uses_actual_insecure_enabled_schema_and_client_ids(self):
        agh = self.render()["agh-conf/AdGuardHome.yaml"]
        self.assertIs(agh["http"]["doh"]["insecure_enabled"], True)
        self.assertNotIn("insecure", agh["http"]["doh"])
        self.assertEqual(agh["dns"]["allowed_clients"], self.settings["client_ids"])
        self.assertIs(agh["dns"]["serve_plain_dns"], True)
        self.assertNotIn("ports", self.render()["compose.lab.json"]["services"]["dns"])
        self.assertNotIn(self.settings["relay_ipv4"], agh["dns"]["allowed_clients"])
        self.assertNotIn("0.0.0.0/0", agh["dns"]["allowed_clients"])
        self.assertNotIn("127.0.0.1", agh["dns"]["allowed_clients"])

    def test_rejects_invalid_excluded_and_own_domains(self):
        bad_domains = [
            "*.chatgpt.com", ".chatgpt.com", "ChatGPT.com", "chatgpt.com.",
            "https://chatgpt.com", "chatgpt.com:443", "1.1.1.1", "localhost",
            "printer.local", "printer.internal", "google.com", "ai.google.com",
            "microsoft.com", "copilot.microsoft.com", "operator.example.net",
            "child.operator.example.net", "dns.example.net", "child.dns.example.net",
        ]
        for domain in bad_domains:
            with self.subTest(domain=domain):
                rules = copy.deepcopy(self.rules)
                rules["domains"] = [domain]
                with self.assertRaises(ValueError):
                    compile_config(rules, self.settings, {domain: "1.1.1.1"})

    def test_native_admin_account_is_required_and_confined_to_agh_config(self):
        artifacts = self.render()
        self.assertEqual(artifacts["agh-conf/AdGuardHome.yaml"]["users"], [
            {"name": "labadmin", "password": LAB_PASSWORD_HASH},
        ])
        for name, artifact in artifacts.items():
            if name != "agh-conf/AdGuardHome.yaml":
                self.assertNotIn(LAB_PASSWORD_HASH, json.dumps(artifact), name)
        for key in ("admin_username", "admin_password_hash"):
            with self.subTest(missing=key):
                settings = dict(self.settings)
                del settings[key]
                with self.assertRaises((KeyError, ValueError)):
                    compile_config(self.rules, settings, self.origins)

    def test_invalid_admin_input_is_rejected_without_echoing_credentials(self):
        invalid = {
            "admin_username": ["", "Admin", "admin\nusers: []", "../admin", "a" * 33],
            "admin_password_hash": ["", "lab-only-change-me", "sha256:password", LAB_PASSWORD_HASH[:-1], LAB_PASSWORD_HASH.replace("$10$", "$03$")],
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(field=key, empty=not value):
                    with self.assertRaises(ValueError) as error:
                        compile_config(self.rules, {**self.settings, key: value}, self.origins)
                    if value:
                        self.assertNotIn(value, str(error.exception))

    def test_dns_network_has_only_dns_and_edge_and_limits_are_attached(self):
        services = self.render()["compose.lab.json"]["services"]
        members = {name for name, service in services.items() if "dns" in service.get("networks", ["default"])}
        self.assertEqual(members, {"dns", "edge"})
        self.assertNotIn("default", services["dns"]["networks"])
        labels = services["dns"]["labels"]
        chain = labels["traefik.http.routers.sd-doh.middlewares"].split(",")
        self.assertEqual(len(chain), 3)
        host, rate, flight = chain
        prefix = "traefik.http.middlewares."
        self.assertEqual(labels[prefix + host + ".headers.customrequestheaders.Host"], self.settings["doh_host"])
        for name, kind in ((rate, "ratelimit"), (flight, "inflightreq")):
            self.assertEqual(labels[prefix + name + "." + kind + ".sourcecriterion.requesthost"], "true")
        self.assertEqual(labels["traefik.http.routers.sd-doh.observability.accesslogs"], "false")

    def test_publishes_complete_new_directory_with_exact_content(self):
        artifacts = self.render()
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "candidate"
            write_new(artifacts, out)
            self.assertEqual({str(path.relative_to(out)).replace("\\", "/") for path in out.rglob("*") if path.is_file()}, set(artifacts))
            for name, value in artifacts.items():
                content = (out / name).read_text(encoding="utf-8")
                self.assertEqual(content if isinstance(value, str) else json.loads(content), value)
            self.assertEqual(list(Path(folder).iterdir()), [out])

    def test_existing_output_is_rejected_and_accepted_bytes_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "accepted"
            write_new(self.render(), out)
            sentinel = out / "do-not-touch"
            sentinel.write_bytes(b"accepted\x00generation\xff")
            before = {path.relative_to(out): path.read_bytes() for path in out.rglob("*") if path.is_file()}
            with self.assertRaises(FileExistsError):
                write_new({"partial.txt": "new"}, out)
            self.assertEqual({path.relative_to(out): path.read_bytes() for path in out.rglob("*") if path.is_file()}, before)
            existing_file = Path(folder) / "occupied-file"
            existing_file.write_bytes(b"also-accepted")
            with self.assertRaises(FileExistsError):
                write_new(self.render(), existing_file)
            self.assertEqual(existing_file.read_bytes(), b"also-accepted")

    def test_write_failure_leaves_no_candidate_or_staging_and_preserves_accepted(self):
        artifacts = self.render()
        real_write = Path.write_text
        writes = []

        def fail_second_write(path, *args, **kwargs):
            writes.append(path)
            if len(writes) == 2:
                self.assertTrue(writes[0].is_file())
                raise OSError("simulated storage failure")
            return real_write(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            accepted = root / "accepted"
            write_new(artifacts, accepted)
            before = {path.relative_to(accepted): path.read_bytes() for path in accepted.rglob("*") if path.is_file()}
            candidate = root / "candidate"
            with patch.object(Path, "write_text", fail_second_write):
                with self.assertRaisesRegex(OSError, "simulated storage failure"):
                    write_new(artifacts, candidate)
            self.assertEqual(len(writes), 2)
            self.assertFalse(candidate.exists())
            self.assertEqual(list(root.iterdir()), [accepted])
            self.assertEqual({path.relative_to(accepted): path.read_bytes() for path in accepted.rglob("*") if path.is_file()}, before)

    def test_cli_publishes_once_and_reports_errors_without_credentials(self):
        renderer = Path(__file__).resolve().parents[1] / "tools/render.py"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, value in (("rules", self.rules), ("settings", self.settings), ("origins", self.origins)):
                (root / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
            out = root / "output"
            command = [sys.executable, str(renderer), "--rules", str(root / "rules.json"), "--settings", str(root / "settings.json"), "--origins", str(root / "origins.json"), "--out", str(out)]
            success = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(success.returncode, 0, success.stderr)
            before = {path.relative_to(out): path.read_bytes() for path in out.rglob("*") if path.is_file()}
            refused = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual({path.relative_to(out): path.read_bytes() for path in out.rglob("*") if path.is_file()}, before)
            invalid_settings = {**self.settings, "admin_password_hash": "plaintext-secret-must-not-be-echoed"}
            (root / "settings.json").write_text(json.dumps(invalid_settings), encoding="utf-8")
            command[-1] = str(root / "invalid-output")
            invalid = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertFalse((root / "invalid-output").exists())
            for result in (success, refused, invalid):
                output = result.stdout + result.stderr
                for secret in (LAB_PASSWORD_HASH, self.settings["client_ids"][0], invalid_settings["admin_password_hash"]):
                    self.assertNotIn(secret, output)

    def test_rejects_nonpublic_or_noncanonical_origins(self):
        for address in [
            "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "224.0.0.1", "239.1.2.3",
            "255.255.255.255", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "::1", "2606:4700:4700::1111", "::ffff:1.1.1.1", "01.1.1.1",
            "chatgpt.com", "1.1.1.1:443",
        ]:
            with self.subTest(address=address):
                origins = {**self.origins, "chatgpt.com": address}
                with self.assertRaises(ValueError):
                    compile_config(self.rules, self.settings, origins)

    def test_rejects_missing_and_extra_origins(self):
        for origins in [{"chatgpt.com": "1.1.1.1"}, {**self.origins, "other.example.org": "1.1.1.1"}]:
            with self.subTest(origins=origins):
                with self.assertRaises(ValueError):
                    compile_config(self.rules, self.settings, origins)

    def test_rejects_own_ingress_and_provider_service(self):
        for address in ["168.63.129.16", "192.0.2.10"]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                compile_config(self.rules, self.settings, {**self.origins, "chatgpt.com": address})
        with self.assertRaises(ValueError):
            compile_config(self.rules, {**self.settings, "relay_ipv4": "1.1.1.1"}, self.origins)
        with self.assertRaises(ValueError):
            compile_config(self.rules, {**self.settings, "own_public_ipv4": ["1.1.1.1"]}, self.origins)

    def test_rejects_empty_unsorted_duplicate_or_oversized_domains(self):
        for domains in [[], ["claude.ai", "chatgpt.com"], ["chatgpt.com", "chatgpt.com"], sorted(f"host{i:02d}.example.org" for i in range(21))]:
            with self.subTest(domains=domains):
                rules = {**self.rules, "domains": domains}
                with self.assertRaises(ValueError):
                    compile_config(rules, self.settings, {host: "1.1.1.1" for host in domains})

    def test_rejects_missing_duplicate_or_invalid_client_ids(self):
        valid = self.settings["client_ids"][0]
        for ids in [[], [valid, valid], ["short"], ["A" * 32], ["g" * 32], ["a" * 31], ["a" * 65], ["127.0.0.1"], ["0.0.0.0/0"]]:
            with self.subTest(ids=ids):
                settings = {**self.settings, "client_ids": ids}
                with self.assertRaises(ValueError):
                    compile_config(self.rules, settings, self.origins)

    def test_generation_is_deterministic_and_does_not_mutate_inputs(self):
        before = copy.deepcopy((self.rules, self.settings, self.origins))
        first = self.render()
        self.assertEqual(first, self.render())
        self.assertEqual((self.rules, self.settings, self.origins), before)
        self.assertEqual(first["snapshot.json"]["domains"], self.rules["domains"])
        self.assertEqual(first["snapshot.json"]["origins"], self.origins)

    def test_native_fixture_setup_error_reaps_started_upstream_thread(self):
        # Real child process and real ephemeral UDP thread. Invalid rules fail
        # after thread.start but before Popen: exiting proves finally reaped it.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "rules").mkdir()
            (root / "rules/pilot.json").write_text(json.dumps({**self.rules, "domains": ["*.chatgpt.com"]}))
            (root / "password").write_text("lab-only-change-me")
            code = "\n".join([
                "import sys", "from pathlib import Path",
                "sys.path.insert(0, sys.argv[1])", "import test_native_agh as fixture",
                "fixture.ROOT = Path(sys.argv[2])",
                "sys.argv = ['fixture', '--binary', 'not-started', '--admin-password-file', str(fixture.ROOT / 'password')]",
                "fixture.main()",
            ])
            result = subprocess.run([sys.executable, "-c", code, str(Path(__file__).resolve().parents[1] / "tools"), folder], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid exact domain", result.stderr)


if __name__ == "__main__":
    unittest.main()
