"""Real JSON normalization and Git blob binding, with only transport replaced."""
import copy
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from tools.registry import API, RAW, API_LIMIT, RAW_LIMIT, RegistryError, fetch_snapshot, fetch_url, normalize_rules

PIN, MASTER, ROOT, GEO, INDEX, LICENSE_ROOT = (character * 40 for character in "abcdef")
LICENSE_TEXT = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\nFixture license only\n"


def git_blob(body):
    data = body.encode()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def fixture():
    definitions = {
        "openai": json.dumps({"version": 2, "rules": [{"domain": "auth.openai.com", "domain_suffix": ["openai.com"], "domain_regex": "^example$"}]}),
        "spotify": json.dumps({"version": 2, "rules": [{"domain_suffix": ["spotify.com"]}]}),
        "category-media": json.dumps({"version": 2, "rules": [{"domain_suffix": ["media.example"]}]}),
    }
    tree = lambda entries: json.dumps({"tree": entries, "truncated": False})
    replies = {
        API + "/commits/sing": json.dumps({"sha": PIN, "commit": {"tree": {"sha": ROOT}}}),
        API + "/git/trees/" + ROOT: tree([{"path": "geo", "type": "tree", "sha": GEO}]),
        API + "/git/trees/" + GEO: tree([{"path": "geosite", "type": "tree", "sha": INDEX}]),
        API + "/git/trees/" + INDEX: tree([{"path": key + ".json", "type": "blob", "sha": git_blob(value), "size": len(value.encode())} for key, value in definitions.items()]),
        API + "/commits/master": json.dumps({"sha": MASTER, "commit": {"tree": {"sha": LICENSE_ROOT}}}),
        API + "/git/trees/" + LICENSE_ROOT: tree([{"path": "LICENSE", "type": "blob", "sha": git_blob(LICENSE_TEXT)}]),
        RAW + "/" + MASTER + "/LICENSE": LICENSE_TEXT,
    }
    replies.update({RAW + "/" + PIN + "/geo/geosite/" + key + ".json": value for key, value in definitions.items()})
    return replies


class RegistryTests(unittest.TestCase):
    def test_native_matcher_types_scalar_lists_and_unsupported_are_preserved(self):
        result = normalize_rules({"version": 2, "rules": [{"domain": ["auth.openai.com", "auth.openai.com", "*.bad.example"],
            "domain_suffix": "openai.com", "domain_regex": ["^one$", "^two$"], "domain_keyword": "unsafe"}]})
        self.assertEqual(result["exact"], ["auth.openai.com"])
        self.assertEqual(result["suffix"], ["openai.com"])
        self.assertTrue(result["partial"])
        self.assertEqual({item["field"] for item in result["unsupported"]}, {"domain", "domain_regex", "domain_keyword"})

    def test_compound_invert_and_unknown_predicates_never_expand_to_domains(self):
        for rule in ({"domain_suffix": ["example.com"], "invert": True},
                     {"domain": ["example.com"], "query_type": ["A"]},
                     {"type": "logical", "mode": "and", "rules": [{"domain": ["example.com"]}]}):
            with self.subTest(rule=rule):
                result = normalize_rules({"version": 2, "rules": [rule]})
                self.assertEqual((result["exact"], result["suffix"]), ([], []))
                self.assertEqual(result["unsupported"][0]["value"], rule)
                self.assertTrue(result["partial"])
        result = normalize_rules({"version": 2, "rules": [{"domain": ["example.com"]}], "unknown_semantics": True})
        self.assertEqual(result["exact"], [])
        self.assertTrue(result["partial"])

    def test_full_index_only_selected_body_and_revalidated_cache_survive_old_pin_loss(self):
        replies, calls = fixture(), []
        def fetch(url):
            calls.append(url)
            return replies[url]
        first = fetch_snapshot(["openai"], fetch=fetch)
        self.assertEqual(set(first["index"]), {"openai", "spotify", "category-media"})
        self.assertEqual(first["index"]["category-media"]["kind"], "category")
        self.assertEqual(set(first["definitions"]), {"openai"})
        self.assertFalse(any(url.endswith("spotify.json") for url in calls))
        self.assertEqual(first["source"]["license_commit"], MASTER)
        self.assertEqual(first["source"]["license_text"], LICENSE_TEXT)
        self.assertNotEqual(first["source"]["license_commit"], first["source"]["commit"])
        before = copy.deepcopy(first)
        del replies[RAW + "/" + PIN + "/geo/geosite/openai.json"]
        second = fetch_snapshot(["openai"], first, fetch)
        self.assertEqual(second, first)
        self.assertEqual(first, before)
        first["definitions"]["openai"]["raw"] = "tampered accepted cache"
        with self.assertRaises(RegistryError):
            fetch_snapshot(["openai"], first, fetch)

    def test_selected_blob_mutation_rejected_even_when_json_is_well_formed(self):
        replies = fixture()
        replies[RAW + "/" + PIN + "/geo/geosite/openai.json"] = json.dumps({"version": 2, "rules": [{"domain_suffix": ["evil.example"]}]})
        with self.assertRaisesRegex(RegistryError, "blob differs"):
            fetch_snapshot(["openai"], fetch=replies.__getitem__)

    def test_failure_does_not_mutate_accepted_or_return_partial_index(self):
        replies = fixture()
        accepted = fetch_snapshot(["openai"], fetch=replies.__getitem__)
        before = copy.deepcopy(accepted)
        for selected in (["missing-service"], ["openai", "spotify"]):
            def unavailable(url):
                if url.endswith("spotify.json"):
                    raise OSError("unavailable")
                return replies[url]
            with self.assertRaises(RegistryError):
                fetch_snapshot(selected, accepted, unavailable)
            self.assertEqual(accepted, before)
        replies[API + "/git/trees/" + INDEX] = json.dumps({"truncated": True, "tree": []})
        with self.assertRaisesRegex(RegistryError, "truncated"):
            fetch_snapshot([], accepted, replies.__getitem__)
        self.assertEqual(accepted, before)

    def test_limits_and_bad_schema_are_explicit(self):
        with self.assertRaises(RegistryError):
            fetch_snapshot(["service" + str(i) for i in range(65)], fetch=lambda _: self.fail("must refuse before network"))
        with self.assertRaises(RegistryError):
            fetch_snapshot(["openai", "openai"], fetch=lambda _: self.fail("must refuse before network"))
        with self.assertRaises(RegistryError):
            fetch_snapshot([], fetch=lambda _: b"x" * (API_LIMIT + 1))
        for document in ({"version": 1, "rules": []}, {"version": 2, "rules": {}}, {"version": 2, "rules": ["text"]}):
            with self.subTest(document=document), self.assertRaises(RegistryError):
                normalize_rules(document)
        result = normalize_rules({"version": 2, "rules": [{"domain_suffix": ["adult", "1.1.1.1", "UPPER.example"]}]})
        self.assertEqual(result["suffix"], [])
        self.assertEqual(len(result["unsupported"]), 3)

    def test_transport_bounds_and_token_never_go_to_raw_host(self):
        requests = []
        def open_request(request, **kwargs):
            requests.append(request)
            return io.BytesIO(b"{}")
        with patch.dict("os.environ", {"GITHUB_TOKEN": "synthetic-token"}), patch("tools.registry.urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = open_request
            fetch_url(API + "/commits/sing")
            fetch_url(RAW + "/" + PIN + "/geo/geosite/openai.json")
            self.assertEqual(requests[0].get_header("Authorization"), "Bearer synthetic-token")
            self.assertIsNone(requests[1].get_header("Authorization"))
            opener.return_value.open.side_effect = lambda *args, **kwargs: io.BytesIO(b"x" * (RAW_LIMIT + 1))
            with self.assertRaises(RegistryError):
                fetch_url(RAW + "/" + PIN + "/geo/geosite/openai.json")
        for url in ("http://api.github.com/x", "https://api.github.com.evil.example/x", "https://user:password@api.github.com/x"):
            with self.subTest(url=url), self.assertRaises(RegistryError):
                fetch_url(url)


if __name__ == "__main__":
    unittest.main()
