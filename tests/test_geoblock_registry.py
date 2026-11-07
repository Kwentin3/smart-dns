"""Synthetic GEO corpus: real Git traversal and parsing, transport only replaced."""
import copy
import hashlib
import json
import unittest

from tools.registry import GEO_SOURCE_ID, SOURCE_REPOSITORIES, RegistryError, fetch_snapshot

PIN, ROOT, CATEGORIES, SERVICES = (character * 40 for character in "abcd")
REPOSITORY = SOURCE_REPOSITORIES[GEO_SOURCE_ID]
API = REPOSITORY.replace("https://github.com/", "https://api.github.com/repos/")
RAW = REPOSITORY.replace("https://github.com/", "https://raw.githubusercontent.com/")


def fixture(geoblock="# Synthetic fixture only\nmedia.example\nlogin.media.example # dependency\nmedia.example\n\n",
            google_ai="assistant.example\napi.assistant.example\n"):
    def blob(path, body):
        data = body.encode("utf-8")
        sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        return {"path": path, "type": "blob", "sha": sha, "size": len(data)}
    def tree(entries):
        return json.dumps({"tree": entries, "truncated": False})
    return {
        API + "/commits/main": json.dumps({"sha": PIN, "commit": {"tree": {"sha": ROOT}}}),
        API + "/git/trees/" + ROOT: tree([
            {"path": "Categories", "type": "tree", "sha": CATEGORIES},
            {"path": "Services", "type": "tree", "sha": SERVICES}]),
        API + "/git/trees/" + CATEGORIES: tree([blob("geoblock.lst", geoblock)]),
        API + "/git/trees/" + SERVICES: tree([blob("google_ai.lst", google_ai)]),
        RAW + "/" + PIN + "/Categories/geoblock.lst": geoblock,
        RAW + "/" + PIN + "/Services/google_ai.lst": google_ai,
    }


class GeoBlockRegistryTests(unittest.TestCase):
    def test_both_known_paths_are_native_suffixes_with_private_provenance(self):
        result = fetch_snapshot(["geoblock", "google-ai"], fetch=fixture().__getitem__, source_id=GEO_SOURCE_ID)
        self.assertEqual(set(result["index"]), {"geoblock", "google-ai"})
        self.assertEqual(result["index"]["google-ai"]["path"], "Services/google_ai.lst")
        self.assertEqual(result["definitions"]["geoblock"]["suffix"], ["login.media.example", "media.example"])
        self.assertEqual(result["definitions"]["google-ai"]["suffix"], ["api.assistant.example", "assistant.example"])
        for definition in result["definitions"].values():
            self.assertEqual(definition["exact"], [])
            self.assertEqual(definition["unsupported"], [])
            self.assertFalse(definition["partial"])
            self.assertEqual(definition["sha256"], hashlib.sha256(definition["raw"].encode()).hexdigest())
        source = result["source"]
        self.assertEqual((source["repository"], source["branch"], source["commit"]), (REPOSITORY, "main", PIN))
        self.assertEqual(source["index_tree"], ROOT)
        self.assertTrue(source["private_only"])
        self.assertIsNone(source["license"])
        self.assertIsNone(source["license_reference"])
        self.assertIn("private-only", source["license_note"])

    def test_unselected_bodies_not_fetched_and_cached_source_inferred(self):
        replies, calls = fixture(), []
        def fetch(url):
            calls.append(url)
            return replies[url]
        first = fetch_snapshot(["geoblock"], fetch=fetch, source_id=GEO_SOURCE_ID)
        self.assertEqual(set(first["definitions"]), {"geoblock"})
        self.assertFalse(any(url.endswith("google_ai.lst") for url in calls))
        del replies[RAW + "/" + PIN + "/Categories/geoblock.lst"]
        before = copy.deepcopy(first)
        self.assertEqual(fetch_snapshot(["geoblock"], first, fetch), before)
        self.assertEqual(first, before)

    def test_invalid_literal_rejects_whole_fetch_even_with_valid_git_hash(self):
        for bad in ("*.bad.example", "domain:bad.example", "UPPER.example", "1.1.1.1", "local", "media.example other.example", ".bad.example", "bad.example/route"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RegistryError, "invalid literal"):
                fetch_snapshot(["geoblock", "google-ai"], fetch=fixture(google_ai=bad).__getitem__, source_id=GEO_SOURCE_ID)

    def test_changed_body_or_cache_must_match_pinned_git_blob(self):
        replies = fixture()
        first = fetch_snapshot(["geoblock"], fetch=replies.__getitem__, source_id=GEO_SOURCE_ID)
        first["definitions"]["geoblock"]["raw"] = "forged.example\n"
        replies[RAW + "/" + PIN + "/Categories/geoblock.lst"] = "forged.example\n"
        before = copy.deepcopy(first)
        with self.assertRaisesRegex(RegistryError, "blob differs"):
            fetch_snapshot(["geoblock"], first, replies.__getitem__)
        self.assertEqual(first, before)

    def test_missing_selected_or_truncated_tree_preserves_accepted(self):
        replies = fixture()
        accepted = fetch_snapshot(["geoblock"], fetch=replies.__getitem__, source_id=GEO_SOURCE_ID)
        before = copy.deepcopy(accepted)
        with self.assertRaisesRegex(RegistryError, "missing upstream"):
            fetch_snapshot(["absent"], accepted, replies.__getitem__)
        for sha in (ROOT, CATEGORIES, SERVICES):
            broken = dict(replies)
            broken[API + "/git/trees/" + sha] = json.dumps({"truncated": True, "tree": []})
            with self.subTest(sha=sha), self.assertRaisesRegex(RegistryError, "truncated"):
                fetch_snapshot(["geoblock"], accepted, broken.__getitem__)
        self.assertEqual(accepted, before)

    def test_foreign_source_and_unknown_profile_rejected_before_fetch(self):
        calls = []
        def fetch(url):
            calls.append(url)
            raise OSError("must not reach transport")
        cases = [({"source": {"repository": "https://github.com/unknown/corpus"}}, None),
                 ({"source": {"repository": SOURCE_REPOSITORIES["metacubex-sing"]}}, GEO_SOURCE_ID),
                 ({"source": {"repository": REPOSITORY}}, "metacubex-sing"),
                 (None, "unknown")]
        for previous, source_id in cases:
            with self.subTest(source_id=source_id), self.assertRaises(RegistryError):
                fetch_snapshot([], previous, fetch, source_id=source_id)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
