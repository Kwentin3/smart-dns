"""Fixed private Fancy GEO adapter, with real Git/projection contracts."""
import copy
import hashlib
import json
import unittest

from tools.registry import FANCY_SOURCE_ID, SOURCE_REPOSITORIES, RegistryError, fetch_snapshot, normalize_rules

PIN, ROOT, LISTS, INDEX = (character * 40 for character in "abcd")
REPOSITORY = SOURCE_REPOSITORIES[FANCY_SOURCE_ID]
API = REPOSITORY.replace("https://github.com/", "https://api.github.com/repos/")
RAW = REPOSITORY.replace("https://github.com/", "https://raw.githubusercontent.com/")
MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy.\nSynthetic license fixture.\n"


def fancy_fixture(document=None, license_text=MIT):
    if document is None:
        document = {"version": 3, "rules": [{"domain": ["login.media.example", "login.media.example"],
                                            "domain_suffix": ["media.example", "assistant.example"]}]}
    body = json.dumps(document)

    def blob(path, value):
        data = value.encode("utf-8")
        sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        return {"path": path, "type": "blob", "sha": sha, "size": len(data)}

    def tree(entries):
        return json.dumps({"tree": entries, "truncated": False})

    return {
        API + "/commits/main": json.dumps({"sha": PIN, "commit": {"tree": {"sha": ROOT}}}),
        API + "/git/trees/" + ROOT: tree([
            {"path": "lists", "type": "tree", "sha": LISTS}, blob("LICENSE", license_text)]),
        API + "/git/trees/" + LISTS: tree([{"path": "geoblock-sing-box", "type": "tree", "sha": INDEX}]),
        API + "/git/trees/" + INDEX: tree([blob("full.json", body), blob("unrelated.json", "{}")]),
        RAW + "/" + PIN + "/lists/geoblock-sing-box/full.json": body,
        RAW + "/" + PIN + "/LICENSE": license_text,
    }


class FancyRegistryTests(unittest.TestCase):
    def test_fixed_path_native_exact_suffixes_and_private_license_provenance(self):
        replies, calls = fancy_fixture(), []

        def fetch(url):
            calls.append(url)
            return replies[url]

        snapshot = fetch_snapshot(["community-geo"], fetch=fetch, source_id=FANCY_SOURCE_ID)
        self.assertEqual(set(snapshot["index"]), {"community-geo"})
        entry = snapshot["index"]["community-geo"]
        self.assertEqual(entry["path"], "lists/geoblock-sing-box/full.json")
        self.assertEqual(entry["kind"], "category")
        definition = snapshot["definitions"]["community-geo"]
        self.assertEqual(definition["exact"], ["login.media.example"])
        self.assertEqual(definition["suffix"], ["assistant.example", "media.example"])
        self.assertEqual(definition["source_blob"], entry["blob_sha"])
        self.assertEqual(definition["sha256"], hashlib.sha256(definition["raw"].encode()).hexdigest())
        self.assertFalse(definition["partial"])
        self.assertEqual(definition["unsupported"], [])
        source = snapshot["source"]
        self.assertEqual((source["repository"], source["branch"], source["commit"]), (REPOSITORY, "main", PIN))
        self.assertEqual(source["index_tree"], INDEX)
        self.assertEqual(source["license"], "MIT")
        self.assertEqual(source["license_text"], MIT)
        self.assertEqual(source["license_reference"], REPOSITORY + "/blob/" + PIN + "/LICENSE")
        self.assertEqual(source["license_commit"], PIN)
        self.assertTrue(source["private_only"])
        self.assertIn("third-party", source["license_note"])
        self.assertFalse(any("unrelated.json" in url for url in calls))

    def test_git_blob_verification_rejects_changed_rule_and_license_bodies(self):
        for path, forged in (("lists/geoblock-sing-box/full.json", '{"version":3,"rules":[]}'),
                             ("LICENSE", MIT + "Unverified change\n")):
            with self.subTest(path=path):
                replies = fancy_fixture()
                replies[RAW + "/" + PIN + "/" + path] = forged
                with self.assertRaisesRegex(RegistryError, "blob differs"):
                    fetch_snapshot(["community-geo"], fetch=replies.__getitem__, source_id=FANCY_SOURCE_ID)

    def test_cached_raw_is_revalidated_and_source_inferred(self):
        replies = fancy_fixture()
        previous = fetch_snapshot(["community-geo"], fetch=replies.__getitem__, source_id=FANCY_SOURCE_ID)
        before = copy.deepcopy(previous)
        del replies[RAW + "/" + PIN + "/lists/geoblock-sing-box/full.json"]
        self.assertEqual(fetch_snapshot(["community-geo"], previous, replies.__getitem__), before)
        previous["definitions"]["community-geo"]["raw"] = '{"version":3,"rules":[]}'
        replies[RAW + "/" + PIN + "/lists/geoblock-sing-box/full.json"] = previous["definitions"]["community-geo"]["raw"]
        with self.assertRaisesRegex(RegistryError, "blob differs"):
            fetch_snapshot(["community-geo"], previous, replies.__getitem__)

    def test_version_three_quarantines_compound_rules_and_unknown_fields(self):
        compound = {"domain": ["restricted.example"], "port": [443]}
        document = {"version": 3, "rules": [{"domain": ["literal.example"]}, compound,
                    {"domain_regex": "^unsupported$"}]}
        result = fetch_snapshot(["community-geo"], fetch=fancy_fixture(document).__getitem__, source_id=FANCY_SOURCE_ID)
        definition = result["definitions"]["community-geo"]
        self.assertEqual(definition["exact"], ["literal.example"])
        self.assertEqual(definition["suffix"], [])
        self.assertTrue(definition["partial"])
        self.assertIn(compound, [item["value"] for item in definition["unsupported"]])
        document["unknown_semantics"] = True
        result = normalize_rules(document)
        self.assertEqual(result["exact"], [])
        self.assertTrue(result["partial"])
        self.assertEqual(result["unsupported"][0]["field"], "document")

    def test_unknown_or_noninteger_version_rejected(self):
        for version in (0, 1, 4, True, "3", None):
            with self.subTest(version=version), self.assertRaisesRegex(RegistryError, "version"):
                fetch_snapshot(["community-geo"], fetch=fancy_fixture({"version": version, "rules": []}).__getitem__,
                               source_id=FANCY_SOURCE_ID)

    def test_missing_selected_or_truncated_tree_preserves_accepted(self):
        replies = fancy_fixture()
        previous = fetch_snapshot(["community-geo"], fetch=replies.__getitem__, source_id=FANCY_SOURCE_ID)
        before = copy.deepcopy(previous)
        with self.assertRaisesRegex(RegistryError, "missing upstream"):
            fetch_snapshot(["unrelated"], previous, replies.__getitem__)
        for sha in (ROOT, LISTS, INDEX):
            broken = dict(replies)
            broken[API + "/git/trees/" + sha] = json.dumps({"tree": [], "truncated": True})
            with self.subTest(sha=sha), self.assertRaisesRegex(RegistryError, "truncated"):
                fetch_snapshot(["community-geo"], previous, broken.__getitem__)
        self.assertEqual(previous, before)


if __name__ == "__main__":
    unittest.main()
