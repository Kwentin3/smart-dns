"""Read an upstream-generated service index and selected JSON definitions only.

No activation, local writes, Geosite parser or runtime DNS. Callers retain the
accepted snapshot on any error. Country/category entries are not geoblock proof.
"""
import copy
import hashlib
import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request

REPOSITORY = "https://github.com/MetaCubeX/meta-rules-dat"
API = "https://api.github.com/repos/MetaCubeX/meta-rules-dat"
RAW = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
BRANCH = "sing"
GEO_SOURCE_ID = "itdog-geoblock"
FANCY_SOURCE_ID = "russia-fancy-geo"
SOURCE_REPOSITORIES = {
    "metacubex-sing": REPOSITORY,
    GEO_SOURCE_ID: "https://github.com/itdoginfo/allow-domains",
    FANCY_SOURCE_ID: "https://github.com/Noktomezo/RussiaFancyLists",
}
API_LIMIT, RAW_LIMIT, MAX_SELECTED = 2 * 1024 * 1024, 1024 * 1024, 64


class RegistryError(ValueError):
    """Fixed diagnostics without request headers, tokens or response bodies."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def fetch_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in ("api.github.com", "raw.githubusercontent.com"):
        raise RegistryError("unexpected registry transport host")
    limit = API_LIMIT if parsed.netloc == "api.github.com" else RAW_LIMIT
    headers = {"User-Agent": "smart-dns-registry", "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and parsed.netloc == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            data = response.read(limit + 1)
    except Exception:
        raise RegistryError("registry fetch failed; accepted snapshot is unchanged") from None
    if len(data) > limit:
        raise RegistryError("registry response exceeds size limit")
    return data


def _sha(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise RegistryError("immutable registry SHA required")
    return value


def _literal(value):
    if not isinstance(value, str) or value != value.lower() or not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    if len(labels) < 2 or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def normalize_rules(document):
    """Keep native exact/suffix meaning; quarantine unsupported predicates.

    Domain matcher fields are OR alternatives. A non-domain condition or logical
    wrapper may narrow them, so such a whole rule must never become a broad list.
    """
    if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] not in (2, 3) or not isinstance(document.get("rules"), list):
        raise RegistryError("expected Sing-box version 2 or 3 rules array")
    exact, suffix, unsupported = set(), set(), []
    if set(document) - {"version", "rules"}:
        return {"exact": [], "suffix": [], "unsupported": [{"field": "document", "value": copy.deepcopy(document),
                "reason": "unknown document fields; entire document quarantined"}], "partial": True}
    for rule in document["rules"]:
        if not isinstance(rule, dict):
            raise RegistryError("registry rule must be an object")
        fields = set(rule) - {"type"}
        if rule.get("type", "default") != "default" or not fields <= {"domain", "domain_suffix", "domain_regex", "domain_keyword"}:
            unsupported.append({"field": "rule", "value": copy.deepcopy(rule), "reason": "compound or unknown predicate; entire rule quarantined"})
            continue
        for field, value in rule.items():
            if field == "type":
                continue
            if field in ("domain_regex", "domain_keyword"):
                unsupported.append({"field": field, "value": copy.deepcopy(value), "reason": "matcher not supported by selected native mapping"})
                continue
            values = [value] if isinstance(value, str) else value
            if not isinstance(values, list):
                unsupported.append({"field": field, "value": copy.deepcopy(value), "reason": "expected literal string or list"})
                continue
            for name in values:
                if not _literal(name):
                    unsupported.append({"field": field, "value": copy.deepcopy(name), "reason": "invalid literal hostname or broad single-label suffix"})
                else:
                    (exact if field == "domain" else suffix).add(name)
    return {"exact": sorted(exact), "suffix": sorted(suffix), "unsupported": unsupported, "partial": bool(unsupported)}


def fetch_snapshot(selected, previous=None, fetch=fetch_url, *, source_id=None):
    """Return a complete discovery index with bodies for selected services only.

    ``fetch`` accepts one URL and returns bytes or UTF-8 text. Previously selected
    raw definitions are reused only after their Git blob hash is revalidated.
    No old force-pushed commit is downloaded to reconstruct accepted evidence.
    """
    if not isinstance(selected, list) or len(selected) > MAX_SELECTED or any(not isinstance(item, str) for item in selected) or len(selected) != len(set(selected)):
        raise RegistryError("select at most 64 unique registry IDs")
    previous_repository = (previous or {}).get("source", {}).get("repository")
    if source_id is None:
        source_id = next((key for key, value in SOURCE_REPOSITORIES.items() if value == previous_repository), None) if previous_repository else "metacubex-sing"
    if not isinstance(source_id, str) or source_id not in SOURCE_REPOSITORIES:
        raise RegistryError("unknown registry source")
    repository = SOURCE_REPOSITORIES[source_id]
    if previous_repository and previous_repository != repository:
        raise RegistryError("previous snapshot belongs to a different registry source")
    is_geo = source_id == GEO_SOURCE_ID
    is_fancy = source_id == FANCY_SOURCE_ID
    api_base = "https://api.github.com/repos/" + repository.removeprefix("https://github.com/")
    raw_base = "https://raw.githubusercontent.com/" + repository.removeprefix("https://github.com/")
    branch = "main" if is_geo or is_fancy else BRANCH

    def raw(url, limit):
        try:
            data = fetch(url)
        except RegistryError:
            raise
        except Exception:
            raise RegistryError("registry fetch failed; accepted snapshot is unchanged") from None
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, bytes) or len(data) > limit or b"\0" in data:
            raise RegistryError("invalid or oversized registry response")
        try:
            data.decode("utf-8")
        except UnicodeError:
            raise RegistryError("registry response is not UTF-8") from None
        return data

    def api(path):
        try:
            value = json.loads(raw(api_base + path, API_LIMIT))
        except (json.JSONDecodeError, UnicodeError):
            raise RegistryError("registry API returned invalid JSON") from None
        if not isinstance(value, dict):
            raise RegistryError("registry API object required")
        return value

    def tree(sha):
        document = api("/git/trees/" + _sha(sha))
        if document.get("truncated") or not isinstance(document.get("tree"), list) or any(not isinstance(item, dict) for item in document["tree"]):
            raise RegistryError("registry tree is truncated or invalid")
        return document["tree"]

    def child(entries, name, kind):
        found = [item for item in entries if item.get("path") == name and item.get("type") == kind]
        if len(found) != 1:
            raise RegistryError("registry tree entry missing or ambiguous")
        return _sha(found[0]["sha"])

    def blob(pin, path, expected):
        data = raw(raw_base + "/" + _sha(pin) + "/" + urllib.parse.quote(path, safe="/"), RAW_LIMIT)
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != _sha(expected):
            raise RegistryError("registry blob differs from pinned Git tree")
        return data.decode("utf-8")

    commit = api("/commits/" + branch)
    pin = _sha(commit["sha"])
    root = tree(commit["commit"]["tree"]["sha"])
    if is_geo:
        index_tree = _sha(commit["commit"]["tree"]["sha"])
        entries = []
        for service_id, directory, filename in (("geoblock", "Categories", "geoblock.lst"), ("google-ai", "Services", "google_ai.lst")):
            listing = tree(child(root, directory, "tree"))
            sha = child(listing, filename, "blob")
            item = next(item for item in listing if item.get("path") == filename and item.get("type") == "blob")
            entries.append({**item, "path": service_id + ".json", "sha": sha, "source_path": directory + "/" + filename})
    elif is_fancy:
        lists = tree(child(root, "lists", "tree"))
        index_tree = child(lists, "geoblock-sing-box", "tree")
        listing = tree(index_tree)
        sha = child(listing, "full.json", "blob")
        item = next(item for item in listing if item.get("path") == "full.json" and item.get("type") == "blob")
        entries = [{**item, "path": "community-geo.json", "sha": sha,
                    "source_path": "lists/geoblock-sing-box/full.json"}]
    else:
        geo = tree(child(root, "geo", "tree"))
        index_tree = child(geo, "geosite", "tree")
        entries = tree(index_tree)
    index = {}
    for item in entries:
        name = item.get("path", "")
        if item.get("type") != "blob" or not name.endswith(".json"):
            continue
        service_id = name[:-5]
        if not re.fullmatch(r"[a-z0-9][a-z0-9@!_.-]{0,150}", service_id):
            raise RegistryError("invalid registry index filename")
        size = item.get("size")
        if not isinstance(size, int) or size < 0:
            raise RegistryError("registry blob size is missing or invalid")
        kind = "attribute" if "@" in service_id else "category" if service_id.startswith("category-") else "group" if service_id.startswith(("geolocation-", "geoip-")) or service_id in ("cn", "private", "gfw", "tld-cn", "tld-!cn") else "service-candidate"
        index[service_id] = {"path": item["source_path"] if is_geo or is_fancy else "geo/geosite/" + name, "blob_sha": _sha(item["sha"]), "size": size, "kind": "category" if is_geo or is_fancy else kind}
    if any(item not in index for item in selected):
        raise RegistryError("selected registry ID missing upstream; accepted snapshot must be retained")
    license_pin, license_root = pin, root
    if not is_geo and not is_fancy and not any(item.get("path") == "LICENSE" and item.get("type") == "blob" for item in root):
        master = api("/commits/master")
        license_pin = _sha(master["sha"])
        license_root = tree(master["commit"]["tree"]["sha"])
    license_text = None if is_geo else blob(license_pin, "LICENSE", child(license_root, "LICENSE", "blob"))
    license_name = None if is_geo else "GPL-3.0" if "GNU GENERAL PUBLIC LICENSE" in license_text and "Version 3" in license_text else "UNKNOWN"
    if is_fancy:
        license_name = "MIT" if "MIT License" in license_text and "Permission is hereby granted" in license_text else "UNKNOWN"
    definitions = {}
    old = (previous or {}).get("definitions", {})
    for service_id in selected:
        entry = index[service_id]
        if entry["size"] > RAW_LIMIT:
            raise RegistryError("selected registry definition exceeds size limit")
        cached = old.get(service_id, {})
        cached_raw = cached.get("raw")
        cached_bytes = cached_raw.encode("utf-8") if isinstance(cached_raw, str) else b""
        cached_hash = hashlib.sha1(b"blob " + str(len(cached_bytes)).encode() + b"\0" + cached_bytes).hexdigest()
        body = cached_raw if cached_hash == entry["blob_sha"] else blob(pin, entry["path"], entry["blob_sha"])
        if is_geo:
            names = [line.split("#", 1)[0].strip() for line in body.splitlines()]
            if any(name and not _literal(name) for name in names):
                raise RegistryError("GeoBlock list contains an invalid literal hostname")
            definition = {"exact": [], "suffix": sorted(set(filter(None, names))), "unsupported": [], "partial": False}
        else:
            try:
                definition = normalize_rules(json.loads(body))
            except json.JSONDecodeError:
                raise RegistryError("selected registry definition is invalid JSON") from None
        definition.update(source_blob=entry["blob_sha"], sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(), raw=body)
        definitions[service_id] = definition
    source = {"repository": repository, "branch": branch, "commit": pin,
            "index_tree": index_tree, "license": license_name, "license_commit": license_pin,
            "license_reference": None if is_geo else repository + "/blob/" + license_pin + "/LICENSE", "license_text": license_text}
    if is_geo:
        source.update(private_only=True, license_note="No license grant established; fetched corpus is private-only and must not be publicly redistributed.")
    elif is_fancy:
        source.update(private_only=True, license_note="Repository license does not establish grants for aggregated third-party rules; fetched corpus is private-only and must not be publicly redistributed.")
    return {"schema_version": 1, "source": source,
            "index": dict(sorted(index.items())), "definitions": definitions}
