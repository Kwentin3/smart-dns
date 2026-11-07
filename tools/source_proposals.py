"""Collect one broad service registry and propose changes without activating it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tempfile

if __package__:
    from . import registry
else:
    import registry

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ID = "metacubex-sing"


def fetch_text(url):
    """Injected collectors may use UTF-8 text; production transport stays native."""
    data = registry.fetch_url(url)
    text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
    if not isinstance(text, str) or "\0" in text:
        raise ValueError("invalid registry text")
    return text


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def differences(before, after):
    """Keep structured values, including quarantined unsupported predicates."""
    old = {json.dumps(item, sort_keys=True, ensure_ascii=False): item for item in before}
    new = {json.dumps(item, sort_keys=True, ensure_ascii=False): item for item in after}
    return {"added": [new[key] for key in sorted(new.keys() - old.keys())],
            "removed": [old[key] for key in sorted(old.keys() - new.keys())]}


def proposal(source_document, previous, catalog, fetch=fetch_text):
    repository = previous.get("source", {}).get("repository", registry.REPOSITORY)
    source_id = next((key for key, value in registry.SOURCE_REPOSITORIES.items() if value == repository), None)
    sources = [item for item in source_document["sources"] if item.get("id") == source_id]
    if source_id is None or len(sources) != 1 or sources[0].get("repository") != repository:
        raise ValueError("one declared supported registry source is required")
    if source_id == SOURCE_ID and sources[0].get("license") != "GPL-3.0":
        raise ValueError("Meta registry license requires review")
    if not isinstance(sources[0].get("commit"), str) or re.fullmatch(r"[0-9a-f]{40}", sources[0]["commit"]) is None:
        raise ValueError("declared registry source requires an immutable 40-hex commit")
    selected = []
    for service in catalog["services"]:
        upstream = service.get("upstream")
        if upstream is not None:
            if upstream["source"] != source_id:
                raise ValueError("catalog refers to an unsupported registry source")
            selected.append(upstream["list"])
    selected = sorted(set(selected))
    candidate = registry.fetch_snapshot(selected, previous=previous, fetch=fetch, source_id=source_id)
    if source_id == SOURCE_ID and candidate["source"]["license"] != "GPL-3.0":
        raise ValueError("registry license requires manual review")
    old_index, new_index = previous.get("index", {}), candidate["index"]
    old_definitions = previous.get("definitions", {})
    selected_changes = {}
    for name in selected:
        old, new = old_definitions.get(name, {}), candidate["definitions"][name]
        selected_changes[name] = {kind: differences(old.get(kind, []), new[kind]) for kind in ("exact", "suffix", "unsupported")}
        selected_changes[name].update(partial=new["partial"], source_blob=new["source_blob"])
    old_source = previous.get("source", {})
    license_changed = (old_source.get("license_text") != candidate["source"]["license_text"] or
                       old_source.get("license") != candidate["source"]["license"])
    review_reasons = []
    if license_changed:
        review_reasons.append("license-change")
    if any(change[kind]["removed"] for change in selected_changes.values() for kind in ("exact", "suffix", "unsupported")):
        review_reasons.append("selected-rule-removal")
    if any(change["unsupported"]["added"] for change in selected_changes.values()):
        review_reasons.append("unsupported-rule-addition")
    return {"schema_version": 2, "kind": "service-registry-proposal", "created_at": datetime.now(timezone.utc).isoformat(),
            "policy": "proposal only; no preferences, client admission, admin state or live runtime changes",
            "accepted_registry_sha256": checksum(previous), "candidate_registry_sha256": checksum(candidate),
            "catalog_sha256": checksum(catalog), "sources_sha256": checksum(source_document),
            "accepted_commit": old_source.get("commit"), "proposed_commit": candidate["source"]["commit"],
            "source": candidate["source"], "selected_lists": selected,
            "index_changes": {"added": sorted(new_index.keys() - old_index.keys()),
                              "removed": sorted(old_index.keys() - new_index.keys()),
                              "changed": sorted(name for name in old_index.keys() & new_index.keys() if old_index[name] != new_index[name])},
            "selected_rule_changes": selected_changes,
            "license_changed": license_changed, "review_required": bool(review_reasons), "review_reasons": review_reasons,
            "changed": previous != candidate, "candidate_registry": candidate}


def produce(sources_path, output_path, fetch=fetch_text, *, registry_path=None, catalog_path=None, public_artifact=False):
    sources_path, output_path = Path(sources_path).resolve(), Path(output_path).resolve()
    root = sources_path.parent.parent
    artifact_root = (root / ".local/source-proposals").resolve()
    if not output_path.is_relative_to(artifact_root) or output_path.suffix != ".json":
        raise ValueError("proposal output must stay under .local/source-proposals")
    registry_path = Path(registry_path) if registry_path is not None else root / "rules/registry.json"
    catalog_path = Path(catalog_path) if catalog_path is not None else root / "rules/pilot.json"
    previous = json.loads(registry_path.read_text(encoding="utf-8"))
    if public_artifact and previous.get("source", {}).get("repository") != registry.REPOSITORY:
        raise ValueError("private GEO snapshots cannot be published as public artifacts")
    result = proposal(json.loads(sources_path.read_text(encoding="utf-8")), previous,
                      json.loads(catalog_path.read_text(encoding="utf-8")), fetch)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # One atomic owner contains both the proposal and its exact candidate.
    with tempfile.TemporaryDirectory(prefix=".registry-", dir=output_path.parent) as staging:
        temporary = Path(staging) / "proposal.json"
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output_path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT / "rules/sources.json")
    parser.add_argument("--registry", type=Path, default=ROOT / "rules/registry.json")
    parser.add_argument("--catalog", type=Path, default=ROOT / "rules/pilot.json")
    parser.add_argument("--out", type=Path, default=ROOT / ".local/source-proposals/latest.json")
    parser.add_argument("--public-artifact", action="store_true", help="Reject private-only source profiles before fetching")
    args = parser.parse_args()
    try:
        result = produce(args.sources, args.out, registry_path=args.registry, catalog_path=args.catalog, public_artifact=args.public_artifact)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Registry proposal failed; accepted registry/preferences/runtime remain unchanged.\n")
    print("Registry proposal saved; changed=" + str(result["changed"]).lower() + "; no accepted or runtime state changed")


if __name__ == "__main__":
    main()
