"""Local service preferences over a ready upstream catalog, never deployment.

Upstream owns membership; local approved_scope owns authority. New roots and
unsupported matchers remain visible and cannot silently enlarge live policy.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.registry import REPOSITORY, SOURCE_REPOSITORIES, fetch_snapshot


def selected_lists(catalog):
    return sorted({service["upstream"]["list"] for service in catalog["services"] if "upstream" in service})


def covered(name, kind, scope):
    if kind == "exact" and name in scope["exact"]:
        return True
    return any(name == root or name.endswith("." + root) for root in scope["suffix"])


def project_catalog(catalog, registry, validate_hostname):
    """Compose source facts and local bounds; hostname validation stays native-owned."""
    result = copy.deepcopy(catalog)
    for service in result["services"]:
        if "upstream" not in service:
            continue
        ref = service["upstream"]
        repository = SOURCE_REPOSITORIES.get(ref.get("source"))
        if not repository or not isinstance(registry, dict) or registry.get("schema_version") != 1 or registry["source"]["repository"] != repository:
            raise ValueError("selected service requires its accepted source registry snapshot")
        if repository != REPOSITORY and registry["source"].get("private_only") is not True:
            raise ValueError("GEO source snapshot must remain private")
        list_id = ref["list"]
        if "kind" not in service:
            service["kind"] = "group" if registry["index"][list_id].get("kind") in ("category", "group") else "service"
        definition = registry["definitions"][list_id]
        if definition["source_blob"] != registry["index"][list_id]["blob_sha"]:
            raise ValueError("selected definition does not match accepted registry index")
        scope = ref["approved_scope"]
        if not isinstance(scope, dict) or set(scope) != {"exact", "suffix"}:
            raise ValueError("upstream approval requires separate exact and suffix scopes")
        for kind in ("exact", "suffix"):
            values = scope[kind]
            if not isinstance(values, list) or values != sorted(set(values)):
                raise ValueError("approved scopes must be unique sorted lists")
            for value in values:
                validate_hostname(value)
        importing = bool(scope["exact"] or scope["suffix"])
        if service["enabled"] and importing and definition["partial"] and ref.get("accept_partial") is not True:
            raise ValueError("selected source contains unsupported rules; explicit literal-only approval required")
        pending = []
        for kind, target in (("exact", "domains"), ("suffix", "domain_suffixes")):
            accepted = []
            for name in definition[kind]:
                validate_hostname(name)
                if covered(name, kind, scope):
                    accepted.append(name)
                else:
                    pending.append({"kind": kind, "name": name})
            if accepted:
                service[target] = sorted(set(service.get(target, [])) | set(accepted))
        service["upstream_state"] = {"commit": registry["source"]["commit"], "list": list_id,
            "source_blob": definition["source_blob"], "partial": definition["partial"],
            "unsupported": definition["unsupported"], "pending_scope": pending,
            "status": "review-required" if pending or definition["partial"] else "current"}
    if any(service.get("domain_suffixes") for service in result["services"]):
        result["domain_policy"] = "exact-and-suffix"
    return result


def configure(catalog, registry, list_id, enabled, reason, *, local_id=None, accept_partial=False, approve_scope=False):
    """One explicit local edit. It never fetches, writes files or applies state."""
    if type(enabled) is not bool:
        raise ValueError("service enabled must be an explicit boolean")
    result = copy.deepcopy(catalog)
    found = [s for s in result["services"] if s["id"] == list_id or s.get("upstream", {}).get("list") == list_id]
    if len(found) > 1:
        raise ValueError("ambiguous local service; select by its local ID")
    if found:
        service = found[0]
        upstream_id = service.get("upstream", {}).get("list", list_id)
    else:
        upstream_id = list_id
        identifier = local_id or list_id
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", identifier):
            raise ValueError("provide --id as a simple local service name")
        if any(s["id"] == identifier for s in result["services"]):
            raise ValueError("local service ID already exists")
        source_id = next((key for key, value in SOURCE_REPOSITORIES.items() if value == registry["source"]["repository"]), None)
        if source_id is None:
            raise ValueError("unsupported registry source")
        kind = "group" if registry["index"][list_id].get("kind") in ("category", "group") else "service"
        service = {"id": identifier, "name": list_id, "kind": kind, "domains": [], "enabled": False, "reason": reason,
            "upstream": {"source": source_id, "list": list_id, "approved_scope": {"exact": [], "suffix": []}}}
        result["services"].append(service)
        approve_scope = True
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("an explicit service-state reason is required")
    if enabled and approve_scope:
        definition = registry["definitions"][upstream_id]
        if definition["partial"] and not accept_partial:
            raise ValueError("source has unsupported rules; inspect show output before --accept-literal-only")
        service["upstream"]["approved_scope"] = {"exact": definition["exact"][:], "suffix": definition["suffix"][:]}
        if accept_partial:
            service["upstream"]["accept_partial"] = True
    service.update(enabled=enabled, reason=reason)
    result["revision"] += 1
    return result


def write_json(path, value):
    """Working-tree edits become authoritative together only through a Git commit."""
    path = Path(path)
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        temporary.replace(path)
        return content.encode("utf-8")
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    from tools.render import hostname, approved_rules
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "show", "enable", "disable"))
    parser.add_argument("service", nargs="?")
    parser.add_argument("--search", default="")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules/pilot.json")
    parser.add_argument("--registry", type=Path, default=ROOT / "rules/registry.json")
    parser.add_argument("--reason")
    parser.add_argument("--id")
    parser.add_argument("--approve-source-scope", action="store_true")
    parser.add_argument("--accept-literal-only", action="store_true")
    args = parser.parse_args()
    catalog = json.loads(args.rules.read_text(encoding="utf-8"))
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    if args.command == "list":
        configured = {s.get("upstream", {}).get("list"): s for s in catalog["services"]}
        print("UPSTREAM LIST\tSTATE\tKIND")
        for name, info in registry["index"].items():
            if args.search.lower() in name:
                state = "ON" if configured.get(name, {}).get("enabled") else "OFF"
                print(name + "\t" + state + "\t" + info["kind"])
        return
    if not args.service:
        parser.error("this command requires a service")
    matching = next((s for s in catalog["services"] if s["id"] == args.service or s.get("upstream", {}).get("list") == args.service), None)
    upstream_id = matching.get("upstream", {}).get("list", args.service) if matching else args.service
    if args.command == "show":
        if matching is not None and "upstream" not in matching:
            print(json.dumps({"service": matching, "status": "desired-policy-only"}, ensure_ascii=False, indent=2))
            return
        if upstream_id not in registry["index"]:
            parser.error("service list is not present in the accepted discovery index")
        preview = registry
        if upstream_id not in registry["definitions"]:
            preview = fetch_snapshot(sorted(set(selected_lists(catalog)) | {upstream_id}), registry)
        print(json.dumps({"list": upstream_id, "accepted_snapshot": preview is registry,
            "source_commit": preview["source"]["commit"], "index": preview["index"][upstream_id],
            "definition": preview["definitions"][upstream_id]}, ensure_ascii=False, indent=2))
        return
    enabled = args.command == "enable"
    updated_registry = registry
    if enabled and (matching is None or "upstream" in matching) and upstream_id not in registry["definitions"]:
        updated_registry = fetch_snapshot(sorted(set(selected_lists(catalog)) | {upstream_id}), registry)
    updated = configure(catalog, updated_registry, args.service, enabled, args.reason,
        local_id=args.id, accept_partial=args.accept_literal_only, approve_scope=args.approve_source_scope)
    approved_rules(project_catalog(updated, updated_registry, hostname))
    # Preferences first: a missing companion definition fails closed until the
    # second edit completes. Git commits, not dirty working trees, are deployed.
    write_json(args.rules, updated)
    if updated_registry != registry:
        write_json(args.registry, updated_registry)
    print("Desired catalog changed. Review/commit the Git diff; no runtime state was changed.")


if __name__ == "__main__":
    main()
