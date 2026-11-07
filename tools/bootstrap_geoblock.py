"""Prepare a private broad GEO catalog using the existing source/policy owners.

No deployment, credentials, DNS settings, live admission or source redistribution.
The base policy is preserved as an explicitly frozen local baseline; the two GEO
groups subsequently use the private source snapshot and ordinary catalog bounds.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.catalog import configure, project_catalog
from tools.registry import FANCY_SOURCE_ID, GEO_SOURCE_ID, SOURCE_REPOSITORIES, fetch_snapshot
from tools.render import catalog_rules, hostname, write_new

PROFILES = {
    GEO_SOURCE_ID: (("geoblock", "GeoBlock"), ("google-ai", "Google AI including Gemini")),
    FANCY_SOURCE_ID: (("community-geo", "Community GEO (RussiaFancyLists)"),),
}


def prepare_catalog(base_catalog, base_registry, geo_registry):
    """Explicit initial approval of the selected complete GEO categories."""
    if geo_registry["source"].get("private_only") is not True:
        raise ValueError("the GEO snapshot must be private")
    source_id = next((key for key in PROFILES if SOURCE_REPOSITORIES[key] == geo_registry["source"]["repository"]), None)
    if source_id is None:
        raise ValueError("unsupported private GEO source")
    catalog = project_catalog(base_catalog, base_registry, hostname)
    for service in catalog["services"]:
        if "upstream" in service:
            ref = service["upstream"]
            service["source_path"] = (base_registry["source"]["repository"] + "/blob/" +
                                      base_registry["source"]["commit"] + "/" + base_registry["index"][ref["list"]]["path"])
            service.pop("upstream")
            service.pop("upstream_state", None)
            service["source"] = "previously-accepted-local-baseline"
    for identifier, name in PROFILES[source_id]:
        if any(s["id"] == identifier for s in catalog["services"]):
            raise ValueError("GEO group already exists; use the ordinary catalog update path")
        catalog = configure(catalog, geo_registry, identifier, True,
                            "Owner requested the complete ready GEO profile", approve_scope=True)
        next(s for s in catalog["services"] if s["id"] == identifier)["name"] = name
    catalog["note"] = "Private desired GEO profile. Source snapshots and proposals remain private. Native readback establishes actual state."
    catalog_rules(catalog, geo_registry)
    return catalog


def prepare(base_catalog, base_registry, *, fetch=None, source_id=GEO_SOURCE_ID):
    if source_id not in PROFILES:
        raise ValueError("unsupported private GEO profile")
    arguments = {"source_id": source_id}
    if fetch is not None:
        arguments["fetch"] = fetch
    snapshot = fetch_snapshot([identifier for identifier, _ in PROFILES[source_id]], **arguments)
    catalog = prepare_catalog(base_catalog, base_registry, snapshot)
    source = snapshot["source"]
    declaration = {"schema_version": 1, "private_only": True, "sources": [{
        "id": source_id, "repository": SOURCE_REPOSITORIES[source_id],
        "branch": source["branch"], "commit": source["commit"], "license": source["license"],
        "paths": [v["path"] for v in snapshot["index"].values()],
        "use": "private GEO collection only; do not publish snapshots or proposal artifacts"}]}
    return {"rules/pilot.json": catalog, "rules/registry.json": snapshot,
            "rules/sources.json": declaration}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-catalog", type=Path, default=ROOT / "rules/pilot.json")
    parser.add_argument("--base-registry", type=Path, default=ROOT / "rules/registry.json")
    parser.add_argument("--source", choices=PROFILES, default=GEO_SOURCE_ID)
    parser.add_argument("--out", type=Path, default=ROOT / ".local/geoblock-policy")
    args = parser.parse_args()
    if ".local" not in args.out.resolve().parts:
        parser.error("the complete GEO profile must stay in an explicitly private .local directory")
    if args.out.exists():
        parser.error("choose a new private output directory")
    try:
        artifacts = prepare(json.loads(args.base_catalog.read_text(encoding="utf-8")),
                            json.loads(args.base_registry.read_text(encoding="utf-8")), source_id=args.source)
        write_new(artifacts, args.out)
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "Private GEO preparation failed; accepted inputs/runtime remain unchanged.\n")
    facts = artifacts["rules/registry.json"]
    print(json.dumps({"status": "prepared-only", "source_commit": facts["source"]["commit"],
                      "groups": {name: len(value["suffix"]) for name, value in facts["definitions"].items()},
                      "group_matchers": {name: {kind: len(value[kind]) for kind in ("exact", "suffix")} for name, value in facts["definitions"].items()},
                      "private_only": True}))


if __name__ == "__main__":
    main()
