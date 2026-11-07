"""Bind a private GEO candidate to the existing compiler in a disposable lab."""
import hashlib
import json
from pathlib import Path

from tools.render import catalog_rules, compile_config, write_new
from tools.source_proposals import checksum

PROJECT = "smart-dns-geo-native"
PASSWORD_HASH = "$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56"


def load_policy(directory):
    directory = Path(directory).resolve(strict=True)
    return {name: json.loads((directory / filename).read_text(encoding="utf-8"))
            for name, filename in (("catalog", "pilot.json"), ("registry", "registry.json"))}


def enforcement_scope(rules):
    """Receipt projection of owner-produced matchers, never another compiler."""
    return {key: rules[key] for key in ("domains", "domain_suffixes", "excluded_domains", "excluded_zones")}


def prepare(out, policy, baseline, expected_policy_sha256):
    inputs, previous = load_policy(policy), load_policy(baseline)
    rules = catalog_rules(inputs["catalog"], inputs["registry"])
    old_rules = catalog_rules(previous["catalog"], previous["registry"])
    policy_sha = checksum(enforcement_scope(rules))
    if policy_sha != expected_policy_sha256:
        raise ValueError("candidate policy differs from the reviewed frozen scope")
    old_states = {service["id"]: service for service in old_rules["service_states"]}
    states = {service["id"]: service for service in rules["service_states"]}
    for identifier, old in old_states.items():
        current = states[identifier]
        for key in ("enabled", "kind", "domains", "domain_suffixes"):
            if current.get(key) != old.get(key):
                raise ValueError("candidate does not preserve the accepted baseline service")
    for key in ("excluded_domains", "excluded_zones"):
        if inputs["catalog"][key] != previous["catalog"][key]:
            raise ValueError("candidate does not preserve owner exclusions")
    settings = {
        "doh_host": "dns.example.net", "relay_ipv4": "192.0.2.10", "client_ids": ["a" * 32],
        "own_zones": ["example.net"], "admin_username": "fixtureadmin",
        "admin_password_hash": PASSWORD_HASH, "max_policy_entries": 4096,
        "upstream_dns": ["https://dns.quad9.net/dns-query"], "bootstrap_dns": ["9.9.9.9"],
        "origin_dns": ["9.9.9.9", "1.1.1.1"],
    }
    artifacts = compile_config(rules, settings)
    compose = artifacts["compose.lab.json"]
    # Keep generated Docker labels intact; constrain only this fixture's discovery.
    command = compose["services"]["edge"]["command"]
    command[:] = [argument if not argument.startswith("--providers.docker.constraints=") else
                  "--providers.docker.constraints=Label(`smart-dns.lab`,`true`) && "
                  "Label(`com.docker.compose.project`,`" + PROJECT + "`)" for argument in command]
    snapshot = artifacts["snapshot.json"]
    label = compose["services"]["relay"]["labels"]["traefik.tcp.routers.sd-relay.rule"]
    receipts = {
        "policy_sha256": policy_sha, "baseline_preserved": True,
        "candidate_catalog_sha256": checksum(inputs["catalog"]),
        "candidate_registry_sha256": checksum(inputs["registry"]),
        "baseline_catalog_sha256": checksum(previous["catalog"]),
        "baseline_registry_sha256": checksum(previous["registry"]),
        "source_commit": inputs["registry"]["source"]["commit"],
        "baseline_source_commit": previous["registry"]["source"]["commit"],
        "compiled_generation": snapshot["sha256"], "max_policy_entries": settings["max_policy_entries"],
        "wire_exact": len(snapshot["wire_scope"]["domains"]),
        "wire_suffix": len(snapshot["wire_scope"]["domain_suffixes"]),
        "compose_label_bytes": len(label.encode()), "native_label_bytes": len(label.replace("$$", "$").encode()),
        "native_label_sha256": hashlib.sha256(label.replace("$$", "$").encode()).hexdigest(),
        "scope": "reviewed policy through compiler, with disposable infrastructure settings",
        "application_functions": "not-checked", "production": "not-checked",
    }
    artifacts.update({"fixture-settings.json": settings, "inputs.json": receipts})
    write_new(artifacts, out)
    return compose
