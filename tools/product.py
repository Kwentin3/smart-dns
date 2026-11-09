"""One private operator entrypoint; catalog, renderer and native policy retain ownership."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.catalog import configure, write_json
from tools.policy_git import PolicyGit, PolicyGitError
from tools.render import catalog_rules, compile_config, compile_production, write_new
from tools.service_policy import PolicyError, management_address, read_status, require
from tools.source_proposals import fetch_text, proposal

INPUT_NAMES = {"settings": "settings.json", "catalog": "rules/pilot.json",
               "registry": "rules/registry.json", "sources": "rules/sources.json", "origins": "origins.json"}


def load_deployment(path):
    path = Path(path).resolve()
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema_version", "mode", "project", "settings", "catalog", "registry", "sources",
                "admin_password_file", "management_base", "releases", "receipts", "dot_cert_dir"}
    require(isinstance(value, dict) and required <= value.keys() and not value.keys() - required - {"origins", "policy_git"},
            "deployment fields are missing or unknown")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["mode"] in ("production", "lab"), "unsupported deployment schema or mode")
    pattern = r"smart-dns(?:-[a-z0-9][a-z0-9-]{0,48})?" if value["mode"] == "production" else r"smart-dns-[a-z0-9][a-z0-9-]{0,48}"
    require(isinstance(value["project"], str) and re.fullmatch(pattern, value["project"]), "Smart DNS project name required")
    management_address(value["management_base"])
    for key in [*INPUT_NAMES, "admin_password_file", "releases", "receipts", "dot_cert_dir"]:
        if key not in value:
            continue
        require(isinstance(value[key], str) and bool(value[key]), "deployment paths must be explicit")
        value[key] = (path.parent / value[key]).resolve()
    for key in ("releases", "receipts"):
        require(".local" in value[key].parts, "operation archives and receipts must remain private under .local")
    inputs = [value[key] for key in INPUT_NAMES if key in value]
    require(len(inputs) == len(set(inputs)), "deployment input paths must differ")
    for output in (value["releases"], value["receipts"]):
        require(all(output != item and output not in item.parents for item in inputs), "operation output overlaps canonical inputs")
    if "policy_git" in value:
        configuration = value["policy_git"]
        require(isinstance(configuration, dict) and set(configuration) == {"directory", "remote", "branch"},
                "policy_git requires only directory, remote and branch")
        require(isinstance(configuration["directory"], str) and bool(configuration["directory"]),
                "policy_git directory must be explicit")
        configuration["directory"] = (path.parent / configuration["directory"]).resolve()
    return value


def read_inputs(deployment):
    return {key: json.loads(deployment[key].read_text(encoding="utf-8")) for key in INPUT_NAMES if key in deployment}


def status(deployment, inputs, *, status_reader=read_status):
    return status_reader(inputs["settings"], inputs["catalog"], project=deployment["project"],
        management_base=deployment["management_base"], admin_username=inputs["settings"]["admin_username"],
        admin_password=deployment["admin_password_file"].read_text(encoding="utf-8").strip(),
        production=deployment["mode"] == "production", registry=inputs["registry"], origins=inputs.get("origins"))


def _input_bytes(deployment):
    return {key: deployment[key].read_bytes() for key in INPUT_NAMES if key in deployment}


def _git_result(deployment, report, accepted, *, publisher=None, publish=True):
    """Compose Git evidence after native acceptance; never restore runtime here."""
    if "policy_git" not in deployment:
        return report
    if report["status"] != "matches":
        return {**report, "runtime_status": report["status"],
                "policy_git": {"status": "not-checked", "reason": "runtime-not-matching"}}
    runtime_status = "matches"
    try:
        if _input_bytes(deployment) != accepted:
            runtime_status = "not-rechecked"
            receipt = {"status": "pending", "reason": "inputs-changed"}
        else:
            publisher = publisher or PolicyGit(deployment)
            receipt = (publisher.publish(expected={key: accepted[key] for key in ("catalog", "registry", "sources")})
                       if publish else publisher.check())
    except PolicyGitError as error:
        receipt = error.receipt
    except Exception:
        receipt = {"status": "pending", "reason": "publication-failed"}
    # An adapter failure can itself report a real concurrent edit. Check the
    # owner binding on both success and failure before claiming native matches.
    try:
        if _input_bytes(deployment) != accepted:
            runtime_status = "not-rechecked"
            receipt = {**receipt, "status": "pending", "reason": "inputs-changed"}
    except OSError:
        runtime_status = "not-rechecked"
        receipt = {**receipt, "status": "pending", "reason": "inputs-unavailable"}
    return {**report, "status": "matches" if receipt["status"] == "synced" else "git-sync-pending",
            "runtime_status": runtime_status, "policy_git": receipt}


def operator_status(deployment, *, status_reader=read_status):
    """Keep the native status owner intact and report publication separately."""
    accepted = _input_bytes(deployment)
    report = status(deployment, {key: json.loads(value) for key, value in accepted.items()},
                    status_reader=status_reader)
    return _git_result(deployment, report, accepted, publish=False)


def catalog_view(inputs, service_id=None):
    """Read accepted discovery and desired policy; never infer live/user success."""
    registry = inputs["registry"]
    states = catalog_rules(inputs["catalog"], registry)["service_states"]
    local = {state["id"]: state for state in states}
    upstream = {state["upstream"]["list"]: state for state in states if "upstream" in state}
    entries = []
    candidates = list(local.items()) + [(identifier, None) for identifier in registry["index"] if identifier not in upstream]
    for identifier, state in sorted(candidates, key=lambda item: item[0]):
        list_id = state.get("upstream", {}).get("list") if state else identifier
        # A manual local name may happen to equal an unrelated discovery ID.
        entry = {"id": identifier, "entry_type": "local-policy" if state else "discovery",
                 "state": ("on" if state["enabled"] else "off") if state else "discovered",
                 "service": state, "index": registry["index"].get(list_id) if list_id else None}
        definition = registry["definitions"].get(list_id)
        entry["definition_available"] = definition is not None
        if service_id is not None and service_id in (identifier, list_id):
            entry["definition"] = {key: value for key, value in definition.items() if key != "raw"} if definition else None
        entries.append(entry)
    if service_id is not None:
        entries = [entry for entry in entries if service_id in (entry["id"], (entry["service"] or {}).get("upstream", {}).get("list"))]
        require(bool(entries), "unknown local service or accepted discovery ID")
    return {"status": "desired-policy-only", "source": registry.get("source"),
            "runtime": "not-checked", "network_path": "not-checked", "user_functionality": "not-checked",
            "excluded_domains": inputs["catalog"]["excluded_domains"],
            "excluded_zones": inputs["catalog"]["excluded_zones"], "entries": entries}


def run_native(arguments, environment):
    """Allow the native child's own rollback after timeout; never kill it blindly."""
    child = subprocess.Popen(arguments, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return child.wait(timeout=215) == 0
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=70)
        except subprocess.TimeoutExpired:
            raise PolicyError("native operation exceeded rollback grace; inspect private state before retry") from None
        raise PolicyError("native operation timed out; inspect private receipt") from None


def archive_inputs(directory, fallback):
    for folder in (directory / "inputs", directory / "private-inputs"):
        if (folder / INPUT_NAMES["catalog"]).is_file():
            require(all((folder / INPUT_NAMES[key]).is_file() for key in ("catalog", "registry", "sources")),
                    "archived generation has incomplete rule inputs")
            return {**fallback, **{key: json.loads((folder / name).read_text(encoding="utf-8"))
                    for key, name in INPUT_NAMES.items() if (folder / name).is_file()}}
        if folder.name == "private-inputs" and (folder / "pilot.json").is_file():
            return {**fallback, **{key: json.loads((folder / name).read_text(encoding="utf-8"))
                    for key, name in (("catalog", "pilot.json"), ("registry", "registry.json"), ("sources", "sources.json"))}}
    raise PolicyError("generation has no archived inputs; cannot reconstruct its policy safely")


def prepare(deployment, inputs, directory):
    compiler = compile_production if deployment["mode"] == "production" else compile_config
    artifacts = compiler(catalog_rules(inputs["catalog"], inputs["registry"]), inputs["settings"], inputs.get("origins"))
    artifacts.update({"inputs/" + INPUT_NAMES[key]: value for key, value in inputs.items()})
    write_new(artifacts, directory)
    directory.chmod(0o700)
    for path in (directory / "inputs").rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    return artifacts["snapshot.json"]


def operate(deployment, command, *, service_id=None, reason=None, domains=(), suffixes=(), to=None,
            status_reader=read_status, native=run_native, fetch=fetch_text):
    """Coordinate one operation under the CLI lock; replace only external boundaries in tests."""
    publisher = PolicyGit(deployment) if "policy_git" in deployment else None
    if publisher is not None:
        publisher.preflight()
    original = _input_bytes(deployment)
    old = {key: json.loads(value) for key, value in original.items()}
    observed = status(deployment, old, status_reader=status_reader)
    if command == "git-sync":
        require(publisher is not None, "git-sync requires policy_git configuration")
        require(observed["status"] == "matches", "native state must match before Git publication")
        return _git_result(deployment, {**observed, "operation": command}, original, publisher=publisher)
    accepted = Path(observed["actual_directory"]).resolve(strict=True)
    candidate_inputs = copy.deepcopy(old)
    if command == "refresh":
        try:
            update = proposal(old["sources"], old["registry"], old["catalog"], fetch=fetch)
        except Exception:
            raise PolicyError("source refresh failed; accepted inputs and runtime unchanged") from None
        require(all(deployment[key].read_bytes() == value for key, value in original.items()),
                "canonical inputs changed during source refresh")
        proposal_path = deployment["receipts"] / "source-proposals/latest.json"
        proposal_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_json(proposal_path, update)
        if update["review_required"]:
            return {"status": "review-required", "operation": command, "review_reasons": update["review_reasons"],
                    "accepted_unchanged": True, "runtime_unchanged": True}
        if not update["changed"]:
            observed = status(deployment, old, status_reader=status_reader)
            accepted = Path(observed["actual_directory"]).resolve(strict=True)
            if observed["status"] == "matches":
                return _git_result(deployment, {**observed, "operation": command, "source_changed": False},
                                   original, publisher=publisher)
        candidate_inputs["registry"] = update["candidate_registry"]
    elif command in ("on", "off"):
        require(any(service["id"] == service_id for service in old["catalog"]["services"]), "unknown local service ID")
        candidate_inputs["catalog"] = configure(old["catalog"], old["registry"], service_id, command == "on", reason)
    elif command in ("exclude", "include"):
        require(isinstance(reason, str) and bool(reason.strip()), "an explicit exclusion-state reason is required")
        exclusions = candidate_inputs["catalog"]["excluded_domains"]
        if command == "exclude":
            exclusions[service_id] = reason
        else:
            require(service_id in exclusions, "name has no manual exclusion to remove")
            del exclusions[service_id]
        candidate_inputs["catalog"]["revision"] += 1
    elif command == "add":
        require(not any(service["id"] == service_id for service in old["catalog"]["services"]), "local service ID already exists")
        require(isinstance(reason, str) and bool(reason.strip()), "an explicit service-state reason is required")
        candidate_inputs["catalog"]["services"].append({"id": service_id, "name": service_id, "kind": "service",
            "enabled": True, "reason": reason, "domains": sorted(set(domains)), "domain_suffixes": sorted(set(suffixes))})
        candidate_inputs["catalog"]["revision"] += 1
        if suffixes:
            candidate_inputs["catalog"]["domain_policy"] = "exact-and-suffix"
    elif command == "rollback":
        require(isinstance(to, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}", to) and to not in (".", ".."), "select one archived generation name")
        target = (deployment["releases"] / to).resolve(strict=True)
        require(target.parent == deployment["releases"], "rollback generation must belong to this deployment")
        restored = archive_inputs(target, old)
        candidate_inputs["catalog"], candidate_inputs["registry"] = restored["catalog"], restored["registry"]
    else:
        require(command == "apply", "unsupported product operation")
    # Compile before creating any files, and prove the native restore target can
    # be regenerated by current owners, rather than executing archived code.
    compiler = compile_production if deployment["mode"] == "production" else compile_config
    compiler(catalog_rules(candidate_inputs["catalog"], candidate_inputs["registry"]), candidate_inputs["settings"], candidate_inputs.get("origins"))
    restore_inputs = old
    if observed["status"] != "matches":
        restore_inputs = archive_inputs(accepted, old)
        compiler(catalog_rules(restore_inputs["catalog"], restore_inputs["registry"]), restore_inputs["settings"], restore_inputs.get("origins"))
    deployment["releases"].mkdir(parents=True, exist_ok=True, mode=0o700)
    deployment["receipts"].mkdir(parents=True, exist_ok=True, mode=0o700)
    identifier = uuid.uuid4().hex
    candidate = deployment["releases"] / identifier
    restore = deployment["releases"] / (identifier + "-restore")
    prepare(deployment, candidate_inputs, candidate)
    prepare(deployment, restore_inputs, restore)
    environment = {**os.environ, "DOT_CERT_DIR": str(deployment["dot_cert_dir"])}

    def apply(before, after, inputs, suffix):
        arguments = [sys.executable, str(ROOT / "tools/service_policy.py"),
            "--production" if deployment["mode"] == "production" else "--lab-only",
            "--accepted", str(before), "--candidate", str(after),
            "--settings", str(after / "inputs/settings.json"), "--rules", str(after / "inputs/rules/pilot.json"),
            "--registry", str(after / "inputs/rules/registry.json"), "--project", deployment["project"],
            "--management-base", deployment["management_base"], "--admin-username", inputs["settings"]["admin_username"],
            "--admin-password-file", str(deployment["admin_password_file"]),
            "--out", str(deployment["receipts"] / (identifier + suffix + ".json"))]
        if "origins" in inputs:
            arguments += ["--origins", str(after / "inputs/origins.json")]
        require(native(arguments, environment), "native operation failed; canonical preferences unchanged; inspect private receipt")

    require(all(deployment[key].read_bytes() == value for key, value in original.items()), "canonical inputs changed before apply")
    apply(accepted, candidate, candidate_inputs, "")
    published = {}
    try:
        require(all(deployment[key].read_bytes() == value for key, value in original.items()), "canonical inputs changed during apply")
        for key in ("catalog", "registry"):
            if candidate_inputs[key] != old[key]:
                require(all(deployment[item].read_bytes() == published.get(item, value) for item, value in original.items()),
                        "canonical inputs changed during publication")
                published[key] = write_json(deployment[key], candidate_inputs[key])
        accepted_bytes = {**original, **published}
        require(_input_bytes(deployment) == accepted_bytes, "canonical inputs changed after publication")
        report = status(deployment, {key: json.loads(value) for key, value in accepted_bytes.items()},
                        status_reader=status_reader)
        require(report["status"] == "matches", "native policy readback does not match published preferences")
    except BaseException:
        try:
            for key, value in published.items():
                if deployment[key].read_bytes() == value:
                    write_json(deployment[key], old[key])
        finally:
            apply(candidate, restore, restore_inputs, "-restore")
        raise PolicyError("publication or readback failed; native policy restored; external edits preserved") from None
    return _git_result(deployment, {**report, "operation": command, "generation": identifier},
                       accepted_bytes, publisher=publisher)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, default=Path("/opt/smart-dns/.local/deployment.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("list")
    commands.add_parser("show").add_argument("service_id")
    commands.add_parser("apply")
    commands.add_parser("refresh")
    commands.add_parser("git-sync")
    for name in ("on", "off", "add", "exclude", "include"):
        command = commands.add_parser(name)
        command.add_argument("service_id", metavar="NAME" if name in ("exclude", "include") else "service_id")
        command.add_argument("--reason", required=True)
        if name == "add":
            command.add_argument("--domain", action="append", default=[])
            command.add_argument("--suffix", action="append", default=[])
    commands.add_parser("rollback").add_argument("--to", required=True)
    args = parser.parse_args()
    try:
        deployment = load_deployment(args.deployment)
        if args.command in ("list", "show"):
            inputs = {key: json.loads(deployment[key].read_text(encoding="utf-8")) for key in ("catalog", "registry")}
            report = catalog_view(inputs, getattr(args, "service_id", None))
        elif args.command == "status":
            report = operator_status(deployment)
        else:
            import fcntl
            os.umask(0o077)
            lock_path = Path("/tmp") / ("smart-dns-product-" + str(os.getuid()) + "-" + deployment["project"] + ".lock")
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as lock:
                require(os.fstat(lock.fileno()).st_uid == os.getuid(), "product lock has another owner")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise PolicyError("another product operation owns this deployment") from None
                report = operate(deployment, args.command, service_id=getattr(args, "service_id", None),
                    reason=getattr(args, "reason", None), domains=getattr(args, "domain", []),
                    suffixes=getattr(args, "suffix", []), to=getattr(args, "to", None))
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["status"] in ("matches", "desired-policy-only") else 1
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error) if isinstance(error, (PolicyError, PolicyGitError)) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
