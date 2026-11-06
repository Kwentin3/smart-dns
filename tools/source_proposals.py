"""Fetch public service-list changes as review evidence, never activate rules."""
import argparse
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/v2fly/domain-list-community"
PATHS = ("data/openai", "data/anthropic")
LIMIT = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_text(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in ("api.github.com", "raw.githubusercontent.com"):
        raise ValueError("unexpected source host")
    headers = {"User-Agent": "smart-dns-source-proposal", "Accept": "application/vnd.github+json" if parsed.netloc == "api.github.com" else "text/plain"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and parsed.netloc == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("source response exceeds size limit")
    text = data.decode("utf-8", errors="strict")
    if "\0" in text:
        raise ValueError("source response contains NUL")
    return text


def commit_id(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("source commit must be immutable lowercase 40-hex SHA")
    return value


def raw_url(commit, path):
    return f"https://raw.githubusercontent.com/v2fly/domain-list-community/{commit}/{path}"


def proposal(source_document, fetch=fetch_text):
    entries = [item for item in source_document["sources"] if item["id"] == "v2fly-service-catalog"]
    if len(entries) != 1:
        raise ValueError("exactly one v2fly-service-catalog source is required")
    source = entries[0]
    accepted = commit_id(source["commit"])
    if source["repository"] != REPOSITORY or source["paths"] != list(PATHS) or source["license"] != "MIT":
        raise ValueError("unexpected service source, selected paths or license")
    if source["license_reference"] != f"{REPOSITORY}/blob/{accepted}/LICENSE":
        raise ValueError("license reference must match accepted source pin")
    latest = commit_id(json.loads(fetch("https://api.github.com/repos/v2fly/domain-list-community/commits/HEAD"))["sha"])
    files = []
    licenses = {}
    for path in (*PATHS, "LICENSE"):
        before = fetch(raw_url(accepted, path))
        after = fetch(raw_url(latest, path))
        if not isinstance(before, str) or not isinstance(after, str) or not before.strip() or not after.strip():
            raise ValueError("empty or invalid source document")
        # Keep every raw line/type/attribute: this is deliberately not an importer.
        files.append({"path": path, "accepted_url": raw_url(accepted, path), "proposed_url": raw_url(latest, path),
                      "accepted_sha256": hashlib.sha256(before.encode("utf-8")).hexdigest(),
                      "proposed_sha256": hashlib.sha256(after.encode("utf-8")).hexdigest(),
                      "changed": before != after,
                      "diff": "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=f"{accepted}/{path}", tofile=f"{latest}/{path}"))})
        if path == "LICENSE":
            if "MIT License" not in before or "MIT License" not in after:
                raise ValueError("MIT license declaration missing; manual review required")
            licenses = {"accepted_text": before, "proposed_text": after}
    return {"schema_version": 1, "kind": "source-change-proposal", "created_at": datetime.now(timezone.utc).isoformat(),
            "policy": "review evidence only; does not approve, import or deploy any rule", "source_id": source["id"],
            "repository": REPOSITORY, "accepted_commit": accepted, "proposed_commit": latest,
            "changed": any(item["changed"] for item in files), "license": {"declared": "MIT", **licenses}, "files": files}


def produce(sources_path, output_path, fetch=fetch_text):
    sources_path, output_path = Path(sources_path).resolve(), Path(output_path).resolve()
    # Evidence has a dedicated namespace, away from private settings/runtime sets.
    artifact_root = (sources_path.parent.parent / ".local/source-proposals").resolve()
    if not output_path.is_relative_to(artifact_root) or output_path.suffix != ".json":
        raise ValueError("proposal output must be a JSON artifact under repository .local/source-proposals")
    result = proposal(json.loads(sources_path.read_text(encoding="utf-8")), fetch)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=output_path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(output_path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=ROOT / "rules/sources.json")
    parser.add_argument("--out", type=Path, default=ROOT / ".local/source-proposals/latest.json")
    args = parser.parse_args()
    try:
        result = produce(args.sources, args.out)
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        # Do not print network exceptions: they can contain credential-bearing headers.
        parser.exit(1, "Source proposal failed; accepted files and any prior proposal remain unchanged.\n")
    print("Source proposal saved; changed=" + str(result["changed"]).lower() + "; no accepted rules or runtime state changed")


if __name__ == "__main__":
    main()
