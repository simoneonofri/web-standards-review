#!/usr/bin/env python3
"""Fail-closed projection and public-core/private-overlay bridge."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


TOOL_VERSION = "reviewctl/0.2.0"
PUBLIC_STATUS = (
    "This project contains independent tools and review methods maintained by Simone Onofri. "
    "It is informed by work on Web standards and W3C processes, but it is not an official W3C "
    "deliverable. Its outputs do not represent a W3C, Working Group, Interest Group, TAG, or "
    "horizontal-review group position unless adopted through the applicable process."
)
TEXT_SUFFIXES = {
    ".md", ".txt", ".rst", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".html",
    ".css", ".csv", ".tsv", ".xml", ".bs", ".diff", ".patch", ".mmd",
}
SPECIAL_TEXT_NAMES = {
    "SKILL.md", "AGENTS.md", "CLAUDE.md", "Makefile", "Dockerfile", "reviewctl", ".gitignore", ".dockerignore",
}
IGNORED_TREE_PARTS = {".git", ".pytest_cache", ".ruff_cache", "__pycache__"}
SECTION_RE = re.compile(r"<!-- section:(?P<id>[a-z0-9]+(?:-[a-z0-9]+)*)(?P<protected> protected)? -->")
PRIVATE_TOPOLOGY_HASHES = {
    "db7b0f1c90fda9acf531254c38afea7bb9e381d12fd57431f63a20b241c6ac9c",
    "cc1b9be78f134d927f7fdd65f836b803ae3865f2db87192ca59e878229b9143d",
    "d0ac142ddc98026dcf48d78b5cc2c53cb0f1cc28be61c379aa035b600702d37f",
    "62d9ff04cccdb910fba209d9d94046c9b67fd288c75b8d0b0157f9d67b541b6b",
    "b36abace1ba5e4e4689f500c123d2800a96ce5f3a14ed84e153e6154987328f8",
    "bff4042480486d0cca6d234f4326cf8be04ac7a6e87b2c5b4bcc1dd97fe2be22",
}
# Catalog v3 explicitly publishes portable whatwg-miner, threat-knowledge and
# standards-vulnerability-intel-miner. Their names are now shared interfaces;
# personal providers, paths, corpora and credentials remain excluded.
ALLOWED_OVERLAY_OPERATIONS = {
    "insert_before",
    "insert_after",
    "replace",
    "append",
    "remove_public_optional_section",
    "register_private_provider",
    "set_private_default",
}
BOUNDARY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("personal-path", re.compile(r"(?:/Users/[^/\s]+|/home/[^/\s]+|~)/(?:work|src|repos|projects)(?:/[^\s`\"'<>)]*)?")),
    ("local-endpoint", re.compile(r"https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?")),
    (
        "private-provider",
        re.compile(
            r"\b(?:private" + r"_provider|private" + r"-provider-id|Private" + r"KnowledgeProvider)\b"
        ),
    ),
    ("private-corpus", re.compile(r"\b(?:private" + r"_corpus|private" + r"-corpus-id)\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret-assignment", re.compile(r"\b(?:API_TOKEN|ACCESS_TOKEN|SECRET_KEY)\s*=\s*[^\s]{8,}")),
)


class ReviewError(RuntimeError):
    """Raised when a review bridge gate fails."""


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_json(path: Path, expected_schema: str | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReviewError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReviewError(f"{path}: top-level value must be an object")
    if expected_schema and value.get("schema_version") != expected_schema:
        raise ReviewError(f"{path}: expected schema_version {expected_schema}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_transaction(files: dict[Path, bytes]) -> None:
    """Stage every write first and restore prior bytes on a caught write failure.

    This is recoverable within one process, not a multi-file crash transaction.
    Callers must not run concurrent mutations of one installation.
    """
    staged: dict[Path, Path] = {}
    backups: dict[Path, Path | None] = {}
    written: list[Path] = []
    rollback_failed = False
    try:
        for destination, data in files.items():
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                raise ReviewError("transaction destination must be a regular file")
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(prefix=".reviewctl-", dir=destination.parent)
            staged[destination] = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            backups[destination] = None
            if destination.exists():
                descriptor, name = tempfile.mkstemp(prefix=".reviewctl-backup-", dir=destination.parent)
                os.close(descriptor)
                backups[destination] = Path(name)
                shutil.copy2(destination, name)
                staged[destination].chmod(destination.stat().st_mode & 0o777)
        for destination, temporary in staged.items():
            os.replace(temporary, destination)
            written.append(destination)
    except Exception:
        try:
            for destination in reversed(written):
                backup = backups[destination]
                if backup is None:
                    destination.unlink()
                else:
                    os.replace(backup, destination)
        except Exception as error:
            rollback_failed = True
            raise ReviewError("rollback failed; backup files were retained beside the installation outputs") from error
        raise
    finally:
        for temporary in [*staged.values(), *([] if rollback_failed else backups.values())]:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def safe_relative(value: str, field: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ReviewError(f"{field} must be a non-empty relative path without '..'")
    return path


def safe_join(root: Path, value: str, field: str) -> Path:
    relative = safe_relative(value, field)
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ReviewError(f"{field} escapes its approved root") from error
    return candidate


def run_git(repository: Path, *arguments: str, binary: bool = False) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=not binary,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"" if binary else "")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        raise ReviewError(f"git {' '.join(arguments)} failed: {str(detail).strip()}") from error
    return result.stdout


def git_blob(repository: Path, commit: str, source_path: str) -> tuple[bytes, str]:
    relative = safe_relative(source_path, "include_paths[].source")
    listing = str(run_git(repository, "ls-tree", commit, "--", relative.as_posix())).strip()
    if not listing:
        raise ReviewError(f"allowlisted source is missing at {commit}: {relative.as_posix()}")
    metadata, listed_path = listing.split("\t", 1)
    mode, object_type, _object_id = metadata.split()
    if listed_path != relative.as_posix() or object_type != "blob":
        raise ReviewError(f"allowlisted source is not an exact file: {relative.as_posix()}")
    if mode == "120000":
        raise ReviewError(f"symlink source is rejected: {relative.as_posix()}")
    return bytes(run_git(repository, "show", f"{commit}:{relative.as_posix()}", binary=True)), mode


def is_binary(path: Path, data: bytes) -> bool:
    if path.name not in SPECIAL_TEXT_NAMES and path.suffix.lower() not in TEXT_SUFFIXES:
        return True
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def boundary_findings(path: str, text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for code, pattern in BOUNDARY_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({"code": code, "path": path, "match": match.group(0)[:160]})
    for token in re.findall(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", text + "\n" + path):
        if hashlib.sha256(token.lower().encode("utf-8")).hexdigest() in PRIVATE_TOPOLOGY_HASHES:
            findings.append({"code": "private-topology-name", "path": path, "match": "[redacted]"})
    return findings


def apply_normalizations(path: str, data: bytes, rules: Iterable[dict[str, Any]]) -> bytes:
    matching = [rule for rule in rules if rule.get("path") == path]
    if not matching:
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReviewError(f"normalization targets non-text file: {path}") from error
    for rule in matching:
        if set(rule).difference({"path", "find", "replace", "expected_count", "action"}):
            raise ReviewError(f"unsupported normalization field for {path}")
        action = rule.get("action")
        if action is not None:
            if action not in {"portable_contract_resolution_v1", "portable_response_contract_resolution_v1"}:
                raise ReviewError(f"unknown deterministic normalization action for {path}: {action}")
            function_name = "resolve_contract_root" if action == "portable_contract_resolution_v1" else "resolve_workbench_root"
            signature = f"def {function_name}() -> Path:\n"
            count = text.count(signature)
            if count == 1:
                start = text.index(signature)
                following = re.search(
                    r"^def [A-Za-z_][A-Za-z0-9_]*\(",
                    text[start + len(signature):],
                    re.MULTILINE,
                )
                if following is None:
                    count = 0
                else:
                    end = start + len(signature) + following.start()
            replacement = (
                f"def {function_name}() -> Path:\n"
                "    explicit = os.environ.get(\"STANDARDS_REVIEW_CONTRACTS_ROOT\")\n"
                "    repository_root = Path(__file__).resolve().parents[1]\n"
                "    candidates = [Path(explicit)] if explicit else []\n"
                "    candidates.extend([repository_root, repository_root.parents[1]])\n"
                "    for candidate in candidates:\n"
                "        if (candidate / \"scripts\" / \"validate_threat_model_contract.py\").is_file():\n"
                "            return candidate\n"
                "    raise SystemExit(\n"
                "        \"Cannot find the shared threat-model contract validator. Set \"\n"
                "        \"STANDARDS_REVIEW_CONTRACTS_ROOT or install the contract tree in the project package.\"\n"
                "    )\n\n\n"
            )
            expected = rule.get("expected_count", 1)
            if count != expected:
                raise ReviewError(
                    f"normalization action for {path} expected {expected} matches, found {count}"
                )
            text = text[:start] + replacement + text[end:]
            continue
        find = rule.get("find")
        replacement = rule.get("replace")
        expected = rule.get("expected_count", 1)
        if not isinstance(find, str) or not isinstance(replacement, str) or not isinstance(expected, int):
            raise ReviewError(f"invalid normalization rule for {path}")
        count = text.count(find)
        if count != expected:
            raise ReviewError(f"normalization for {path} expected {expected} matches, found {count}")
        text = text.replace(find, replacement)
    return text.encode("utf-8")


def tree_digest(records: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: item["path"]):
        digest.update(record["path"].encode("utf-8") + b"\0")
        digest.update(record["sha256"].encode("ascii") + b"\n")
    return "sha256:" + digest.hexdigest()


def exact_tree_diff(previous: Path | None, projected: Path) -> str:
    old_files = {
        path.relative_to(previous).as_posix(): path.read_text(encoding="utf-8", errors="replace").splitlines(True)
        for path in previous.rglob("*")
        if path.is_file() and not path.is_symlink() and not ({".review"} | IGNORED_TREE_PARTS).intersection(path.parts)
    } if previous and previous.is_dir() else {}
    new_files = {
        path.relative_to(projected).as_posix(): path.read_text(encoding="utf-8", errors="replace").splitlines(True)
        for path in projected.rglob("*")
        if path.is_file() and not path.is_symlink() and not ({".review"} | IGNORED_TREE_PARTS).intersection(path.parts)
    }
    lines: list[str] = []
    for name in sorted(set(old_files) | set(new_files)):
        lines.extend(
            difflib.unified_diff(
                old_files.get(name, []),
                new_files.get(name, []),
                fromfile=f"a/{name}",
                tofile=f"b/{name}",
            )
        )
    normalized = [
        ("\n" if line[0] == " " else line[0] + "\n")
        if len(line) > 1 and line[0] in {"+", "-", " "} and not line[1:].strip()
        else line
        for line in lines
    ]
    return "".join(normalized)


def audit_tree(root: Path, rights: dict[str, Any] | None = None) -> dict[str, Any]:
    if not root.is_dir():
        raise ReviewError(f"audit target is not a directory: {root}")
    decisions = (rights or {}).get("files", {})
    findings: list[dict[str, Any]] = []
    inventory: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if any(part in IGNORED_TREE_PARTS for part in path.relative_to(root).parts):
            continue
        if path.suffix == ".pyc":
            continue
        if path.is_symlink():
            findings.append({"code": "symlink", "path": relative})
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        decision = decisions.get(relative, {})
        maximum = decision.get("max_bytes", 1_000_000)
        binary = is_binary(path, data)
        inventory.append({"path": relative, "size": len(data), "sha256": sha256_bytes(data), "binary": binary})
        if len(data) > maximum:
            findings.append({"code": "unscanned-large-file", "path": relative, "size": len(data)})
        if binary and not decision.get("binary_allowed", False):
            findings.append({"code": "unapproved-binary", "path": relative})
        if not binary:
            findings.extend(boundary_findings(relative, data.decode("utf-8")))
    return {
        "schema_version": "boundary-audit/v1",
        "tool_version": TOOL_VERSION,
        "root_digest": tree_digest(inventory),
        "inventory": inventory,
        "findings": findings,
        "status": "pass" if not findings else "blocked",
    }


def validate_public_contracts(root: Path, contracts: list[str]) -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and not is_binary(path, path.read_bytes())
    )
    missing = [contract for contract in contracts if contract not in combined]
    if missing:
        raise ReviewError(f"projection is missing expected contract declarations: {', '.join(missing)}")


def project(manifest_path: Path, source_root: Path, output_root: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path, "publication-manifest/v1")
    source = manifest.get("source")
    if not isinstance(source, dict):
        raise ReviewError("publication manifest requires source")
    repository = safe_join(source_root, str(source.get("repository_path", "")), "source.repository_path")
    declared_commit = str(source.get("commit", ""))
    resolved_commit = str(run_git(repository, "rev-parse", f"{declared_commit}^{{commit}}")).strip()
    if declared_commit not in {resolved_commit, resolved_commit[: len(declared_commit)]}:
        raise ReviewError("source commit did not resolve to the declared revision")
    include_paths = manifest.get("include_paths")
    if not isinstance(include_paths, list) or (not include_paths and not manifest.get("maintainer_files")):
        raise ReviewError("projection requires a positive file allowlist or reviewed maintainer files")
    targets: set[str] = set()
    excluded_paths = [
        safe_relative(str(value), "exclude_paths[]")
        for value in manifest.get("exclude_paths", [])
    ]
    staged: list[tuple[str, bytes, dict[str, Any], bool]] = []
    for index, item in enumerate(include_paths):
        if not isinstance(item, dict):
            raise ReviewError(f"include_paths[{index}] must be an object")
        source_path = str(item.get("source", ""))
        target_path = str(item.get("target", source_path))
        safe_relative(source_path, f"include_paths[{index}].source")
        safe_relative(target_path, f"include_paths[{index}].target")
        if target_path in targets:
            raise ReviewError(f"duplicate target path: {target_path}")
        targets.add(target_path)
        rights = item.get("rights")
        if not isinstance(rights, dict) or rights.get("include_decision") != "include":
            raise ReviewError(f"{source_path}: typed include rights decision is required")
        if not rights.get("source_class") or not rights.get("rights_status"):
            raise ReviewError(f"{source_path}: incomplete rights decision")
        source_relative = Path(source_path)
        if any(
            source_relative == excluded or excluded in source_relative.parents
            for excluded in excluded_paths
        ):
            raise ReviewError(f"{source_path}: allowlist intersects a defense-in-depth exclude")
        source_class = rights.get("source_class")
        if source_class in {
            "book-or-paid-training",
            "private-or-internal",
            "cache-or-database",
        }:
            raise ReviewError(f"{source_path}: {source_class} is excluded from public projection")
        if source_class in {"public-standard", "paper-or-article"} and rights.get(
            "redistribution_approved"
        ) is not True:
            raise ReviewError(f"{source_path}: full-text redistribution lacks explicit approval")
        if source_class == "open-licensed-framework" and not all(
            isinstance(rights.get(field), str) and rights[field].strip()
            for field in ("license", "attribution", "modification_status")
        ):
            raise ReviewError(
                f"{source_path}: open-licensed material requires license, attribution, and modification status"
            )
        if source_class == "synthetic-fixture" and rights.get("rights_status") != "synthetic-approved":
            raise ReviewError(f"{source_path}: synthetic fixture is not explicitly marked synthetic")
        data, _mode = git_blob(repository, resolved_commit, source_path)
        maximum = rights.get("max_bytes", 1_000_000)
        if not isinstance(maximum, int) or maximum <= 0 or len(data) > maximum:
            raise ReviewError(f"{source_path}: file exceeds its reviewed max_bytes")
        binary = is_binary(Path(target_path), data)
        if binary and not rights.get("binary_allowed", False):
            raise ReviewError(f"{source_path}: binary or unsupported type lacks an explicit decision")
        data = apply_normalizations(target_path, data, manifest.get("normalizations", []))
        data = apply_normalizations(target_path, data, manifest.get("private_dependency_replacements", []))
        if not binary:
            findings = boundary_findings(target_path, data.decode("utf-8"))
            if findings:
                raise ReviewError(f"{target_path}: unresolved public/private boundary findings: {findings}")
        staged.append((target_path, data, rights, binary))

    # A portable entrypoint may be an original adaptation rather than a copy of
    # a private SKILL.md. Keep that adaptation in this reviewed repository, with
    # its own pinned digest, instead of embedding private source text in rules.
    for item in manifest.get("maintainer_files", []):
        target_path = str(item.get("target", ""))
        safe_relative(target_path, "maintainer_files[].target")
        if target_path in targets:
            raise ReviewError(f"duplicate target path: {target_path}")
        targets.add(target_path)
        relative_origin = safe_relative(str(item.get("source", "")), "maintainer_files[].source")
        if any((manifest_path.parent / Path(*relative_origin.parts[:i])).is_symlink() for i in range(1, len(relative_origin.parts) + 1)):
            raise ReviewError("maintainer file path cannot contain symlinks")
        origin = safe_join(manifest_path.parent, str(relative_origin), "maintainer_files[].source")
        if origin.is_symlink() or not origin.is_file():
            raise ReviewError("maintainer file must be a regular reviewed file")
        data = origin.read_bytes()
        rights = item.get("rights", {})
        if rights != {"source_class": "original", "rights_status": "maintainer-owned", "include_decision": "include"}:
            raise ReviewError("maintainer files require an original maintainer-owned rights declaration")
        if sha256_bytes(data) != item.get("sha256"):
            raise ReviewError("maintainer file digest changed; review the new adaptation")
        if len(data) > 1_000_000 or is_binary(Path(target_path), data):
            raise ReviewError("maintainer adaptation must be bounded text")
        if boundary_findings(target_path, data.decode("utf-8")):
            raise ReviewError("maintainer adaptation contains unresolved boundary findings")
        staged.append((target_path, data, rights, False))

    target = safe_relative(str(manifest.get("target_path", "")), "target_path")
    final = (output_root / target).resolve()
    try:
        final.relative_to(output_root.resolve())
    except ValueError as error:
        raise ReviewError("target_path escapes output root") from error
    with tempfile.TemporaryDirectory(prefix="reviewctl-project-") as temporary:
        stage = Path(temporary) / target.name
        records: list[dict[str, Any]] = []
        rights_files: dict[str, Any] = {}
        for target_path, data, rights, binary in staged:
            destination = safe_join(stage, target_path, "include_paths[].target")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            records.append({"path": target_path, "sha256": sha256_bytes(data), "size": len(data), "binary": binary})
            rights_files[target_path] = rights
        status_data = ("# Project status\n\n" + PUBLIC_STATUS + "\n").encode("utf-8")
        (stage / "PROJECT_STATUS.md").write_bytes(status_data)
        records.append({"path": "PROJECT_STATUS.md", "sha256": sha256_bytes(status_data), "size": len(status_data), "binary": False})
        rights_files["PROJECT_STATUS.md"] = {
            "source_class": "original",
            "rights_status": "maintainer-owned",
            "include_decision": "generated",
            "binary_allowed": False,
            "max_bytes": 1_000_000,
        }
        validate_public_contracts(stage, list(manifest.get("expected_public_contracts", [])))
        rights_manifest = {
            "schema_version": "rights-manifest/v1",
            "manifest_reference": manifest.get("rights_manifest_reference"),
            "files": rights_files,
            "pending": manifest.get("rights_pending", []),
        }
        audit = audit_tree(stage, rights_manifest)
        if audit["status"] != "pass":
            raise ReviewError(f"projection boundary audit failed: {audit['findings']}")
        projection_diff = exact_tree_diff(final if final.exists() else None, stage)
        provenance = {
            "schema_version": "projection-provenance/v1",
            "project": manifest.get("project"),
            "skill_id": manifest.get("skill_id"),
            "source_repository": source.get("repository"),
            "source_commit": resolved_commit,
            "host_projection": manifest.get("host_projection", "portable"),
            "included_files": sorted(records, key=lambda item: item["path"]),
            "output_digest": tree_digest(records),
            "contract_versions": manifest.get("expected_public_contracts", []),
            "rights_manifest_reference": manifest.get("rights_manifest_reference"),
            "export_policy": "explicit-allowlist",
            "human_review_decision": manifest.get("human_review_decision"),
            "tool_version": TOOL_VERSION,
            "required_tests": manifest.get("required_tests", []),
        }
        expected_digest = manifest.get("expected_output_digest")
        if expected_digest is not None and expected_digest != provenance["output_digest"]:
            raise ReviewError(
                f"projection output digest changed: expected {expected_digest}, got {provenance['output_digest']}"
            )
        review_dir = stage / ".review"
        generated_rights = {
            "source_class": "original",
            "rights_status": "generated-metadata",
            "include_decision": "generated",
            "binary_allowed": False,
            "max_bytes": 1_000_000,
        }
        for generated_path in (
            ".review/provenance.json",
            ".review/rights.json",
            ".review/boundary-audit.json",
            ".review/projection.diff",
        ):
            rights_files[generated_path] = generated_rights
        write_json(review_dir / "provenance.json", provenance)
        write_json(review_dir / "rights.json", rights_manifest)
        (review_dir / "projection.diff").write_text(projection_diff, encoding="utf-8")
        audit = audit_tree(stage, rights_manifest)
        if audit["status"] != "pass":
            raise ReviewError(f"generated projection metadata failed boundary audit: {audit['findings']}")
        write_json(review_dir / "boundary-audit.json", audit)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            backup = final.with_name(final.name + ".reviewctl-backup")
            if backup.exists():
                raise ReviewError(f"stale projection backup blocks update: {backup}")
            final.rename(backup)
            try:
                shutil.copytree(stage, final)
            except Exception:
                backup.rename(final)
                raise
            shutil.rmtree(backup)
        else:
            shutil.copytree(stage, final)
    return provenance


def section_spans(text: str) -> dict[str, tuple[int, int, bool]]:
    matches = list(SECTION_RE.finditer(text))
    spans: dict[str, tuple[int, int, bool]] = {}
    for index, match in enumerate(matches):
        section_id = match.group("id")
        if section_id in spans:
            raise ReviewError(f"ambiguous duplicate semantic section: {section_id}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        spans[section_id] = (match.start(), end, bool(match.group("protected")))
    return spans


def patch_content(patch: dict[str, Any], base: Path) -> str:
    if "content" in patch and "source" in patch:
        raise ReviewError("overlay patch must use either content or source")
    if "source" in patch:
        content = safe_join(base, str(patch["source"]), "patch.source").read_text(encoding="utf-8")
    else:
        content = patch.get("content", "")
    if not isinstance(content, str):
        raise ReviewError("overlay patch content must be a string")
    if SECTION_RE.search(content):
        raise ReviewError("overlay content cannot introduce a semantic marker")
    return content


def apply_overlay(core: str, overlay: dict[str, Any], overlay_root: Path) -> tuple[str, dict[str, Any]]:
    patches = overlay.get("patches")
    if not isinstance(patches, list):
        raise ReviewError("overlay patches must be an array")
    seen: set[tuple[str, str]] = set()
    providers: dict[str, Any] = {}
    defaults: dict[str, Any] = {}
    text = core
    optional = set(overlay.get("public_optional_sections", []))
    protected_declared = set(overlay.get("protected_sections", []))
    original_spans = section_spans(core)
    protected = protected_declared | {
        section for section, (_, _, marked) in original_spans.items() if marked
    }
    for patch in patches:
        if not isinstance(patch, dict):
            raise ReviewError("overlay patch must be an object")
        if "line" in patch or "line_number" in patch:
            raise ReviewError("line-number patches are forbidden")
        operation = patch.get("operation")
        if operation not in ALLOWED_OVERLAY_OPERATIONS:
            raise ReviewError(f"unknown overlay operation: {operation}")
        section_id = str(patch.get("section_id", ""))
        identity = (str(operation), section_id or str(patch.get("provider_id", patch.get("key", ""))))
        if identity in seen:
            raise ReviewError(f"duplicate overlay patch: {identity}")
        seen.add(identity)
        if operation == "register_private_provider":
            provider_id = str(patch.get("provider_id", ""))
            if not provider_id:
                raise ReviewError("register_private_provider requires provider_id")
            providers[provider_id] = patch.get("interface")
            continue
        if operation == "set_private_default":
            key = str(patch.get("key", ""))
            if not key:
                raise ReviewError("set_private_default requires key")
            defaults[key] = patch.get("value")
            continue
        if operation == "append" and not section_id:
            text += "\n" + patch_content(patch, overlay_root).rstrip() + "\n"
            continue
        spans = section_spans(text)
        if section_id not in spans:
            raise ReviewError(f"missing overlay anchor: {section_id}")
        start, end, marker_protected = spans[section_id]
        if marker_protected or section_id in protected_declared:
            raise ReviewError(f"overlay cannot change protected contract section: {section_id}")
        content = patch_content(patch, overlay_root).rstrip() + "\n"
        if operation == "replace":
            marker_end = text.find("-->", start) + 3
            text = text[:marker_end] + "\n" + content + text[end:]
        elif operation == "insert_before":
            text = text[:start] + content + text[start:]
        elif operation == "insert_after":
            text = text[:end] + content + text[end:]
        elif operation == "append":
            text = text[:end] + content + text[end:]
        elif operation == "remove_public_optional_section":
            if section_id not in optional:
                raise ReviewError(f"section is not declared public optional: {section_id}")
            text = text[:start] + text[end:]
    changed = changed_sections(core, text)
    if changed.intersection(protected):
        raise ReviewError("overlay cannot change a protected contract section through adjacent content")
    return text, {"private_providers": providers, "private_defaults": defaults}


def installation_paths(path: Path) -> tuple[dict[str, Any], Path, Path, Path, Path]:
    install = load_json(path, "private-installation/v1")
    root = path.parent.resolve()
    core = safe_join(root, str(install.get("public", {}).get("core", "")), "public.core")
    overlay = safe_join(root, str(install.get("overlay", "")), "overlay")
    generated = safe_join(root, str(install.get("generated", "")), "generated")
    lock = safe_join(root, str(install.get("lock", "")), "lock")
    paths = [path.resolve(), core, overlay, generated, lock]
    if len(set(paths)) != len(paths) or any(
        a in b.parents or b in a.parents for index, a in enumerate(paths) for b in paths[index + 1:]
    ):
        raise ReviewError("installation inputs and outputs must be distinct and cannot overlap")
    return install, core, overlay, generated, lock


def compose_bytes(install: dict[str, Any], core: Path, overlay_path: Path) -> tuple[bytes, dict[str, Any]]:
    public = install.get("public", {})
    core_data = core.read_bytes()
    core_digest = sha256_bytes(core_data)
    if public.get("artifact_digest") != core_digest:
        raise ReviewError("public core digest does not match the installation declaration")
    overlay = load_json(overlay_path, "private-overlay/v1")
    overlay_digest = sha256_bytes(overlay_path.read_bytes())
    extends = overlay.get("extends")
    if not isinstance(extends, dict):
        raise ReviewError("overlay requires an extends declaration")
    expected_extends = {
        "skill": install.get("skill"),
        "version": public.get("version"),
        "commit": public.get("commit"),
        "digest": core_digest,
    }
    if any(extends.get(key) != value for key, value in expected_extends.items()):
        raise ReviewError("overlay extends declaration does not match the locked public core")
    composed, private_configuration = apply_overlay(
        core_data.decode("utf-8"), overlay, overlay_path.parent
    )
    allowed_interfaces = set(install.get("provider_interfaces", []))
    undeclared_interfaces = sorted(
        {
            interface
            for interface in private_configuration["private_providers"].values()
            if interface not in allowed_interfaces
        }
    )
    if undeclared_interfaces:
        raise ReviewError(
            f"private provider uses undeclared public interface: {', '.join(undeclared_interfaces)}"
        )
    metadata = {
        "public_version": public.get("version"),
        "public_commit": public.get("commit"),
        "public_digest": core_digest,
        "overlay_version": overlay.get("overlay_version"),
        "overlay_digest": overlay_digest,
        "contract_versions": install.get("contract_versions", {}),
        **private_configuration,
    }
    header = (
        "<!-- GENERATED — DO NOT EDIT\n"
        + json.dumps(metadata, indent=2, sort_keys=True)
        + "\n-->\n\n"
    )
    frontmatter = re.match(r"\A---\r?\n.*?\r?\n---(?:\r?\n|$)", composed, re.DOTALL)
    if not frontmatter:
        raise ReviewError("public core must start with skill YAML frontmatter")
    end = frontmatter.end()
    return (composed[:end] + "\n" + header + composed[end:]).encode("utf-8"), metadata


def compose(installation_path: Path) -> dict[str, Any]:
    install, core, overlay, generated, lock = installation_paths(installation_path)
    output, metadata = compose_bytes(install, core, overlay)
    lock_payload = {
        "schema_version": "review-lock/v1",
        "skill": install.get("skill"),
        "marketplace": install.get("marketplace"),
        "version": install["public"].get("version"),
        "commit": install["public"].get("commit"),
        "artifact_digest": install["public"].get("artifact_digest"),
        "overlay_version": metadata["overlay_version"],
        "overlay_digest": metadata["overlay_digest"],
        "contract_versions": install.get("contract_versions", {}),
        "generated_digest": sha256_bytes(output),
        "core_path": install["public"].get("core"),
    }
    write_transaction({generated: output, lock: json_bytes(lock_payload)})
    return lock_payload


def drift(installation_path: Path) -> dict[str, Any]:
    install, core, overlay, generated, lock = installation_paths(installation_path)
    locked = load_json(lock, "review-lock/v1")
    if not generated.is_file():
        raise ReviewError("generated private skill is missing")
    actual = sha256_bytes(generated.read_bytes())
    expected_bytes, _metadata = compose_bytes(install, core, overlay)
    expected = sha256_bytes(expected_bytes)
    if actual != locked.get("generated_digest") or actual != expected:
        raise ReviewError("generated private skill drift detected; do not edit generated output")
    return {"status": "clean", "generated_digest": actual}


def changed_sections(old: str, new: str) -> set[str]:
    old_spans = section_spans(old)
    new_spans = section_spans(new)
    changed = set(old_spans).symmetric_difference(new_spans)
    old_prefix = old[:min((span[0] for span in old_spans.values()), default=len(old))]
    new_prefix = new[:min((span[0] for span in new_spans.values()), default=len(new))]
    if old_prefix != new_prefix:
        changed.add("$preamble")
    for section_id in set(old_spans).intersection(new_spans):
        old_start, old_end, _ = old_spans[section_id]
        new_start, new_end, _ = new_spans[section_id]
        if old[old_start:old_end] != new[new_start:new_end]:
            changed.add(section_id)
    return changed


def overlay_touched_sections(overlay: dict[str, Any]) -> set[str]:
    return {
        str(patch.get("section_id"))
        for patch in overlay.get("patches", [])
        if patch.get("operation") not in {"register_private_provider", "set_private_default"}
        and patch.get("section_id")
    }


def overlay_owned_sections(core: str, overlay: dict[str, Any], root: Path) -> set[str]:
    """Include where inserted bytes actually land, not only their named anchor."""
    composed, _configuration = apply_overlay(core, overlay, root)
    return changed_sections(core, composed) | overlay_touched_sections(overlay)


def pull(installation_path: Path) -> dict[str, Any]:
    install, old_core, overlay_path, generated, lock = installation_paths(installation_path)
    drift(installation_path)
    update = install.get("update")
    if not isinstance(update, dict):
        raise ReviewError("private installation has no update candidate")
    new_core = safe_join(installation_path.parent.resolve(), str(update.get("core", "")), "update.core")
    if new_core in {installation_path.resolve(), overlay_path, generated, lock}:
        raise ReviewError("update core must be distinct from installation outputs")
    new_data = new_core.read_bytes()
    if sha256_bytes(new_data) != update.get("artifact_digest"):
        raise ReviewError("new public core digest does not match update declaration")
    old_text = old_core.read_text(encoding="utf-8")
    new_text = new_data.decode("utf-8")
    overlay = load_json(overlay_path, "private-overlay/v1")
    public_changes = changed_sections(old_text, new_text)
    conflicts = sorted(public_changes.intersection(overlay_owned_sections(old_text, overlay, overlay_path.parent)))
    if conflicts:
        raise ReviewError(f"explicit public/private overlay conflict: {', '.join(conflicts)}")
    candidate_install = json.loads(json.dumps(install))
    candidate_install["public"] = {
        **install["public"],
        "core": update["core"],
        "version": update.get("version"),
        "commit": update.get("commit"),
        "artifact_digest": update.get("artifact_digest"),
    }
    candidate_overlay = json.loads(json.dumps(overlay))
    candidate_overlay["extends"] = {
        "skill": install.get("skill"),
        "version": update.get("version"),
        "commit": update.get("commit"),
        "digest": update.get("artifact_digest"),
    }
    temporary_overlay = overlay_path.with_name(overlay_path.name + ".reviewctl-pull")
    if temporary_overlay.exists():
        raise ReviewError(f"stale pull overlay blocks update: {temporary_overlay}")
    write_json(temporary_overlay, candidate_overlay)
    try:
        output, metadata = compose_bytes(candidate_install, new_core, temporary_overlay)
    finally:
        temporary_overlay.unlink(missing_ok=True)
    for contract in candidate_install.get("contract_versions", {}).values():
        if contract not in output.decode("utf-8"):
            raise ReviewError(f"updated composition is missing contract declaration: {contract}")
    lock_payload = {
        "schema_version": "review-lock/v1",
        "skill": install.get("skill"),
        "marketplace": install.get("marketplace"),
        "version": update.get("version"),
        "commit": update.get("commit"),
        "artifact_digest": update.get("artifact_digest"),
        "overlay_version": metadata["overlay_version"],
        "overlay_digest": metadata["overlay_digest"],
        "contract_versions": install.get("contract_versions", {}),
        "generated_digest": sha256_bytes(output),
        "core_path": update.get("core"),
    }
    candidate_install.pop("update", None)
    write_transaction({generated: output, overlay_path: json_bytes(candidate_overlay),
                       lock: json_bytes(lock_payload), installation_path: json_bytes(candidate_install)})
    return {"status": "updated", "public_changed_sections": sorted(public_changes), "conflicts": [], "lock": lock_payload}


def section_body(text: str, section_id: str) -> str:
    spans = section_spans(text)
    if section_id not in spans:
        raise ReviewError(f"missing semantic section: {section_id}")
    start, end, _ = spans[section_id]
    return text[start:end]


def replace_section(text: str, section_id: str, value: str) -> str:
    start, end, protected = section_spans(text)[section_id]
    if protected:
        raise ReviewError(f"promotion cannot modify protected section: {section_id}")
    return text[:start] + value + text[end:]


def promote(installation_path: Path) -> dict[str, Any]:
    install, core, overlay_path, _generated, _lock = installation_paths(installation_path)
    candidate = safe_join(
        installation_path.parent.resolve(),
        str(install.get("promotion_candidate", "")),
        "promotion_candidate",
    )
    expected_bytes, _metadata = compose_bytes(install, core, overlay_path)
    expected = expected_bytes.decode("utf-8")
    candidate_text = candidate.read_text(encoding="utf-8")
    changed = changed_sections(expected, candidate_text)
    if "$preamble" in changed:
        raise ReviewError("promotion cannot change frontmatter, generated metadata, or unanchored preamble")
    if set(section_spans(expected)) != set(section_spans(candidate_text)):
        raise ReviewError("promotion cannot add or remove semantic sections; review the public core directly")
    overlay = load_json(overlay_path, "private-overlay/v1")
    protected = {identifier for identifier, span in section_spans(expected).items() if span[2]} | set(overlay.get("protected_sections", []))
    if changed.intersection(protected):
        raise ReviewError("promotion cannot change protected contract sections; review the public core directly")
    private_sections = overlay_owned_sections(core.read_text(encoding="utf-8"), overlay, overlay_path.parent)
    if changed.intersection(private_sections):
        raise ReviewError("promotion candidate changes private overlay output")
    claims = install.get("promotion_claims", {})
    missing_claims = sorted(
        section_id
        for section_id in changed
        if not isinstance(claims.get(section_id), dict)
        or claims[section_id].get("basis") not in {"public_source", "assumption"}
    )
    if missing_claims:
        raise ReviewError(f"promotion claims need a public source or explicit assumption: {', '.join(missing_claims)}")
    public_candidate = core.read_text(encoding="utf-8")
    for section_id in sorted(changed):
        value = section_body(candidate_text, section_id)
        findings = boundary_findings(section_id, value)
        if findings:
            raise ReviewError(f"promotion contains private or secret material: {findings}")
        public_candidate = replace_section(public_candidate, section_id, value)
    patch = "".join(
        difflib.unified_diff(
            core.read_text(encoding="utf-8").splitlines(True),
            public_candidate.splitlines(True),
            fromfile="a/SKILL.md",
            tofile="b/SKILL.md",
        )
    )
    report_path = safe_join(
        installation_path.parent.resolve(),
        str(install.get("promotion_report", "promotion/provenance.json")),
        "promotion_report",
    )
    patch_path = report_path.with_name("public.patch")
    paths = [installation_path.resolve(), core, overlay_path, _generated, _lock, candidate, report_path, patch_path]
    if len(set(paths)) != len(paths) or any(a in b.parents or b in a.parents for i, a in enumerate(paths) for b in paths[i + 1:]):
        raise ReviewError("promotion inputs and outputs must be distinct and cannot overlap")
    report = {
        "schema_version": "promotion-report/v1",
        "skill": install.get("skill"),
        "public_core_digest": sha256_bytes(core.read_bytes()),
        "candidate_sections": sorted(changed),
        "subtracted_overlay_sections": sorted(private_sections),
        "claim_sources": {section: claims[section] for section in sorted(changed)},
        "patch": patch_path.name,
        "status": "local-review-only",
        "remote_write": False,
        "tool_version": TOOL_VERSION,
    }
    report_bytes = json_bytes(report)
    if boundary_findings("promotion-report", report_bytes.decode("utf-8")) or boundary_findings("public.patch", patch):
        raise ReviewError("promotion artifacts contain private or secret material")
    write_transaction({patch_path: patch.encode("utf-8"), report_path: report_bytes})
    return report


EXPECTED_PRIVATE_BETA_SKILLS = (
    "what-are-we-building",
    "dfd-mermaid",
    "what-can-go-wrong",
    "what-are-we-going-to-do-about-it",
    "did-we-do-a-good-enough-job",
    "threat-card-generator",
    "fact-check",
    "spec-review",
    "w3c-webappsec-miner",
    "whatwg-miner",
    "w3c-spec-miner",
    "w3c-security-pattern-miner",
    "w3c-horizontal-review-patterns-miner",
    "standards-vulnerability-intel-miner",
    "strategy-charter-miner",
    "threat-knowledge",
    "w3c-spec-code",
    "w3c-horizontal-review",
    "w3c-issue-pr-review",
)
SUPPORTED_MARKETPLACE_HOSTS = ("codex", "claude")
MARKETPLACE_LOCK_SCHEMA = "web-standards-review-lock/v1"


def marketplace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def catalog_entries(catalog: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    values = catalog.get(key)
    if not isinstance(values, list):
        raise ReviewError(f"catalog {key} must be a list")
    entries: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            raise ReviewError(f"catalog {key} entries require string ids")
        identifier = value["id"]
        if identifier in entries:
            raise ReviewError(f"duplicate catalog {key} id: {identifier}")
        entries[identifier] = value
    return entries


def load_catalog(root: Path) -> dict[str, Any]:
    catalog = load_json(root / "catalog.yaml", "web-standards-review-catalog/v1")
    if catalog.get("status") != "private-beta":
        raise ReviewError("catalog status must be private-beta")
    if catalog.get("publication_review_required") is not True:
        raise ReviewError("catalog must retain publication_review_required")
    if catalog.get("official_w3c_deliverable") is not False:
        raise ReviewError("catalog must preserve the independent/non-official-W3C boundary")
    if set(catalog.get("supported_hosts", [])) != set(SUPPORTED_MARKETPLACE_HOSTS):
        raise ReviewError("catalog supported_hosts must be exactly codex and claude")
    skills = catalog_entries(catalog, "skills")
    inventories = {
        2: EXPECTED_PRIVATE_BETA_SKILLS[:8],
        3: EXPECTED_PRIVATE_BETA_SKILLS[:18],
        4: EXPECTED_PRIVATE_BETA_SKILLS,
    }
    expected_skills = inventories.get(catalog.get("catalog_version"))
    if expected_skills is None:
        raise ReviewError("unsupported catalog version")
    if tuple(skills) != expected_skills:
        raise ReviewError("catalog must contain the reviewed ordered skill inventory")
    discovered = {
        path.parent.name
        for path in (root / "skills").glob("*/SKILL.md")
        if path.is_file()
    }
    if discovered != set(skills):
        raise ReviewError(
            "catalog/installable skill mismatch: "
            f"catalog={sorted(skills)} discovered={sorted(discovered)}"
        )
    for identifier, entry in skills.items():
        skill_path = safe_join(root, str(entry.get("path", "")), f"skills[{identifier}].path")
        if skill_path != (root / "skills" / identifier).resolve() or not (skill_path / "SKILL.md").is_file():
            raise ReviewError(f"catalog skill path does not resolve exactly: {identifier}")
        if entry.get("review_state") != "publication_review_required":
            raise ReviewError(f"catalog skill lacks publication review gate: {identifier}")
        if set(entry.get("supported_hosts", [])) != set(SUPPORTED_MARKETPLACE_HOSTS):
            raise ReviewError(f"catalog skill host projection mismatch: {identifier}")
        source = entry.get("source")
        if not isinstance(source, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", ""))):
            raise ReviewError(f"catalog skill source pin is invalid: {identifier}")
        for field in ("publication_manifest", "projection_manifest"):
            reference = safe_join(root, str(source.get(field, "")), f"skills[{identifier}].source.{field}")
            if not reference.is_file():
                raise ReviewError(f"catalog skill reference is missing: {identifier}:{field}")
        contracts = entry.get("contracts")
        if not isinstance(contracts, dict) or not all(
            isinstance(contracts.get(field), list) for field in ("consumes", "produces")
        ):
            raise ReviewError(f"catalog skill contracts are incomplete: {identifier}")
    bundles = catalog_entries(catalog, "bundles")
    if set(bundles) != {"threat-modeling-flow-v1"}:
        raise ReviewError("catalog must contain only threat-modeling-flow-v1 in Phase 1")
    bundle = bundles["threat-modeling-flow-v1"]
    if bundle.get("skills") != list(expected_skills):
        raise ReviewError("review bundle must install the complete reviewed skill inventory")
    for field in ("path", "source_pins_and_digests"):
        reference = safe_join(root, str(bundle.get(field, "")), f"bundles[0].{field}")
        if not reference.is_file():
            raise ReviewError(f"bundle reference is missing: {field}")
    contracts = bundle.get("contracts")
    if not isinstance(contracts, dict):
        raise ReviewError("bundle contracts are missing")
    for field in ("manifest", "root"):
        reference = safe_join(root, str(contracts.get(field, "")), f"bundle.contracts.{field}")
        if not reference.exists():
            raise ReviewError(f"bundle contract reference is missing: {field}")
    export = catalog.get("export")
    if not isinstance(export, dict) or export.get("remote_write") is not False:
        raise ReviewError("catalog export policy must be local-only")
    if export.get("publication_status") != "publication_review_required":
        raise ReviewError("catalog export policy must retain publication review")
    return catalog


def optional_git(repository: Path, *arguments: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        return None
    return result.stdout.strip()


def repository_state(root: Path) -> dict[str, str]:
    top = Path(str(run_git(root, "rev-parse", "--show-toplevel")).strip()).resolve()
    if top != root.resolve():
        raise ReviewError(f"marketplace must be run from its repository root: {top}")
    commit = str(run_git(root, "rev-parse", "HEAD^{commit}")).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReviewError("repository HEAD is not an exact commit")
    dirty = str(run_git(root, "status", "--porcelain", "--untracked-files=all")).strip()
    if dirty:
        raise ReviewError("marketplace checkout is dirty; install/update/export requires an exact clean commit")
    remote = optional_git(root, "config", "--get", "remote.origin.url") or root.resolve().as_uri()
    return {"commit": commit, "repository": remote, "repository_path": str(root.resolve())}


def file_inventory(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED_TREE_PARTS for part in relative.parts) or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise ReviewError(f"symlink is not allowed in a catalog artifact: {relative.as_posix()}")
        if not path.is_file():
            continue
        data = path.read_bytes()
        records.append(
            {
                "path": relative.as_posix(),
                "size": len(data),
                "sha256": sha256_bytes(data),
            }
        )
    return records


def artifact_digest(path: Path) -> str:
    return tree_digest(file_inventory(path))


def host_skill_roots() -> dict[str, Path]:
    home = Path.home()
    return {
        "codex": Path(
            os.environ.get("WEB_STANDARDS_REVIEW_CODEX_SKILLS_ROOT", home / ".agents" / "skills")
        ).expanduser().resolve(strict=False),
        "claude": Path(
            os.environ.get("WEB_STANDARDS_REVIEW_CLAUDE_SKILLS_ROOT", home / ".claude" / "skills")
        ).expanduser().resolve(strict=False),
    }


def marketplace_state_dir(explicit: Path | None = None) -> Path:
    value = explicit or Path(
        os.environ.get(
            "WEB_STANDARDS_REVIEW_STATE_DIR",
            Path.home() / ".local" / "state" / "web-standards-review",
        )
    )
    return value.expanduser().resolve(strict=False)


def marketplace_lock_path(explicit: Path | None = None) -> Path:
    return marketplace_state_dir(explicit) / "install.lock.json"


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    data = json.dumps(value, indent=2, sort_keys=True) + "\n"
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def selected_catalog_skills(
    catalog: dict[str, Any], skill_id: str | None, bundle_id: str | None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    skills = catalog_entries(catalog, "skills")
    bundles = catalog_entries(catalog, "bundles")
    bundle_versions: dict[str, int] = {}
    if skill_id:
        if skill_id not in skills:
            raise ReviewError(f"skill is not catalog-listed: {skill_id}")
        selected = [skills[skill_id]]
    elif bundle_id:
        if bundle_id not in bundles:
            raise ReviewError(f"bundle is not catalog-listed: {bundle_id}")
        bundle = bundles[bundle_id]
        selected = [skills[identifier] for identifier in bundle["skills"]]
        bundle_versions[bundle_id] = int(bundle["version"])
    else:
        raise ReviewError("select exactly one --skill or --bundle")
    return selected, bundle_versions


def symlink_target(path: Path) -> Path:
    value = Path(os.readlink(path))
    if not value.is_absolute():
        value = path.parent / value
    return value.resolve(strict=False)


def snapshot_path(root: Path, commit: str, state_dir: Path | None) -> Path:
    path = marketplace_state_dir(state_dir) / "snapshots" / commit
    if path.resolve().is_relative_to(root.resolve()):
        raise ReviewError("installation snapshots must be outside the source checkout")
    return path


def verify_snapshot(path: Path, commit: str, manifest_digest: str | None = None) -> None:
    if path.is_symlink():
        raise ReviewError("snapshot cannot be a symlink")
    manifest = load_json(path / ".review/export-manifest.json", "marketplace-export-manifest/v1")
    if manifest_digest and sha256_bytes((path / ".review/export-manifest.json").read_bytes()) != manifest_digest:
        raise ReviewError("snapshot manifest has changed")
    if manifest.get("source_commit") != commit:
        raise ReviewError("snapshot does not match the accepted commit")
    actual = [row for row in file_inventory(path) if row["path"] not in {".review/export-manifest.json", ".review/review-report.json"}]
    if actual != manifest.get("files"):
        raise ReviewError("installed snapshot has changed; refuse to reuse it")


def ensure_snapshot(root: Path, commit: str, state_dir: Path | None) -> Path:
    path = snapshot_path(root, commit, state_dir)
    if not path.exists():
        export_marketplace(root, path, commit)
    verify_snapshot(path, commit)
    return path


def install_marketplace(
    root: Path,
    *,
    skill_id: str | None,
    bundle_id: str | None,
    host: str,
    dry_run: bool,
    replace_link: bool,
    state_dir: Path | None,
) -> dict[str, Any]:
    catalog = load_catalog(root)
    repository = repository_state(root)
    selected, bundle_versions = selected_catalog_skills(catalog, skill_id, bundle_id)
    hosts = list(SUPPORTED_MARKETPLACE_HOSTS) if host == "all" else [host]
    if any(value not in SUPPORTED_MARKETPLACE_HOSTS for value in hosts):
        raise ReviewError(f"unsupported host: {host}")
    roots = host_skill_roots()
    snapshot = snapshot_path(root, repository["commit"], state_dir)
    lock_path = marketplace_lock_path(state_dir)
    existing: dict[str, Any] | None = None
    if lock_path.is_file():
        existing = load_json(lock_path, MARKETPLACE_LOCK_SCHEMA)
        if existing.get("repository_path") != repository["repository_path"]:
            raise ReviewError("existing marketplace lock belongs to a different checkout")
        if existing.get("commit") != repository["commit"] or not existing.get("snapshot_path"):
            raise ReviewError("update the existing installation before adding skills or hosts")
        verify_snapshot(Path(existing["snapshot_path"]), existing["commit"], existing.get("snapshot_manifest_digest"))
    actions: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for entry in selected:
        identifier = entry["id"]
        source_target = safe_join(root, entry["path"], f"skill:{identifier}")
        target = safe_join(snapshot, entry["path"], f"skill:{identifier}")
        digests[identifier] = artifact_digest(source_target)
        for host_name in hosts:
            destination = roots[host_name] / identifier
            action = "create"
            if destination.is_symlink():
                current = symlink_target(destination)
                if current == target.resolve():
                    action = "keep"
                elif replace_link:
                    action = "replace-link"
                else:
                    raise ReviewError(
                        f"refusing unrelated symlink for {host_name}:{identifier}: {current}"
                    )
            elif destination.exists():
                raise ReviewError(
                    f"refusing non-symlink installation for {host_name}:{identifier}: {destination}"
                )
            actions.append(
                {
                    "host": host_name,
                    "skill": identifier,
                    "action": action,
                    "link": str(destination),
                    "target": str(target.resolve()),
                    "artifact_digest": digests[identifier],
                }
            )
    result = {
        "schema_version": "marketplace-install-result/v1",
        "status": "dry-run" if dry_run else "installed",
        "repository": repository["repository"],
        "repository_path": repository["repository_path"],
        "commit": repository["commit"],
        "catalog_version": catalog["catalog_version"],
        "bundle_versions": bundle_versions,
        "actions": actions,
        "lock": str(lock_path),
    }
    if dry_run:
        return result
    created: list[Path] = []
    ensure_snapshot(root, repository["commit"], state_dir)
    replaced: list[tuple[Path, str]] = []
    try:
        for action in actions:
            destination = Path(action["link"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            if action["action"] == "replace-link":
                replaced.append((destination, os.readlink(destination)))
                destination.unlink()
            if action["action"] in {"create", "replace-link"}:
                os.symlink(action["target"], destination)
                created.append(destination)
        lock = existing or {
            "schema_version": MARKETPLACE_LOCK_SCHEMA,
            "hosts": {},
            "bundle_versions": {},
        }
        lock.update(
            {
                "repository": repository["repository"],
                "repository_path": repository["repository_path"],
                "commit": repository["commit"],
                "catalog_version": catalog["catalog_version"],
                "publication_status": "publication_review_required",
                "snapshot_path": str(snapshot),
                "snapshot_manifest_digest": sha256_bytes((snapshot / ".review/export-manifest.json").read_bytes()),
            }
        )
        lock["bundle_versions"] = {**lock.get("bundle_versions", {}), **bundle_versions}
        host_records = lock.setdefault("hosts", {})
        for action in actions:
            host_record = host_records.setdefault(
                action["host"], {"skills_root": str(roots[action["host"]]), "skills": {}}
            )
            host_record["skills_root"] = str(roots[action["host"]])
            host_record.setdefault("skills", {})[action["skill"]] = {
                "link": action["link"],
                "target": action["target"],
                "artifact_digest": action["artifact_digest"],
            }
        lock["installed_skills"] = sorted(
            {
                identifier
                for host_record in host_records.values()
                for identifier in host_record.get("skills", {})
            }
        )
        atomic_write_json(lock_path, lock)
    except Exception:
        for path in reversed(created):
            if path.is_symlink():
                path.unlink()
        for path, old_target in reversed(replaced):
            if not path.exists() and not path.is_symlink():
                os.symlink(old_target, path)
        raise
    return result


def marketplace_status(state_dir: Path | None = None) -> dict[str, Any]:
    lock_path = marketplace_lock_path(state_dir)
    if not lock_path.is_file():
        return {
            "schema_version": "marketplace-status/v1",
            "status": "not-installed",
            "lock": str(lock_path),
            "findings": [],
        }
    lock = load_json(lock_path, MARKETPLACE_LOCK_SCHEMA)
    findings: list[dict[str, Any]] = []
    if lock.get("snapshot_path"):
        try:
            verify_snapshot(Path(lock["snapshot_path"]), lock["commit"], lock.get("snapshot_manifest_digest"))
        except (ReviewError, OSError) as error:
            findings.append({"code": "snapshot-drift", "message": str(error)})
    else:
        findings.append({"code": "legacy-live-installation", "message": "update to isolate the installation from checkout edits"})
    repository_path = Path(str(lock.get("repository_path", "")))
    current_commit: str | None = None
    if not repository_path.is_dir():
        findings.append({"code": "repository-missing", "path": str(repository_path)})
    else:
        try:
            current_commit = str(run_git(repository_path, "rev-parse", "HEAD^{commit}")).strip()
            dirty = str(
                run_git(repository_path, "status", "--porcelain", "--untracked-files=all")
            ).strip()
            if dirty:
                findings.append({"code": "repository-dirty"})
            if current_commit != lock.get("commit"):
                findings.append(
                    {
                        "code": "commit-drift",
                        "locked": lock.get("commit"),
                        "current": current_commit,
                    }
                )
            catalog = load_catalog(repository_path)
            if catalog.get("catalog_version") != lock.get("catalog_version"):
                findings.append(
                    {
                        "code": "catalog-drift",
                        "locked": lock.get("catalog_version"),
                        "current": catalog.get("catalog_version"),
                    }
                )
        except ReviewError as error:
            findings.append({"code": "repository-invalid", "message": str(error)})
    for host, host_record in sorted(lock.get("hosts", {}).items()):
        for identifier, record in sorted(host_record.get("skills", {}).items()):
            link = Path(record["link"])
            target = Path(record["target"])
            if not link.is_symlink():
                findings.append({"code": "link-missing-or-replaced", "host": host, "skill": identifier})
                continue
            actual_target = symlink_target(link)
            if actual_target != target.resolve(strict=False):
                findings.append(
                    {
                        "code": "link-target-drift",
                        "host": host,
                        "skill": identifier,
                        "locked": str(target),
                        "current": str(actual_target),
                    }
                )
                continue
            if not target.is_dir():
                findings.append({"code": "target-missing", "host": host, "skill": identifier})
                continue
            try:
                current_digest = artifact_digest(target)
            except ReviewError as error:
                findings.append(
                    {"code": "artifact-invalid", "host": host, "skill": identifier, "message": str(error)}
                )
                continue
            if current_digest != record.get("artifact_digest"):
                findings.append(
                    {
                        "code": "artifact-drift",
                        "host": host,
                        "skill": identifier,
                        "locked": record.get("artifact_digest"),
                        "current": current_digest,
                    }
                )
    return {
        "schema_version": "marketplace-status/v1",
        "status": "clean" if not findings else "drift",
        "lock": str(lock_path),
        "locked_commit": lock.get("commit"),
        "current_commit": current_commit,
        "installed_skills": lock.get("installed_skills", []),
        "hosts": sorted(lock.get("hosts", {})),
        "findings": findings,
    }


def update_marketplace(*, dry_run: bool, state_dir: Path | None = None) -> dict[str, Any]:
    lock_path = marketplace_lock_path(state_dir)
    if not lock_path.is_file():
        raise ReviewError("marketplace is not installed")
    lock = load_json(lock_path, MARKETPLACE_LOCK_SCHEMA)
    if lock.get("snapshot_path"):
        verify_snapshot(Path(lock["snapshot_path"]), lock["commit"], lock.get("snapshot_manifest_digest"))
    root = Path(lock["repository_path"])
    catalog = load_catalog(root)
    repository = repository_state(root)
    skills = catalog_entries(catalog, "skills")
    snapshot = snapshot_path(root, repository["commit"], state_dir)
    actions: list[dict[str, Any]] = []
    for host, host_record in sorted(lock.get("hosts", {}).items()):
        for identifier, record in sorted(host_record.get("skills", {}).items()):
            if identifier not in skills:
                raise ReviewError(f"installed skill is no longer catalog-listed: {identifier}")
            link = Path(record["link"])
            old_target = Path(record["target"])
            if not link.is_symlink() or symlink_target(link) != old_target.resolve(strict=False):
                raise ReviewError(f"cannot update drifted link: {host}:{identifier}")
            source_target = safe_join(root, skills[identifier]["path"], f"skill:{identifier}")
            new_target = safe_join(snapshot, skills[identifier]["path"], f"skill:{identifier}")
            new_digest = artifact_digest(source_target)
            if new_digest != record.get("artifact_digest") or new_target.resolve() != old_target.resolve():
                actions.append(
                    {
                        "host": host,
                        "skill": identifier,
                        "link": str(link),
                        "old_target": str(old_target),
                        "new_target": str(new_target.resolve()),
                        "old_digest": record.get("artifact_digest"),
                        "new_digest": new_digest,
                    }
                )
    result = {
        "schema_version": "marketplace-update-result/v1",
        "status": "dry-run" if dry_run else "updated",
        "old_commit": lock.get("commit"),
        "new_commit": repository["commit"],
        "affected_skills": sorted({action["skill"] for action in actions}),
        "actions": actions,
        "lock": str(lock_path),
    }
    if dry_run:
        return result
    ensure_snapshot(root, repository["commit"], state_dir)
    changed_links = []
    try:
        for action in actions:
            link = Path(action["link"])
            if Path(action["old_target"]).resolve() != Path(action["new_target"]).resolve():
                temporary_link = link.with_name(link.name + ".reviewctl-update")
                if temporary_link.exists() or temporary_link.is_symlink():
                    raise ReviewError("stale update link blocks installation")
                previous = os.readlink(link)
                try:
                    os.symlink(action["new_target"], temporary_link)
                    os.replace(temporary_link, link)
                    changed_links.append((link, previous))
                finally:
                    temporary_link.unlink(missing_ok=True)
            record = lock["hosts"][action["host"]]["skills"][action["skill"]]
            record["target"] = action["new_target"]
            record["artifact_digest"] = action["new_digest"]
        lock.update({"repository": repository["repository"], "commit": repository["commit"],
                     "catalog_version": catalog["catalog_version"], "snapshot_path": str(snapshot),
                     "snapshot_manifest_digest": sha256_bytes((snapshot / ".review/export-manifest.json").read_bytes())})
        atomic_write_json(lock_path, lock)
    except Exception:
        for link, previous in reversed(changed_links):
            link.unlink(missing_ok=True)
            os.symlink(previous, link)
        raise
    return result


def uninstall_marketplace(
    *, host: str, dry_run: bool, state_dir: Path | None = None
) -> dict[str, Any]:
    lock_path = marketplace_lock_path(state_dir)
    if not lock_path.is_file():
        raise ReviewError("marketplace is not installed")
    lock = load_json(lock_path, MARKETPLACE_LOCK_SCHEMA)
    selected_hosts = sorted(lock.get("hosts", {})) if host == "all" else [host]
    actions: list[dict[str, str]] = []
    for host_name in selected_hosts:
        host_record = lock.get("hosts", {}).get(host_name)
        if host_record is None:
            continue
        for identifier, record in sorted(host_record.get("skills", {}).items()):
            link = Path(record["link"])
            target = Path(record["target"]).resolve(strict=False)
            if not link.is_symlink() or symlink_target(link) != target:
                raise ReviewError(f"refusing to remove drifted or unrelated path: {host_name}:{identifier}")
            actions.append({"host": host_name, "skill": identifier, "link": str(link)})
    result = {
        "schema_version": "marketplace-uninstall-result/v1",
        "status": "dry-run" if dry_run else "uninstalled",
        "actions": actions,
        "lock": str(lock_path),
    }
    if dry_run:
        return result
    for action in actions:
        Path(action["link"]).unlink()
    for host_name in selected_hosts:
        lock.get("hosts", {}).pop(host_name, None)
    if lock.get("hosts"):
        lock["installed_skills"] = sorted(
            {
                identifier
                for host_record in lock["hosts"].values()
                for identifier in host_record.get("skills", {})
            }
        )
        atomic_write_json(lock_path, lock)
    else:
        lock_path.unlink()
    return result


def audit_marketplace(root: Path) -> dict[str, Any]:
    catalog = load_catalog(root)
    boundary = audit_tree(root)
    skill_results: dict[str, Any] = {}
    rights_findings: list[dict[str, Any]] = []
    component_results: dict[str, Any] = {}
    components = catalog_entries(catalog, "components")
    discovered_components = {path.name for path in (root / "providers").iterdir() if path.is_dir()}
    if discovered_components != set(components):
        rights_findings.append({"code": "component-inventory-mismatch"})
    for identifier, entry in components.items():
        component = safe_join(root, entry["path"], f"component:{identifier}")
        if component != (root / "providers" / identifier).resolve():
            raise ReviewError("component path must match its identifier")
        review = load_json(component / ".review/inventory.json", "reviewed-component-inventory/v1")
        actual = [row for row in file_inventory(component) if row["path"] != ".review/inventory.json"]
        valid = actual == review.get("files") and review.get("publication_status") == "publication_review_required"
        component_results[identifier] = {"status": "pass" if valid else "blocked", "files": len(actual)}
        if not valid:
            rights_findings.append({"component": identifier, "code": "component-review-drift"})
    for identifier, entry in catalog_entries(catalog, "skills").items():
        skill_root = safe_join(root, entry["path"], f"skill:{identifier}")
        rights = load_json(skill_root / ".review" / "rights.json", "rights-manifest/v1")
        actual = {record["path"] for record in file_inventory(skill_root)}
        declared = set(rights.get("files", {}))
        if actual != declared:
            rights_findings.append(
                {
                    "skill": identifier,
                    "unlisted": sorted(actual - declared),
                    "missing": sorted(declared - actual),
                }
            )
        audit = audit_tree(skill_root, rights)
        skill_results[identifier] = {
            "status": audit["status"],
            "root_digest": audit["root_digest"],
            "findings": audit["findings"],
        }
    findings = list(boundary["findings"])
    findings.extend({"code": "rights-inventory-mismatch", **item} for item in rights_findings)
    findings.extend(
        {"code": "skill-boundary", "skill": identifier, "findings": value["findings"]}
        for identifier, value in skill_results.items()
        if value["status"] != "pass"
    )
    return {
        "schema_version": "marketplace-audit/v1",
        "status": "pass" if not findings else "blocked",
        "publication_status": "publication_review_required",
        "catalog_version": catalog["catalog_version"],
        "root_digest": boundary["root_digest"],
        "boundary_findings": boundary["findings"],
        "rights_findings": rights_findings,
        "skills": skill_results,
        "components": component_results,
        "findings": findings,
    }


def path_is_selected(path: str, exact: set[str], roots: tuple[str, ...]) -> bool:
    relative = Path(path)
    return path in exact or any(relative == Path(root) or Path(root) in relative.parents for root in roots)


def export_marketplace(root: Path, output: Path, ref: str | None) -> dict[str, Any]:
    repository = repository_state(root)
    commit = repository["commit"]
    if ref is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise ReviewError("--ref must be an exact 40-character commit")
        resolved = str(run_git(root, "rev-parse", f"{ref}^{{commit}}")).strip()
        if resolved != ref:
            raise ReviewError("--ref did not resolve to the exact declared commit")
        commit = resolved
    if output.exists() or output.is_symlink():
        raise ReviewError(f"export output already exists: {output}")
    catalog_data, _mode = git_blob(root, commit, "catalog.yaml")
    try:
        catalog_at_ref = json.loads(catalog_data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError(f"catalog at {commit} is invalid: {error}") from error
    export = catalog_at_ref.get("export")
    if not isinstance(export, dict) or export.get("remote_write") is not False:
        raise ReviewError("catalog at ref lacks a local-only export policy")
    roots = tuple(str(value) for value in export.get("include_roots", []))
    exact = {str(value) for value in export.get("include_files", [])}
    excludes = tuple(str(value) for value in export.get("exclude_paths", []))
    tree_entries = {}
    for row in run_git(root, "ls-tree", "-r", "-z", commit, binary=True).split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        tree_entries[name.decode("utf-8")] = (mode, kind, object_id)
    names = list(tree_entries)
    selected = [
        name
        for name in names
        if path_is_selected(name, exact, roots) and not path_is_selected(name, set(), excludes)
    ]
    if not selected:
        raise ReviewError("export positive allowlist selected no files")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="reviewctl-export-", dir=output.parent) as temporary:
        stage = Path(temporary) / "marketplace"
        stage.mkdir()
        # Batch raw immutable blobs. Unlike git archive, this cannot apply
        # export-subst/export-ignore attributes to the selected commit's bytes.
        for name in selected:
            mode, kind, _object_id = tree_entries[name]
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise ReviewError(f"export rejects symlink or unsupported Git mode: {name}")
        object_ids = [tree_entries[name][2] for name in selected]
        process = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"],
                                 input=("\n".join(object_ids) + "\n").encode("ascii"),
                                 capture_output=True, check=False)
        if process.returncode:
            raise ReviewError("Git could not read the selected export blobs")
        data, offset = process.stdout, 0
        for name, object_id in zip(selected, object_ids):
            end = data.find(b"\n", offset)
            header = data[offset:end].decode("ascii").split()
            if end < 0 or len(header) != 3 or header[:2] != [object_id, "blob"]:
                raise ReviewError("Git export blob identity mismatch")
            size = int(header[2])
            start = end + 1
            if size < 0 or data[start + size:start + size + 1] != b"\n":
                raise ReviewError("Git export blob length mismatch")
            destination = safe_join(stage, name, "export path")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data[start:start + size])
            destination.chmod(0o755 if tree_entries[name][0] == "100755" else 0o644)
            offset = start + size + 1
        if offset != len(data):
            raise ReviewError("Git export contains unexpected trailing bytes")
        load_catalog(stage)
        audit = audit_marketplace(stage)
        if audit["status"] != "pass":
            raise ReviewError(f"export audit blocked: {audit['findings']}")
        inventory = file_inventory(stage)
        manifest = {
            "schema_version": "marketplace-export-manifest/v1",
            "source_commit": commit,
            "publication_status": "publication_review_required",
            "remote_write": False,
            "files": inventory,
            "tree_digest": tree_digest(inventory),
        }
        manifest_path = stage / ".review" / "export-manifest.json"
        write_json(manifest_path, manifest)
        report = {
            "schema_version": "marketplace-export-review/v1",
            "source_commit": commit,
            "publication_status": "publication_review_required",
            "remote_created": False,
            "remote_write": False,
            "boundary_status": audit["status"],
            "rights_status": "pass" if not audit["rights_findings"] else "blocked",
            "export_manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
            "human_review_required": True,
        }
        write_json(stage / ".review" / "review-report.json", report)
        final_audit = audit_tree(stage)
        if final_audit["status"] != "pass":
            raise ReviewError(f"generated export metadata failed audit: {final_audit['findings']}")
        shutil.move(str(stage), str(output))
    return {
        "schema_version": "marketplace-export-result/v1",
        "status": "exported",
        "output": str(output.resolve()),
        "source_commit": commit,
        "tree_digest": manifest["tree_digest"],
        "file_count": len(manifest["files"]),
        "publication_status": "publication_review_required",
        "remote_write": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="reviewctl", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("catalog")
    project_parser = subparsers.add_parser("project")
    project_parser.add_argument("manifest", type=Path)
    project_parser.add_argument("--source-root", type=Path, required=True)
    project_parser.add_argument("--output-root", type=Path, required=True)
    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("target", type=Path)
    subparsers.add_parser("audit-marketplace")
    install_parser = subparsers.add_parser("install")
    selection = install_parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--skill")
    selection.add_argument("--bundle")
    install_parser.add_argument("--host", choices=("codex", "claude", "all"), required=True)
    install_parser.add_argument("--dry-run", action="store_true")
    install_parser.add_argument("--replace-link", action="store_true")
    install_parser.add_argument("--state-dir", type=Path)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--state-dir", type=Path)
    update_parser = subparsers.add_parser("update")
    update_parser.add_argument("--dry-run", action="store_true")
    update_parser.add_argument("--state-dir", type=Path)
    uninstall_parser = subparsers.add_parser("uninstall")
    uninstall_parser.add_argument("--host", choices=("codex", "claude", "all"), default="all")
    uninstall_parser.add_argument("--dry-run", action="store_true")
    uninstall_parser.add_argument("--state-dir", type=Path)
    for command in ("export-marketplace", "export-native-marketplace"):
        export_parser = subparsers.add_parser(command)
        export_parser.add_argument("--output", type=Path, required=True)
        export_parser.add_argument("--ref")
    private_parser = subparsers.add_parser("prepare-private")
    private_parser.add_argument("--output", type=Path, required=True)
    private_parser.add_argument("--previous", type=Path)
    private_parser.add_argument("--allow-new-skills", action="store_true")
    for command in ("compose", "diff", "pull", "promote"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("installation", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        root = marketplace_root()
        if args.command == "catalog":
            result = load_catalog(root)
        elif args.command == "project":
            result = project(args.manifest.resolve(), args.source_root.resolve(), args.output_root.resolve())
        elif args.command == "audit":
            rights_path = args.target / ".review" / "rights.json"
            rights = load_json(rights_path) if rights_path.is_file() else None
            result = audit_tree(args.target.resolve(), rights)
            if result["status"] != "pass":
                raise ReviewError(f"boundary audit blocked: {result['findings']}")
        elif args.command == "audit-marketplace":
            result = audit_marketplace(root)
            if result["status"] != "pass":
                raise ReviewError(f"marketplace audit blocked: {result['findings']}")
        elif args.command == "install":
            result = install_marketplace(
                root,
                skill_id=args.skill,
                bundle_id=args.bundle,
                host=args.host,
                dry_run=args.dry_run,
                replace_link=args.replace_link,
                state_dir=args.state_dir,
            )
        elif args.command == "status":
            result = marketplace_status(args.state_dir)
        elif args.command == "update":
            result = update_marketplace(dry_run=args.dry_run, state_dir=args.state_dir)
        elif args.command == "uninstall":
            result = uninstall_marketplace(
                host=args.host, dry_run=args.dry_run, state_dir=args.state_dir
            )
        elif args.command == "export-marketplace":
            result = export_marketplace(root, args.output.resolve(), args.ref)
        elif args.command in {"export-native-marketplace", "prepare-private"}:
            from package_workflows import export_native, prepare_private
            if args.command == "prepare-private":
                result = prepare_private(root, args.output.resolve(), args.previous.resolve() if args.previous else None, allow_new_skills=args.allow_new_skills)
            else:
                result = export_native(root, args.output.resolve(), args.ref)
        elif args.command == "compose":
            result = compose(args.installation.resolve())
        elif args.command == "diff":
            result = drift(args.installation.resolve())
        elif args.command == "pull":
            result = pull(args.installation.resolve())
        else:
            result = promote(args.installation.resolve())
    except (ReviewError, OSError, UnicodeError, KeyError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
