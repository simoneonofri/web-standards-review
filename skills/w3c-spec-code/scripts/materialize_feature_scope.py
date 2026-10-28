#!/usr/bin/env python3
"""Validate and materialize a fail-closed feature-scoped source packet."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA_VERSION = "w3c-spec-code-feature-scope/v1"
GENERIC_ROOTS = {
    ".",
    "src",
    "source",
    "browser",
    "engine",
    "components",
    "content",
    "third_party",
    "v8",
    "v8/src",
}
ENGINE_COMPONENTS = {"v8", "spidermonkey", "javascriptcore"}
MAX_SCOPE_FILES = 5000
MAX_SCOPE_BYTES = 1073741824


class ScopeError(ValueError):
    """Raised when the manifest does not establish a safe, bounded scope."""


@dataclass(frozen=True)
class SelectedFile:
    relative_path: str
    source: Path
    size: int
    sha256: str
    category: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_relative(raw: Any, *, field: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeError(f"{field}: path must be a non-empty string")
    if "\\" in raw:
        raise ScopeError(f"{field}: use POSIX separators; backslashes are rejected")
    path = PurePosixPath(raw)
    if path.is_absolute():
        raise ScopeError(f"{field}: absolute paths are rejected: {raw}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ScopeError(f"{field}: traversal or dot components are rejected: {raw}")
    if ".git" in path.parts:
        raise ScopeError(f"{field}: Git metadata is outside the review scope: {raw}")
    return path


def is_engine_path(path: PurePosixPath) -> bool:
    lowered = {part.lower() for part in path.parts}
    return bool(lowered & ENGINE_COMPONENTS)


def reject_generic(path: PurePosixPath, *, field: str) -> None:
    value = path.as_posix().rstrip("/")
    if value.lower() in GENERIC_ROOTS:
        raise ScopeError(f"{field}: generic repository or subsystem root is rejected: {value}")


def ensure_no_symlink(repo: Path, path: PurePosixPath, *, field: str) -> Path:
    current = repo
    for part in path.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise ScopeError(f"{field}: path does not exist: {path.as_posix()}") from exc
        if stat.S_ISLNK(mode):
            raise ScopeError(f"{field}: symlinks are rejected: {current}")
    resolved_repo = repo.resolve()
    resolved = current.resolve()
    try:
        resolved.relative_to(resolved_repo)
    except ValueError as exc:
        raise ScopeError(f"{field}: path escapes the repository: {path.as_posix()}") from exc
    return current


def iter_regular_files(repo: Path, path: PurePosixPath, *, field: str) -> Iterable[Path]:
    target = ensure_no_symlink(repo, path, field=field)
    mode = target.lstat().st_mode
    if stat.S_ISREG(mode):
        yield target
        return
    if not stat.S_ISDIR(mode):
        raise ScopeError(f"{field}: only regular files and directories are allowed: {path.as_posix()}")
    for directory, dirnames, filenames in os.walk(target, followlinks=False):
        directory_path = Path(directory)
        kept_dirs: list[str] = []
        for name in sorted(dirnames):
            candidate = directory_path / name
            candidate_mode = candidate.lstat().st_mode
            if stat.S_ISLNK(candidate_mode):
                raise ScopeError(f"{field}: symlink inside selected directory: {candidate}")
            if name == ".git":
                raise ScopeError(f"{field}: Git metadata inside selected directory: {candidate}")
            if not stat.S_ISDIR(candidate_mode):
                raise ScopeError(f"{field}: non-directory entry in directory list: {candidate}")
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            candidate = directory_path / name
            candidate_mode = candidate.lstat().st_mode
            if stat.S_ISLNK(candidate_mode):
                raise ScopeError(f"{field}: symlink inside selected directory: {candidate}")
            if not stat.S_ISREG(candidate_mode):
                raise ScopeError(f"{field}: non-regular file is rejected: {candidate}")
            yield candidate


def require_string(value: Any, *, field: str, minimum: int = 1) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ScopeError(f"{field}: expected a string of at least {minimum} characters")
    return value.strip()


def require_evidence(item: Any, *, field: str) -> tuple[PurePosixPath, str, list[str]]:
    if not isinstance(item, dict):
        raise ScopeError(f"{field}: expected an object")
    path = normalize_relative(item.get("path"), field=f"{field}.path")
    reject_generic(path, field=f"{field}.path")
    rationale = require_string(item.get("rationale"), field=f"{field}.rationale", minimum=20)
    evidence = item.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ScopeError(f"{field}.evidence: at least one concrete evidence reference is required")
    normalized_evidence = [require_string(entry, field=f"{field}.evidence") for entry in evidence]
    return path, rationale, normalized_evidence


def validate_manifest_shape(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ScopeError("manifest: expected a JSON object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ScopeError(f"schema_version: expected {SCHEMA_VERSION}")
    for field in ("feature", "implementation"):
        if not isinstance(manifest.get(field), dict):
            raise ScopeError(f"{field}: expected an object")
    entry_points = manifest.get("entry_points")
    feature_paths = manifest.get("feature_paths")
    if not isinstance(entry_points, list) or not entry_points:
        raise ScopeError("entry_points: at least one concrete entry point is required")
    if not isinstance(feature_paths, list) or not feature_paths:
        raise ScopeError("feature_paths: at least one concrete feature path is required")
    for field in ("supporting_paths", "engine_dependencies", "excluded_paths"):
        if not isinstance(manifest.get(field), list):
            raise ScopeError(f"{field}: expected an array")
    budgets = manifest.get("budgets")
    if not isinstance(budgets, dict):
        raise ScopeError("budgets: expected an object")
    limits = {"max_files": MAX_SCOPE_FILES, "max_bytes": MAX_SCOPE_BYTES}
    for name, upper_bound in limits.items():
        value = budgets.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ScopeError(f"budgets.{name}: expected a positive integer")
        if value > upper_bound:
            raise ScopeError(f"budgets.{name}: {value} exceeds the hard limit {upper_bound}")
    return manifest


def collect(repo: Path, manifest: dict[str, Any]) -> list[SelectedFile]:
    selected: dict[str, SelectedFile] = {}
    excluded_paths = [normalize_relative(raw, field="excluded_paths") for raw in manifest["excluded_paths"]]

    def excluded(relative: PurePosixPath) -> bool:
        for prefix in excluded_paths:
            if relative == prefix or prefix in relative.parents:
                return True
        return False

    def add_path(path: PurePosixPath, *, category: str, field: str) -> None:
        for source in iter_regular_files(repo, path, field=field):
            relative = PurePosixPath(source.relative_to(repo).as_posix())
            if excluded(relative):
                continue
            if ".git" in relative.parts:
                raise ScopeError(f"{field}: Git metadata is rejected: {relative}")
            data_size = source.stat().st_size
            selected[relative.as_posix()] = SelectedFile(
                relative_path=relative.as_posix(),
                source=source,
                size=data_size,
                sha256=sha256_file(source),
                category=category,
            )

    for index, raw in enumerate(manifest["entry_points"]):
        path = normalize_relative(raw, field=f"entry_points[{index}]")
        reject_generic(path, field=f"entry_points[{index}]")
        if is_engine_path(path):
            raise ScopeError("entry_points: engine paths must be declared as evidenced engine_dependencies")
        entry_target = ensure_no_symlink(repo, path, field=f"entry_points[{index}]")
        if not stat.S_ISREG(entry_target.lstat().st_mode):
            raise ScopeError(f"entry_points[{index}]: entry points must identify a regular file")
        add_path(path, category="entry_point", field=f"entry_points[{index}]")

    for index, raw in enumerate(manifest["feature_paths"]):
        path = normalize_relative(raw, field=f"feature_paths[{index}]")
        reject_generic(path, field=f"feature_paths[{index}]")
        if is_engine_path(path):
            raise ScopeError("feature_paths: engine paths must be declared as evidenced engine_dependencies")
        add_path(path, category="feature", field=f"feature_paths[{index}]")

    for index, item in enumerate(manifest["supporting_paths"]):
        path, _, _ = require_evidence(item, field=f"supporting_paths[{index}]")
        if is_engine_path(path):
            raise ScopeError("supporting_paths: engine paths must use engine_dependencies")
        add_path(path, category="supporting", field=f"supporting_paths[{index}]")

    for index, item in enumerate(manifest["engine_dependencies"]):
        path, _, _ = require_evidence(item, field=f"engine_dependencies[{index}]")
        engine = require_string(item.get("engine"), field=f"engine_dependencies[{index}].engine").lower()
        if engine not in {"v8", "spidermonkey", "javascriptcore", "other"}:
            raise ScopeError(f"engine_dependencies[{index}].engine: unsupported engine {engine}")
        if not is_engine_path(path):
            raise ScopeError(f"engine_dependencies[{index}]: path does not identify engine code")
        if len(path.parts) < 3:
            raise ScopeError(f"engine_dependencies[{index}]: engine root is too broad: {path}")
        add_path(path, category=f"engine:{engine}", field=f"engine_dependencies[{index}]")

    if not selected:
        raise ScopeError("scope selected no files")
    max_files = manifest["budgets"]["max_files"]
    max_bytes = manifest["budgets"]["max_bytes"]
    total_bytes = sum(item.size for item in selected.values())
    if len(selected) > max_files:
        raise ScopeError(f"file budget exceeded: selected {len(selected)}, maximum {max_files}")
    if total_bytes > max_bytes:
        raise ScopeError(f"byte budget exceeded: selected {total_bytes}, maximum {max_bytes}")
    return [selected[name] for name in sorted(selected)]


def materialize(repo: Path, manifest_path: Path, output: Path, *, replace: bool = False) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    if not repo.is_dir():
        raise ScopeError(f"repository is not a directory: {repo}")
    raw_manifest = manifest_path.read_bytes()
    manifest = validate_manifest_shape(json.loads(raw_manifest))
    files = collect(repo, manifest)
    output = output.resolve()
    try:
        output.relative_to(repo)
    except ValueError:
        pass
    else:
        raise ScopeError("output must be outside the implementation repository")
    if output.exists() and not replace:
        raise ScopeError(f"output exists; pass --replace to replace it: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        for item in files:
            destination = temporary / item.relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item.source, destination, follow_symlinks=False)
        lock = {
            "schema_version": SCHEMA_VERSION,
            "manifest_sha256": sha256_bytes(raw_manifest),
            "implementation": manifest["implementation"],
            "feature": manifest["feature"],
            "file_count": len(files),
            "total_bytes": sum(item.size for item in files),
            "files": [
                {
                    "path": item.relative_path,
                    "size": item.size,
                    "sha256": item.sha256,
                    "category": item.category,
                }
                for item in files
            ],
        }
        (temporary / "feature-scope.lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        if output.exists():
            shutil.rmtree(output)
        temporary.replace(output)
        return lock
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="implementation repository checkout")
    parser.add_argument("--manifest", required=True, type=Path, help="feature-scope manifest")
    parser.add_argument("--out", required=True, type=Path, help="isolated packet destination")
    parser.add_argument("--replace", action="store_true", help="replace an existing destination")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        lock = materialize(args.repo, args.manifest, args.out, replace=args.replace)
    except (OSError, json.JSONDecodeError, ScopeError) as exc:
        print(f"feature scope rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.out), "file_count": lock["file_count"], "total_bytes": lock["total_bytes"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
