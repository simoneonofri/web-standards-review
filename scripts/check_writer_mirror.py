"""Verify the pinned private Considerations writer and the adapted monorepo mirror."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / "skills/write-considerations"
MANIFEST = ROOT / "manifests/standalone-writer-source.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_safe(relative: str) -> bool:
    value = Path(relative)
    return bool(relative) and not value.is_absolute() and ".." not in value.parts


def check_digest(path: Path, digest: str, label: str, problems: list[str]) -> None:
    if not path.is_file() or path.is_symlink() or sha(path) != digest:
        problems.append(label)


def common_files(root: Path) -> set[str]:
    files = {"SKILL.md"}
    for directory, suffix in (("scripts", ".py"), ("references", ".md")):
        files |= {
            str(path.relative_to(root))
            for path in (root / directory).glob("*")
            if path.is_file() and path.suffix == suffix
        }
    return files


def adapted_test(content: str) -> str:
    return (
        content.replace(
            "ROOT = Path(__file__).resolve().parents[1]",
            "ROOT = Path(__file__).resolve().parents[3]",
        )
        .replace(
            'SCRIPT_DIR = ROOT / "scripts"',
            'SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"',
        )
        .replace(
            'SCRIPTS = ROOT / "scripts"',
            'SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"',
        )
        .replace(
            'ROOT / "tests/fixtures/clean-room-demo"',
            'ROOT / "fixtures/clean-room-demo"',
        )
    )


def check(standalone_checkout: Path | None = None) -> dict:
    meta = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if meta.get("schema_version") != "standalone-skill-mirror/v2":
        raise ValueError("unsupported standalone skill mirror schema")
    commit = meta.get("upstream_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", commit):
        raise ValueError("invalid pinned standalone commit")
    standard = meta.get("files")
    tests = meta.get("adapted_tests")
    fixtures = meta.get("fixture_hashes")
    if not all(isinstance(obj, dict) and obj for obj in (standard, tests, fixtures)):
        raise ValueError(
            "mirror inventory must include common files, adapted tests and fixtures"
        )
    problems: list[str] = []
    if set(standard) != common_files(SKILL_ROOT):
        problems.append("monorepo:untracked_or_missing_skill_source")
    if standalone_checkout and set(standard) != common_files(standalone_checkout):
        problems.append("standalone:untracked_or_missing_skill_source")
    for relative, digest in sorted(standard.items()):
        if not is_safe(relative):
            raise ValueError("unsafe path in common file inventory")
        check_digest(SKILL_ROOT / relative, digest, "monorepo:" + relative, problems)
        projected = (
            ROOT
            / "manifests"
            / (
                "portable-entrypoints/write-considerations.md"
                if relative == "SKILL.md"
                else "portable-resources/write-considerations/" + relative
            )
        )
        check_digest(projected, digest, "projection:" + relative, problems)
        if standalone_checkout:
            check_digest(
                standalone_checkout / relative,
                digest,
                "standalone:" + relative,
                problems,
            )
    expected_tests = {
        str(path.relative_to(SKILL_ROOT))
        for path in (SKILL_ROOT / "tests").glob("test_*.py")
        if path.is_file()
    }
    if set(tests) != expected_tests:
        problems.append("monorepo:untracked_or_missing_tests")
    if standalone_checkout:
        standalone_tests = {
            str(path.relative_to(standalone_checkout))
            for path in (standalone_checkout / "tests").glob("test_*.py")
            if path.is_file()
        }
        if set(tests) != standalone_tests:
            problems.append("standalone:untracked_or_missing_tests")
    for relative, expected in sorted(tests.items()):
        if not is_safe(relative) or not isinstance(expected, dict):
            raise ValueError("invalid adapted test inventory")
        monorepo = SKILL_ROOT / relative
        check_digest(
            monorepo,
            expected["monorepo_sha256"],
            "monorepo_test:" + relative,
            problems,
        )
        check_digest(
            ROOT / "manifests/portable-resources/write-considerations" / relative,
            expected["monorepo_sha256"],
            "projection_test:" + relative,
            problems,
        )
        if standalone_checkout:
            upstream = standalone_checkout / relative
            check_digest(
                upstream,
                expected["upstream_sha256"],
                "standalone_test:" + relative,
                problems,
            )
            if (
                upstream.is_file()
                and monorepo.is_file()
                and adapted_test(upstream.read_text(encoding="utf-8"))
                != monorepo.read_text(encoding="utf-8")
            ):
                problems.append("adaptation_drift:" + relative)
    for relative, digest in sorted(fixtures.items()):
        if not is_safe(relative):
            raise ValueError("unsafe fixture inventory path")
        monorepo = ROOT / "fixtures/clean-room-demo" / Path(relative).name
        check_digest(monorepo, digest, "monorepo_fixture:" + relative, problems)
        if standalone_checkout:
            check_digest(
                standalone_checkout / relative,
                digest,
                "standalone_fixture:" + relative,
                problems,
            )
    if standalone_checkout:
        result = subprocess.run(
            ["git", "-C", str(standalone_checkout), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        if result.returncode or result.stdout.strip() != commit:
            problems.append("standalone:incorrect_source_commit")
        dirty = subprocess.run(
            [
                "git",
                "-C",
                str(standalone_checkout),
                "status",
                "--porcelain",
                "--untracked-files=no",
            ],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        if dirty.returncode or dirty.stdout.strip():
            problems.append("standalone:working_tree_modified")
    return {
        "schema_version": "standalone-skill-mirror-verification/v2",
        "status": "pass" if not problems else "blocked",
        "upstream_repository": meta["upstream_repository"],
        "upstream_commit": commit,
        "same_content_files": len(standard),
        "adapted_tests": len(tests),
        "fixture_hashes": len(fixtures),
        "private_checkout_verified": standalone_checkout is not None,
        "problems": problems,
        "differences": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--standalone-checkout", type=Path)
    args = parser.parse_args()
    receipt = check(args.standalone_checkout)
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
