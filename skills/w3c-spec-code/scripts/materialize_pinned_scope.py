"""Verify a bounded feature packet against exact raw Git blobs before exposing it."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from materialize_feature_scope import ScopeError, materialize


def materialize_pinned(repo, manifest, output):
    require_new = not output.exists() and not output.is_symlink()
    if not require_new:
        raise ScopeError("Use a new packet directory")
    data = json.loads(manifest.read_text())
    revision = data["implementation"]["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ScopeError("An exact 40-hex implementation commit is required")
    def git(*args):
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
        if result.returncode:
            raise ScopeError("Pinned commit or selected source is unavailable in Git")
        return result.stdout
    if git("rev-parse", revision + "^{commit}").decode().strip() != revision:
        raise ScopeError("Implementation revision is not the declared commit")
    if output.resolve().is_relative_to(repo.resolve()):
        raise ScopeError("Packet must be outside the source repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="feature-packet-", dir=output.parent) as temporary:
        stage = Path(temporary) / "packet"
        lock = materialize(repo, manifest, stage)
        for record in lock["files"]:
            path = record["path"]
            raw = git("ls-tree", "-z", revision, "--", path).split(b"\0")
            entry = next((item for item in raw if item and item.split(b"\t", 1)[1].decode() == path), None)
            if entry is None or entry.split(b" ", 2)[0] not in {b"100644", b"100755"}:
                raise ScopeError("Selected source is not a regular file at the pinned commit")
            oid = entry.split(b"\t", 1)[0].split(b" ")[2].decode()
            expected = hashlib.sha256(git("cat-file", "blob", oid)).hexdigest()
            actual = hashlib.sha256((stage / path).read_bytes()).hexdigest()
            if actual != expected or record["sha256"] != actual:
                raise ScopeError("Selected working-tree bytes differ from the pinned commit")
        lock["revision_verified"] = True
        (stage / "feature-scope.lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        stage.rename(output)
    return lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ["repo", "manifest", "out"]:
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    try:
        lock = materialize_pinned(args.repo, args.manifest, args.out)
    except (ScopeError, ValueError, OSError, KeyError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 1
    print(json.dumps({"status": "verified", "file_count": lock["file_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
