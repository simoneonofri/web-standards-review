from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_fixture(
    model: str, dictionary: str = "valid-minimal-dictionary.json"
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_model_packet.py"),
            str(ROOT / "evals" / "fixtures" / model),
            str(ROOT / "evals" / "fixtures" / dictionary),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_valid_model_packet_passes() -> None:
    assert run_fixture("valid-minimal-model.json").returncode == 0


def test_missing_source_reference_fails() -> None:
    result = run_fixture("missing-source-reference.json")
    assert result.returncode != 0
    assert "source_reference" in result.stdout


def test_decorative_boundary_fails() -> None:
    result = run_fixture("decorative-boundary.json")
    assert result.returncode != 0
    assert "trust boundary" in result.stdout


def test_stripped_canonical_id_fails() -> None:
    result = run_fixture("valid-minimal-model.json", "stripped-canonical-id-dictionary.json")
    assert result.returncode != 0
    assert "canonical" in result.stdout


def test_truncated_dictionary_fails() -> None:
    result = run_fixture("valid-minimal-model.json", "truncated-dictionary.json")
    assert result.returncode != 0
    assert "missing required dictionary field" in result.stdout


def validate_modified_dictionary(tmp_path, mutate):
    import json
    dictionary = json.loads((ROOT / "evals/fixtures/valid-minimal-dictionary.json").read_text())
    mutate(dictionary)
    path = tmp_path / "dictionary.json"
    path.write_text(json.dumps(dictionary))
    return subprocess.run([sys.executable, str(ROOT / "scripts/validate_model_packet.py"), str(ROOT / "evals/fixtures/valid-minimal-model.json"), str(path)], capture_output=True, text=True)


def test_dictionary_preserves_model_flow_direction(tmp_path):
    def reverse(dictionary):
        flow = next(row for row in dictionary["rows"] if row["canonical_id"].startswith("DF-"))
        flow["flow_source"], flow["flow_destination"] = flow["flow_destination"], flow["flow_source"]
    result = validate_modified_dictionary(tmp_path, reverse)
    assert result.returncode == 1
    assert "must preserve the model flow endpoint" in result.stdout


def test_null_dictionary_membership_does_not_crash(tmp_path):
    result = validate_modified_dictionary(tmp_path, lambda dictionary: dictionary["rows"][0].update(boundary_membership=None))
    assert result.returncode == 1
    assert "must be an array" in result.stdout
    assert "Traceback" not in result.stderr
