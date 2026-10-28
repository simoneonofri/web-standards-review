from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evals" / "fixtures"


def validate(diagram: str, dictionary: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_dfd.py"),
            str(FIXTURES / diagram),
            str(FIXTURES / dictionary),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_canonical_tmdc_diagram_and_complete_dictionary_pass() -> None:
    result = validate("valid-tmdc.mmd", "valid-dictionary.json")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "4 complete dictionary rows" in result.stdout


def test_stripped_canonical_ids_fail() -> None:
    result = validate("valid-tmdc.mmd", "stripped-ids-dictionary.json")
    assert result.returncode != 0
    assert "canonical hyphenated ID" in result.stdout


def test_custom_renderer_without_tmdc_source_fails() -> None:
    result = validate("custom-renderer.mmd", "valid-dictionary.json")
    assert result.returncode != 0
    assert "canonical TMDC" in result.stdout


def test_truncated_dictionary_fails() -> None:
    result = validate("valid-tmdc.mmd", "truncated-dictionary.json")
    assert result.returncode != 0
    assert "missing required dictionary field" in result.stdout


def test_complete_dictionary_renders_inline() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_dictionary.py"),
            str(FIXTURES / "valid-dictionary.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "| ID | Mermaid node ID | Type | Visible label |" in result.stdout
    assert "| EE-01 | EE1_Service |" in result.stdout
    assert "| DF-01 | DF1_Request |" in result.stdout


def validate_modified(tmp_path, *, source=None, dictionary=None):
    import json
    source = (FIXTURES / "valid-tmdc.mmd").read_text() if source is None else source
    dictionary = json.loads((FIXTURES / "valid-dictionary.json").read_text()) if dictionary is None else dictionary
    diagram_path = tmp_path / "diagram.mmd"
    dictionary_path = tmp_path / "dictionary.json"
    diagram_path.write_text(source)
    dictionary_path.write_text(json.dumps(dictionary))
    return subprocess.run([sys.executable, str(ROOT / "scripts/validate_dfd.py"), str(diagram_path), str(dictionary_path)], capture_output=True, text=True)


def test_null_boundary_membership_reports_error_without_crashing(tmp_path):
    import json
    dictionary = json.loads((FIXTURES / "valid-dictionary.json").read_text())
    dictionary["rows"][0]["boundary_membership"] = None
    result = validate_modified(tmp_path, dictionary=dictionary)
    assert result.returncode == 1
    assert "must be an array" in result.stdout
    assert "Traceback" not in result.stderr


def test_malformed_boundary_member_reports_error_without_crashing(tmp_path):
    import json
    dictionary = json.loads((FIXTURES / "valid-dictionary.json").read_text())
    dictionary["rows"][0]["boundary_membership"] = [{}]
    result = validate_modified(tmp_path, dictionary=dictionary)
    assert result.returncode == 1
    assert "unknown boundary" in result.stdout
    assert "Traceback" not in result.stderr


def test_extra_diagram_node_requires_a_dictionary_row(tmp_path):
    source = (FIXTURES / "valid-tmdc.mmd").read_text() + "\nEE99_Orphan[EE-99<br/>Orphan]\n"
    result = validate_modified(tmp_path, source=source)
    assert result.returncode == 1
    assert "renderer IDs absent from dictionary" in result.stdout


def test_extra_named_flow_requires_a_dictionary_row(tmp_path):
    import re
    source = (FIXTURES / "valid-tmdc.mmd").read_text()
    flow_line = next(line for line in source.splitlines() if "==>" in line)
    source += "\n" + re.sub(r"DF-\d{2,}", "DF-99", flow_line) + "\n"
    result = validate_modified(tmp_path, source=source)
    assert result.returncode == 1
    assert "flow IDs absent from dictionary" in result.stdout


def test_equivalent_boundary_style_whitespace_and_order_pass(tmp_path):
    import re
    source = (FIXTURES / "valid-tmdc.mmd").read_text()
    source = re.sub(r"(style\s+TB\d+_\w+)[^\n]+", r"\1 stroke-dasharray: 8 6, stroke: #000, stroke-width: 4px, fill: transparent", source)
    result = validate_modified(tmp_path, source=source)
    assert result.returncode == 0, result.stdout + result.stderr


def test_boundary_style_must_still_be_black(tmp_path):
    import re
    source = (FIXTURES / "valid-tmdc.mmd").read_text()
    source = re.sub(r"(style\s+TB\d+_\w+[^\n]*stroke:)#000", r"\1red", source)
    result = validate_modified(tmp_path, source=source)
    assert result.returncode == 1
    assert "dashed black 4px" in result.stdout


def test_comment_examples_do_not_add_diagram_elements_or_thin_arrows(tmp_path):
    source = (FIXTURES / "valid-tmdc.mmd").read_text() + "\n%% EE99_Example --> PO99_Example is not a diagram element\n"
    result = validate_modified(tmp_path, source=source)
    assert result.returncode == 0, result.stdout + result.stderr
