from __future__ import annotations

import csv
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def module(name: str):
    p = ROOT / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, p)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def source_root(tmp_path: Path):
    exporter = module("export_threat_knowledge_cache")
    root = tmp_path / "source"
    folder = root / "references/corpus/threat-frameworks/google-sheet"
    folder.mkdir(parents=True)
    (folder.parent / "MANIFEST.md").write_text(
        "Synthetic source manifest for validation."
    )
    for slug, (_domain, _source, title, question) in exporter.SHEETS.items():
        p = folder / (slug + ".csv")
        stream = io.StringIO()
        writer = csv.writer(stream)
        if slug == "harms-threats-corti-et-al-ndi":
            writer.writerow(["Corti source attribution", "", "", "", "", "", "", ""])
            writer.writerow(
                [
                    "CATEGORY",
                    "TYPE OF HARM",
                    "HARM",
                    "SOURCE",
                    "STAKEHOLDERS (Specific)",
                    "",
                    "",
                    "",
                ]
            )
            writer.writerow(
                [
                    "Risk",
                    "Impact",
                    "Discrimination through credential exclusion",
                    "Synthetic bibliography",
                    "People",
                    "",
                    "",
                    "",
                ]
            )
        else:
            fields = list(dict.fromkeys([title, question]))
            writer.writerow(fields)
            writer.writerow(
                ["What could go wrong in this category?"]
                if len(fields) == 1
                else ["Authorization", "Can unauthorized access reveal sensitive data?"]
            )
        p.write_text(stream.getvalue())
    return root


def test_exports_portable_questions_without_source_corpus(source_root, tmp_path):
    exporter = module("export_threat_knowledge_cache")
    reader = module("query_threat_knowledge_cache")
    output = tmp_path / "threat-cache.zip"
    result = exporter.create(source_root, output)
    assert result["rights_review"].startswith("blocked_")
    assert result["records"] == len(exporter.SHEETS)
    rows, manifest = reader.load(output)
    assert len(rows) == manifest["records"]
    assert len({r["id"] for r in rows}) == len(rows)
    assert "sustainability" not in manifest["domains"]
    assert any(x["source_id"] == "rfc9620" for x in rows)
    assert any(x["source_id"] == "stride" for x in rows)
    with zipfile.ZipFile(output) as archive:
        assert "index.html" in archive.namelist()
        assert "records.csv" in archive.namelist()
        assert "records.jsonl" in archive.namelist()
        text = archive.read("records.jsonl").decode()
        assert "/Users/" not in text
        assert "Full case-study narratives" in str(manifest["limitations"])
    _, count = reader.query(rows, source_id="rfc9620")
    assert count == 1


def test_human_curated_override_survives_regeneration(source_root, tmp_path):
    exporter = module("export_threat_knowledge_cache")
    original = tmp_path / "original.zip"
    exporter.create(source_root, original)
    records, _manifest = module("query_threat_knowledge_cache").load(original)
    target = records[0]["id"]
    override = tmp_path / "overrides.csv"
    with override.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=exporter.EDIT_HEADERS)
        writer.writeheader()
        writer.writerow(
            {
                "id": target,
                "question": "Could a privileged actor disclose hidden data?",
                "curation_status": "proposed",
                "reviewer_note": "Needs approval.",
            }
        )
    updated = tmp_path / "updated.zip"
    result = exporter.create(source_root, updated, override)
    assert result["records"] == len(records)
    new, _manifest = module("query_threat_knowledge_cache").load(updated)
    row = next(x for x in new if x["id"] == target)
    assert row["question"] == "Could a privileged actor disclose hidden data?"
    assert row["curation_status"] == "proposed"


def test_rejects_corrupt_archive_and_dangerous_content(source_root, tmp_path):
    exporter = module("export_threat_knowledge_cache")
    reader = module("query_threat_knowledge_cache")
    output = tmp_path / "source.zip"
    exporter.create(source_root, output)
    with zipfile.ZipFile(output) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    contents["records.jsonl"] += b"\nUNAUTHORIZED CHANGE\n"
    corrupted = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(corrupted, "w") as archive:
        for name, data in contents.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="checksum"):
        reader.load(corrupted)
    with pytest.raises(ValueError, match="private"):
        exporter.safe("leak /Users/test/password", 100)


def test_previous_snapshot_cannot_be_silently_overwritten(source_root, tmp_path):
    exporter = module("export_threat_knowledge_cache")
    output = tmp_path / "source.zip"
    exporter.create(source_root, output)
    with pytest.raises(ValueError, match="overwrite"):
        exporter.create(source_root, output)
