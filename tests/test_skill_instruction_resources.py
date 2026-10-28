"""The distributed instructions must describe the resources and wire fields shipped with them."""

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_literal_skill_resources_exist_in_the_portable_package():
    catalog = json.loads((ROOT / "catalog.yaml").read_text())
    missing = []
    for entry in catalog["skills"]:
        skill = ROOT / entry["path"]
        core = skill / "portable-core.json"
        excluded = set(json.loads(core.read_text()).get("excluded_roots", [])) if core.exists() else set()
        for reference in re.findall(
            r"`((?:references|scripts|schemas|templates|resources|assets|tests|evals)/[^`\s*<>]+)`",
            (skill / "SKILL.md").read_text(),
        ):
            reference = reference.rstrip(".,;:")
            if any(reference.rstrip("/") == path or reference.startswith(path + "/") for path in excluded):
                continue
            if not (skill / reference).exists():
                missing.append(f"{entry['id']}: {reference}")
    assert not missing, "Instructions refer to absent portable resources: " + ", ".join(missing)


def test_documented_model_fields_cover_the_shared_wire_contract():
    skill = (ROOT / "skills/what-are-we-building/SKILL.md").read_text()
    output = skill.split("## Output Contract", 1)[1]
    fields = set(re.search(r"```text\n(.*?)\n```", output, re.S).group(1).splitlines())
    schema = json.loads((ROOT / "contracts/threat-modeling-flow-v1/schemas/model-packet.schema.json").read_text())
    assert set(schema["required"]) <= fields
    assert not {"threat-model-contract-version", "run_identity", "target_identity", "sources"} & fields
