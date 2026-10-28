import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("manifest", sorted((ROOT / "manifests").glob("*.publication.json")), ids=lambda path: path.stem)
def test_real_publication_manifests_conform_to_declared_schema(manifest):
    schema = json.loads((ROOT / "schemas/publication-manifest-v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(json.loads(manifest.read_text()))
