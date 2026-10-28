#!/usr/bin/env python3
"""Compatibility entry point for the canonical strict threat-model contract."""

from __future__ import annotations

import runpy
from pathlib import Path

TARGET = (
    Path(__file__).resolve().parents[1]
    / "threat-modeling-flow-v1"
    / "scripts"
    / "validate_threat_model_contract.py"
)
if not TARGET.is_file():
    raise SystemExit(f"canonical strict contract validator is missing: {TARGET}")
runpy.run_path(str(TARGET), run_name="__main__")
