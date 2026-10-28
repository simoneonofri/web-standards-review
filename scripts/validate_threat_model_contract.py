#!/usr/bin/env python3
"""Compatibility entry point for the canonical contracts validator."""

from __future__ import annotations

import runpy
from pathlib import Path

TARGET = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "scripts"
    / "validate_threat_model_contract.py"
)
if not TARGET.is_file():
    raise SystemExit(f"canonical shared contract validator is missing: {TARGET}")
runpy.run_path(str(TARGET), run_name="__main__")
