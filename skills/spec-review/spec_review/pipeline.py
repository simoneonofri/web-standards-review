"""Portable spec-review pipeline entrypoints."""

from __future__ import annotations

from pathlib import Path

from .report_assembler import assemble_report


def assemble_existing_run(run_dir: Path, output: Path | None = None, title: str | None = None) -> Path:
    """Assemble an existing run directory into the canonical spec-review report."""

    return assemble_report(run_dir=run_dir, output=output, title=title)
