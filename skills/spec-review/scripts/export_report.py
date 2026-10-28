#!/usr/bin/env python3
"""Export a Markdown security review report to DOCX and/or PDF using Pandoc."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export a Markdown report to DOCX and/or PDF with Pandoc."
    )
    parser.add_argument("markdown", type=Path, help="Path to the Markdown report")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Directory for generated files. Defaults to the Markdown file directory.",
    )
    parser.add_argument("--docx", action="store_true", help="Generate DOCX")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF")
    parser.add_argument(
        "--pdf-engine",
        default=None,
        help="Optional Pandoc PDF engine, such as xelatex, lualatex, or wkhtmltopdf.",
    )
    return parser.parse_args()


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, check=True)


def main() -> int:
    args = parse_args()
    markdown = args.markdown.resolve()
    if not markdown.exists():
        print(f"Markdown file not found: {markdown}", file=sys.stderr)
        return 2
    if markdown.suffix.lower() not in {".md", ".markdown"}:
        print(f"Expected a Markdown file, got: {markdown}", file=sys.stderr)
        return 2

    pandoc = shutil.which("pandoc")
    if not pandoc:
        print("Pandoc not found. Install Pandoc or provide Markdown only.", file=sys.stderr)
        return 3

    out_dir = (args.out_dir or markdown.parent).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    formats = []
    if args.docx:
        formats.append("docx")
    if args.pdf:
        formats.append("pdf")
    if not formats:
        formats = ["docx", "pdf"]

    for fmt in formats:
        output = out_dir / f"{markdown.stem}.{fmt}"
        cmd = [pandoc, str(markdown), "-o", str(output)]
        if fmt == "pdf" and args.pdf_engine:
            cmd.extend(["--pdf-engine", args.pdf_engine])
        run(cmd)
        print(f"Wrote {output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
