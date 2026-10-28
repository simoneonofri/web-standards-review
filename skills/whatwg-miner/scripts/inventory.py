#!/usr/bin/env python3
"""Build the WHATWG standards inventory from the official index."""

from __future__ import annotations

import argparse
from pathlib import Path

from whatwg_miner import INDEX_URL, atomic_write, dump_json, fetch_bytes, parse_index


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, help="saved official index HTML")
    parser.add_argument("--save-source", type=Path, help="save the exact official index snapshot")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.source.read_bytes() if args.source else fetch_bytes(INDEX_URL)
    if args.save_source:
        atomic_write(args.save_source, data.decode("utf-8"))
    dump_json(args.output, parse_index(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
