"""Create private local Compose settings without printing credentials."""

import argparse
import os
import secrets
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / ".env")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(f"KNOWLEDGE_DB_PASSWORD={secrets.token_hex(32)}\nKNOWLEDGE_PORT={args.port}\n")
    print("Created local settings. Existing settings are never overwritten.")


if __name__ == "__main__":
    main()
