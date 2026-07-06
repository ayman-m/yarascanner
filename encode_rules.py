"""Base64-encode a YARA rules file."""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path


def encode_file(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to a .yar / .yara rules file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the base64 output to this file instead of stdout",
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"error: {args.input} not found or not a regular file", file=sys.stderr)
        return 1

    encoded = encode_file(args.input)

    if args.output:
        args.output.write_text(encoded, encoding="ascii")
        print(f"Wrote {len(encoded)} base64 chars to {args.output}")
    else:
        sys.stdout.write(encoded + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
