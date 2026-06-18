#!/usr/bin/env python3
"""Initialize the local workspace used by the Volatility3 analysis skill."""

from __future__ import annotations

import argparse
from pathlib import Path


WORKSPACE_DIRECTORIES = (
    Path("images"),
    Path("results"),
    Path("symbols"),
    Path("symbols/linux"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the default Volatility3 analysis workspace directories."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Workspace root to initialize. Defaults to the current directory.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.expanduser().resolve()

    for relative_path in WORKSPACE_DIRECTORIES:
        directory = root / relative_path
        directory.mkdir(parents=True, exist_ok=True)
        print(directory)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
