from __future__ import annotations

import argparse
from pathlib import Path

from .report import analyze_file, to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rev-inspector",
        description="Static binary inspection assistant. Does not execute analyzed files.",
    )
    parser.add_argument("sample", type=Path, help="Path to the file to inspect")
    parser.add_argument("--json", action="store_true", help="Print a JSON report")
    parser.add_argument("--rules", type=Path, help="Optional YARA rules file")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.sample.exists():
        parser.error(f"sample does not exist: {args.sample}")
    if not args.sample.is_file():
        parser.error(f"sample is not a file: {args.sample}")
    if args.rules and not args.rules.exists():
        parser.error(f"rules file does not exist: {args.rules}")

    report = analyze_file(args.sample, args.rules)
    if args.json:
        print(to_json(report))
    else:
        print(to_text(report), end="")
    return 0
