"""CLI entry point for aibom-scanner."""

import argparse
import sys

from aibom_scanner import __version__
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.scanner import scan_directory

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="aibom-scanner",
        description="Scan codebases for AI SDK usage and map compliance risks to NIST AI RMF, ISO 42001, and EU AI Act.",
    )
    parser.add_argument("--version", action="version", version=f"aibom-scanner {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a directory for AI SDK usage")
    scan_parser.add_argument(
        "--path", "-p",
        required=True,
        help="Path to the directory to scan",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "sarif"],
        default=None,
        help="Output format (default: table for terminal, json when piped)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Write output to file instead of stdout",
    )
    scan_parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 if findings at or above this severity",
    )

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(2)

    if args.command == "scan":
        _run_scan(args)


def _run_scan(args: argparse.Namespace) -> None:
    try:
        result = scan_directory(args.path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        sys.exit(2)

    # Auto-detect format
    fmt = args.format
    if fmt is None:
        fmt = "table" if sys.stdout.isatty() else "json"

    if fmt == "table":
        output = format_table(result)
    elif fmt == "json":
        output = format_json(result)
    elif fmt == "sarif":
        output = format_sarif(result)
    else:
        output = format_json(result)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
            f.write("\n")
        if sys.stdout.isatty():
            print(f"Output written to {args.output}")
    else:
        print(output)

    # Check severity threshold
    if args.severity_threshold:
        threshold = SEVERITY_RANK[args.severity_threshold]
        for risk in result.risks:
            sev = risk.get("severity", "low")
            if SEVERITY_RANK.get(sev, 0) >= threshold:
                sys.exit(1)
