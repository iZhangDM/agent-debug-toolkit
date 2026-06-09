#!/usr/bin/env python3
"""Agent Debug Toolkit — CLI entry point.

Usage:
    adt analyze <file>                # Free analysis
    adt analyze <file> --license KEY  # Pro analysis
    adt generate-license <email>      # Generate a license key
    adt validate-license <key>        # Validate a license
    adt version                       # Show version
"""

import argparse
import json
import os
import sys
from typing import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adt",
        description="Agent Debug Toolkit — find bugs in AI agent code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  adt analyze my_agent.py
  adt analyze my_agent.py --license abc123
  adt analyze my_agent.py --format text
  adt generate-license user@example.com
  adt validate-license "user@example.com:1234567890:abc123"
  adt version
""",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # analyze
    analyze_parser = sub.add_parser("analyze", help="Analyze a Python agent file")
    analyze_parser.add_argument("file", help="Path to Python file to analyze")
    analyze_parser.add_argument("--license", "-l", help="License key for Pro features")
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    analyze_parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low", "all"],
        default="all",
        help="Minimum severity to show (default: all)",
    )
    analyze_parser.add_argument(
        "--analyzer", "-a",
        help="Run only a specific analyzer (e.g., loop_analyzer)",
    )

    # generate-license
    gen_parser = sub.add_parser("generate-license", help="Generate a Pro license key")
    gen_parser.add_argument("email", help="Email for the license")
    gen_parser.add_argument("--days", "-d", type=int, default=365, help="Validity in days (default: 365)")

    # validate-license
    val_parser = sub.add_parser("validate-license", help="Validate a license key")
    val_parser.add_argument("key", help="License key to validate")

    # version
    sub.add_parser("version", help="Show version")

    return parser


def cmd_analyze(args: argparse.Namespace) -> int:
    """Run the analyze command."""
    from adt import analyze_file

    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        return 1

    if not filepath.endswith(".py"):
        print(f"Warning: {filepath} does not appear to be a Python file.", file=sys.stderr)

    print(f"Analyzing: {filepath}\n", file=sys.stderr)

    license_key = args.license if args.license else None
    report = analyze_file(filepath, license_key=license_key)

    # Filter by analyzer if requested
    if args.analyzer:
        report["findings"] = [
            f for f in report["findings"]
            if f.get("analyzer") == args.analyzer
        ]
        report["summary"] = _recount(report["findings"])

    # Filter by severity if requested
    if args.severity != "all":
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = severity_order.get(args.severity, 3)
        report["findings"] = [
            f for f in report["findings"]
            if severity_order.get(f.get("severity", "low"), 3) <= min_level
        ]
        report["summary"] = _recount(report["findings"])

    if args.format == "text":
        _print_text_report(report)
    else:
        print(json.dumps(report, indent=2))

    # Return non-zero if critical findings
    return 1 if report["summary"]["critical"] > 0 else 0


def _recount(findings: list) -> dict:
    """Recount findings by severity."""
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        summary["total"] += 1
        if sev in summary:
            summary[sev] += 1
    return summary


def _print_text_report(report: dict) -> None:
    """Pretty-print the report as colored text."""
    findings = report["findings"]
    summary = report["summary"]
    meta = report["meta"]

    SEV_COLORS = {
        "critical": "\033[1;31m",  # Bold red
        "high": "\033[0;31m",      # Red
        "medium": "\033[0;33m",    # Yellow
        "low": "\033[0;36m",       # Cyan
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    print(f"{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║       Agent Debug Toolkit — Report        ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}")
    print()
    print(f"  File:       {meta.get('file', 'N/A')}")
    print(f"  Version:    {meta.get('version', 'N/A')}")
    print(f"  Pro:        {'Enabled' if meta.get('pro_features') else 'Disabled'}")
    print(f"  Analyzers:  {', '.join(meta.get('analyzers_ran', []))}")
    print()
    print(f"{BOLD}  Summary:{RESET}")
    print(f"    Total findings: {summary['total']}")
    print(f"    Critical:       {SEV_COLORS['critical']}{summary['critical']}{RESET}")
    print(f"    High:           {SEV_COLORS['high']}{summary['high']}{RESET}")
    print(f"    Medium:         {SEV_COLORS['medium']}{summary['medium']}{RESET}")
    print(f"    Low:            {SEV_COLORS['low']}{summary['low']}{RESET}")
    print()

    if not findings:
        print(f"  {SEV_COLORS['low']}✓ No issues found!{RESET}")
        return

    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "low")
        color = SEV_COLORS.get(sev, RESET)
        print(f"{BOLD}  [{i}] {color}[{sev.upper()}]{RESET} {finding['title']}{RESET}")
        print(f"      Line {finding.get('line', 0)} | {finding.get('analyzer', 'unknown')}")
        if finding.get("code_snippet"):
            snippet = finding["code_snippet"][:100]
            print(f"      Code: {snippet}")
        desc = finding.get("description", "")
        if desc:
            # Wrap description at 70 chars
            print(f"      {desc[:200]}")
        rec = finding.get("recommendation", "")
        if rec:
            print(f"      {BOLD}Fix:{RESET} {rec[:200]}")
        print()


def cmd_generate_license(args: argparse.Namespace) -> int:
    """Generate a license key."""
    from adt.license import LicenseManager

    key = LicenseManager.generate(args.email, args.days)
    print(f"License key for {args.email} (valid {args.days} days):")
    print()
    print(f"  {key}")
    print()
    print("Use with: adt analyze <file> --license <key>")
    return 0


def cmd_validate_license(args: argparse.Namespace) -> int:
    """Validate a license key."""
    from adt.license import LicenseManager

    info = LicenseManager.validate(args.key)
    if info.valid:
        print(f"✓ Valid license")
        print(f"  Email:  {info.email}")
        expiry_date = __import__("datetime").datetime.fromtimestamp(info.expiry)
        print(f"  Expiry: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
        return 0
    else:
        print(f"✗ Invalid: {info.reason}")
        return 1


def cmd_version(args: argparse.Namespace) -> int:
    """Print version."""
    from adt import __version__
    print(f"Agent Debug Toolkit v{__version__}")
    print("Pure Python • Zero dependencies • AST-based analysis")
    print()
    print("Free features:  loop analysis, tool validation, injection scanning, memory leak detection")
    print("Pro features:   RAG pipeline analysis, performance benchmarking")
    print()
    print("Get a Pro license: adt generate-license <email>")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "generate-license":
        return cmd_generate_license(args)
    elif args.command == "validate-license":
        return cmd_validate_license(args)
    elif args.command == "version":
        return cmd_version(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
