import argparse
import sys

from scanner.scanner import run_scan
from scanner.report import print_terminal_summary, write_json_report, write_html_report

LEGAL_WARNING = """
================================================================
  WARNING: Only scan targets you own or have explicit, written
  permission to test. Scanning systems without authorization is
  illegal in most jurisdictions (e.g., the Computer Fraud and
  Abuse Act in the US, or the Computer Misuse Act in the UK).
================================================================
"""


def main():
    parser = argparse.ArgumentParser(
        description="VulnScan — a lightweight web application security scanner for authorized testing only."
    )
    parser.add_argument("target", help="Target URL to scan, e.g. https://example.com")
    parser.add_argument("--json", help="Write a JSON report to this file path")
    parser.add_argument("--html", help="Write an HTML report to this file path")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    args = parser.parse_args()

    print(LEGAL_WARNING)
    if not args.yes:
        confirm = input(f"Do you own or have explicit permission to scan '{args.target}'? [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Aborting. Only scan authorized targets.")
            sys.exit(1)

    scan_result = run_scan(args.target)
    print_terminal_summary(scan_result)

    if args.json:
        write_json_report(scan_result, args.json)
        print(f"JSON report written to {args.json}")
    if args.html:
        write_html_report(scan_result, args.html)
        print(f"HTML report written to {args.html}")


if __name__ == "__main__":
    main()