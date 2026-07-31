import json
import os
from datetime import datetime, timezone
from colorama import init, Fore, Style

init(autoreset=True)

SEVERITY_COLORS = {
    "Critical": Fore.RED,
    "High": Fore.LIGHTRED_EX,
    "Medium": Fore.YELLOW,
    "Low": Fore.CYAN,
    "Info": Fore.WHITE,
}


def print_terminal_summary(scan_result):
    target = scan_result["target"]
    findings = scan_result["findings"]

    print(f"\n{Style.BRIGHT}VulnScan Report - {target}{Style.RESET_ALL}")
    print(f"Scanned at: {datetime.now(timezone.utc).isoformat()}")
    print(f"Total findings: {len(findings)}\n")

    if not findings:
        print(Fore.GREEN + "No issues found by the checks in this scan." + Style.RESET_ALL)
        return

    for f in findings:
        color = SEVERITY_COLORS.get(f.get("severity", "Info"), Fore.WHITE)
        print(f"{color}[{f.get('severity', 'Info')}]{Style.RESET_ALL} {f.get('check')}")
        for key, value in f.items():
            if key in ("check", "severity"):
                continue
            print(f"    {key}: {value}")
        print()


def write_json_report(scan_result, path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w") as f:
        json.dump(scan_result, f, indent=2, default=str)


def write_html_report(scan_result, path):
    target = scan_result["target"]
    findings = scan_result["findings"]

    rows = ""
    for f in findings:
        details = "; ".join(f"{k}: {v}" for k, v in f.items() if k not in ("check", "severity"))
        severity_class = f.get("severity", "Info").lower()
        rows += f"""
        <tr class="sev-{severity_class}">
          <td>{f.get('severity', 'Info')}</td>
          <td>{f.get('check', '')}</td>
          <td>{details}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VulnScan Report - {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#111; color:#eee; padding:2rem; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem; }}
  th, td {{ border:1px solid #444; padding:8px; text-align:left; font-size:14px; }}
  th {{ background:#222; }}
  .sev-critical {{ background:#4a1010; }}
  .sev-high {{ background:#4a2b10; }}
  .sev-medium {{ background:#4a4210; }}
  .sev-low {{ background:#10334a; }}
  .sev-info {{ background:#222; }}
</style>
</head>
<body>
  <h1>VulnScan Report</h1>
  <p>Target: {target}</p>
  <p>Total findings: {len(findings)}</p>
  <table>
    <tr><th>Severity</th><th>Check</th><th>Details</th></tr>
    {rows}
  </table>
</body>
</html>"""

    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w") as f:
        f.write(html)