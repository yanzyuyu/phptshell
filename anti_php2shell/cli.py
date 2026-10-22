import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from anti_php2shell.checker import probe_endpoint
from anti_php2shell.hunter import scan_log_directory
from anti_php2shell.scanner import run_system_scan
from anti_php2shell.vaccine import export_waf_rules, patch_single_ini

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_RESET = "\033[0m"

def is_color_enabled() -> bool:
    return sys.stdout.isatty()

def badge(text: str, color: str) -> str:
    if not is_color_enabled():
        return f"[{text}]"
    return f"{color}[{text}]{COLOR_RESET}"

def cmd_scan(args: argparse.Namespace) -> int:
    result = run_system_scan(custom_ini_dir=args.ini_dir)
    print("\n--- ANTI-PHP2SHELL SECURITY AUDIT ---")
    print(f"PHP Binary: {result.binary_path or 'Not found in PATH'}")
    print(f"Detected Version: {result.version_str or 'Unknown'}")
    print(f"Active SAPI(s): {', '.join(result.active_sapi) if result.active_sapi else 'None detected'}")
    print(f"session.upload_progress: {'ENABLED (Dangerous)' if result.upload_progress_enabled else 'DISABLED (Safe)'}")
    print(f"Found php.ini files: {len(result.ini_files)}")
    for ini in result.ini_files:
        print(f"  - {ini}")

    level = result.risk_level
    if level == "CRITICAL":
        b = badge("CRITICAL RISK", COLOR_RED)
    elif level == "HIGH":
        b = badge("HIGH RISK", COLOR_RED)
    elif level == "MEDIUM":
        b = badge("MEDIUM RISK", COLOR_YELLOW)
    elif level == "IMMUNIZED":
        b = badge("IMMUNIZED", COLOR_GREEN)
    else:
        b = badge(level, COLOR_BLUE)

    print(f"\nAudit Status: {b}")
    print(f"Details: {result.summary}\n")
    return 1 if level in ("CRITICAL", "HIGH") else 0

def cmd_vaccine(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    print("\n--- ANTI-PHP2SHELL ACTIVE INOCULATION ---")

    target_inis = []
    if args.ini:
        p = Path(args.ini)
        if p.is_file():
            target_inis.append(p)
        else:
            print(f"Error: Specified ini file '{p}' not found.")
            return 1
    else:
        scan_res = run_system_scan()
        target_inis = scan_res.ini_files

    if not target_inis:
        print("No php.ini files detected to inoculate.")
    else:
        for ini in target_inis:
            if args.dry_run:
                print(f"[DRY-RUN] Would patch: {ini}")
            else:
                res = patch_single_ini(ini)
                if res.applied:
                    print(f"{badge('VACCINATED', COLOR_GREEN)} {res.target_path}")
                    if res.backup_path:
                        print(f"  Backup saved: {res.backup_path}")
                else:
                    print(f"{badge('FAILED', COLOR_RED)} {res.target_path}: {res.status}")

    print(f"\nGenerating WAF Virtual Patch rules in: {out_dir}")
    waf_files = export_waf_rules(out_dir)
    for title, filepath in waf_files:
        print(f"  {badge('GENERATED', COLOR_BLUE)} {title}: {filepath}")

    print("\nReminder: Reload your web server or PHP-FPM service to activate changes.\n")
    return 0

def cmd_hunt(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
    print(f"\n--- ANTI-PHP2SHELL FORENSIC LOG HUNTER ---")
    print(f"Inspecting target path: {log_path}")

    report = scan_log_directory(log_path)
    if args.json:
        data = {
            "total_lines_scanned": report.total_lines_scanned,
            "incidents_found": report.incidents_found,
            "categories": report.categories,
            "attacker_ips": report.attacker_ips,
            "sample_events": [
                {
                    "log": e.log_file,
                    "line": e.line_number,
                    "category": e.category,
                    "ip": e.client_ip,
                    "timestamp": e.timestamp,
                }
                for e in report.events[:20]
            ],
        }
        print(json.dumps(data, indent=2))
        return 0

    print(f"Lines Scanned: {report.total_lines_scanned:,}")
    print(f"Incidents Detected: {report.incidents_found}")
    if report.incidents_found > 0:
        print(f"\n{badge('INCIDENTS DETECTED', COLOR_RED)}")
        print("\nBreakdown by Category:")
        for cat, cnt in report.categories.items():
            print(f"  - {cat}: {cnt}")

        print("\nTop Suspect Source IPs:")
        sorted_ips = sorted(report.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, cnt in sorted_ips:
            print(f"  - {ip}: {cnt} attempts")

        print("\nRecent Chronological Findings:")
        for ev in report.events[:10]:
            print(f"  [{ev.timestamp or 'NO_TS'}] [{ev.category}] IP: {ev.client_ip} in {ev.log_file}:{ev.line_number}")
    else:
        print(f"\n{badge('CLEAN', COLOR_GREEN)} No PHP2Shell attack signatures found.")
    print()
    return 0

def cmd_check(args: argparse.Namespace) -> int:
    print(f"\n--- ANTI-PHP2SHELL CANARY VERIFIER ---")
    print(f"Probing: {args.url}")
    result = probe_endpoint(args.url, timeout=args.timeout)

    if result.is_blocked_by_waf:
        print(f"Result: {badge('PROTECTED', COLOR_GREEN)}")
        print(f"Server response code: HTTP {result.status_code}")
        print(f"Status: {result.message}\n")
        return 0
    elif result.is_potentially_vulnerable:
        print(f"Result: {badge('VULNERABLE OR UNFILTERED', COLOR_RED)}")
        print(f"Server response code: HTTP {result.status_code}")
        print(f"Status: {result.message}\n")
        return 1
    else:
        print(f"Result: {badge('UNVERIFIED', COLOR_YELLOW)}")
        print(f"Status: {result.message}\n")
        return 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anti-php2shell",
        description="Zero-dependency defense, audit, and inoculation tool against PHP2Shell (CVE-2026-109618/19).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan local system for vulnerable PHP runtimes and configs.")
    scan_parser.add_argument("--ini-dir", type=str, default=None, help="Custom directory to search for php.ini")
    scan_parser.set_defaults(func=cmd_scan)

    vaccine_parser = subparsers.add_parser("vaccine", help="Immunize php.ini files and export WAF rules.")
    vaccine_parser.add_argument("--ini", type=str, default=None, help="Specific php.ini file to patch")
    vaccine_parser.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    vaccine_parser.add_argument("--out-dir", type=str, default="./waf-rules", help="Directory for WAF rule exports")
    vaccine_parser.set_defaults(func=cmd_vaccine)

    hunt_parser = subparsers.add_parser("hunt", help="Analyze web server logs for PHP2Shell exploitation artifacts.")
    hunt_parser.add_argument("--log", type=str, required=True, help="Path to log file or log directory")
    hunt_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    hunt_parser.set_defaults(func=cmd_hunt)

    check_parser = subparsers.add_parser("check", help="Send safe diagnostic canary probe to target URL.")
    check_parser.add_argument("--url", type=str, required=True, help="Target URL (e.g., http://localhost/index.php)")
    check_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout in seconds")
    check_parser.set_defaults(func=cmd_check)

    return parser

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
