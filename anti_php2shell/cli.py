import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from anti_php2shell.checker import audit_url
from anti_php2shell.hunter import scan_log_directory
from anti_php2shell.ledger import RollbackLedger
from anti_php2shell.scanner import run_system_scan
from anti_php2shell.vaccine import export_waf_rules, patch_single_ini, reload_php_services

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
    if args.json:
        data = {
            "binary_path": result.binary_path,
            "version": result.version_str,
            "is_vulnerable": result.is_vulnerable_version,
            "upload_progress_enabled": result.upload_progress_enabled,
            "active_sapi": result.active_sapi,
            "ini_files": [str(p) for p in result.ini_files],
            "risk_level": result.risk_level,
            "summary": result.summary,
        }
        print(json.dumps(data, indent=2))
        return 1 if result.risk_level in ("CRITICAL", "HIGH") else 0

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
    ledger_path = Path(args.ledger) if args.ledger else None
    ledger = RollbackLedger(ledger_path)

    target_inis = []
    if args.ini:
        p = Path(args.ini)
        if p.is_file():
            target_inis.append(p)
        else:
            if args.json:
                print(json.dumps({"error": f"Specified ini file '{p}' not found."}))
            else:
                print(f"Error: Specified ini file '{p}' not found.")
            return 1
    else:
        scan_res = run_system_scan()
        target_inis = scan_res.ini_files

    patch_results = []
    for ini in target_inis:
        if args.dry_run:
            patch_results.append({"file": str(ini), "status": "DRY_RUN", "applied": False})
        else:
            res = patch_single_ini(ini, ledger=ledger)
            patch_results.append(
                {
                    "file": str(res.target_path),
                    "backup": str(res.backup_path) if res.backup_path else None,
                    "applied": res.applied,
                    "status": res.status,
                }
            )

    waf_files = export_waf_rules(out_dir)
    waf_data = [{"name": title, "path": str(filepath)} for title, filepath in waf_files]

    reload_data = []
    if args.reload:
        reloads = reload_php_services()
        reload_data = [{"service": svc, "success": ok, "detail": det} for svc, ok, det in reloads]

    if args.json:
        payload = {
            "patches": patch_results,
            "waf_rules": waf_data,
            "reloads": reload_data,
        }
        print(json.dumps(payload, indent=2))
        return 0

    print("\n--- ANTI-PHP2SHELL ACTIVE INOCULATION ---")
    if not target_inis:
        print("No php.ini files detected to inoculate.")
    else:
        for pr in patch_results:
            if pr.get("status") == "DRY_RUN":
                print(f"[DRY-RUN] Would patch: {pr['file']}")
            elif pr.get("applied"):
                print(f"{badge('VACCINATED', COLOR_GREEN)} {pr['file']}")
                if pr.get("backup"):
                    print(f"  Backup saved: {pr['backup']}")
            else:
                print(f"{badge('FAILED', COLOR_RED)} {pr['file']}: {pr['status']}")

    print(f"\nGenerating WAF Virtual Patch rules in: {out_dir}")
    for item in waf_data:
        print(f"  {badge('GENERATED', COLOR_BLUE)} {item['name']}: {item['path']}")

    if args.reload:
        print("\nReloading services gracefully:")
        for r in reload_data:
            st = badge("RELOADED", COLOR_GREEN) if r["success"] else badge("FAILED", COLOR_RED)
            print(f"  {st} {r['service']}: {r['detail']}")
    else:
        print("\nReminder: Reload your web server or PHP-FPM service to activate changes.\n")

    return 0

def cmd_rollback(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger) if args.ledger else None
    ledger = RollbackLedger(ledger_path)
    results = ledger.rollback(target_filter=args.target)

    if args.json:
        data = [
            {"target": target, "success": ok, "detail": detail}
            for target, ok, detail in results
        ]
        print(json.dumps({"rollback_results": data}, indent=2))
        return 0 if all(ok for _, ok, _ in results) else 1

    print("\n--- ANTI-PHP2SHELL ROLLBACK ENGINE ---")
    if not results:
        print("No recorded transactions found in ledger to rollback.")
        return 0

    all_ok = True
    for target, ok, detail in results:
        if ok:
            print(f"{badge('RESTORED', COLOR_GREEN)} {target}: {detail}")
        else:
            all_ok = False
            print(f"{badge('FAILED', COLOR_RED)} {target}: {detail}")

    print()
    return 0 if all_ok else 1

def cmd_hunt(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
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

    print(f"\n--- ANTI-PHP2SHELL FORENSIC LOG HUNTER ---")
    print(f"Inspecting target path: {log_path}")
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
    report = audit_url(args.url, timeout=args.timeout)
    if args.json:
        data = {
            "target_url": report.target_url,
            "status_code": report.status_code,
            "server_header": report.server_header,
            "php_version": report.php_version,
            "is_php_vulnerable": report.is_php_vulnerable,
            "waf_detected": report.waf_detected,
            "virtual_patch_active": report.virtual_patch_active,
            "missing_headers": report.missing_headers,
            "risk_level": report.risk_level,
            "summary": report.summary,
        }
        print(json.dumps(data, indent=2))
        return 0 if report.risk_level in ("PROTECTED", "LOW") else 1

    print("\n--- ANTI-PHP2SHELL ENDPOINT DEFENSE AUDITOR ---")
    print(f"Target URL: {report.target_url}")
    print(f"HTTP Status: {report.status_code if report.status_code is not None else 'Unreachable'}")
    print(f"Server Header: {report.server_header or 'Hidden / Not exposed'}")
    print(f"PHP Runtime: {report.php_version or 'Hidden / Not exposed'}")
    print(f"WAF Layer: {report.waf_detected or 'None detected'}")
    print(f"Virtual Patch: {'ACTIVE (Drop upload progress)' if report.virtual_patch_active else 'UNFILTERED'}")
    if report.missing_headers:
        print(f"Missing Hardening Headers: {', '.join(report.missing_headers)}")

    level = report.risk_level
    if level == "PROTECTED":
        b = badge("PROTECTED", COLOR_GREEN)
    elif level == "CRITICAL":
        b = badge("CRITICAL EXPOSURE", COLOR_RED)
    elif level == "EXPOSED":
        b = badge("EXPOSED", COLOR_YELLOW)
    elif level == "LOW":
        b = badge("LOW RISK", COLOR_BLUE)
    else:
        b = badge(level, COLOR_RED)

    print(f"\nDefense Status: {b}")
    print(f"Summary: {report.summary}\n")
    return 0 if level in ("PROTECTED", "LOW") else 1

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anti-php2shell",
        description="Zero-dependency defense, audit, and inoculation tool against PHP2Shell (CVE-2026-109618/19).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan local system for vulnerable PHP runtimes and configs.")
    scan_parser.add_argument("--ini-dir", type=str, default=None, help="Custom directory to search for php.ini")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    scan_parser.set_defaults(func=cmd_scan)

    vaccine_parser = subparsers.add_parser("vaccine", help="Immunize php.ini files and export WAF rules.")
    vaccine_parser.add_argument("--ini", type=str, default=None, help="Specific php.ini file to patch")
    vaccine_parser.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    vaccine_parser.add_argument("--out-dir", type=str, default="./waf-rules", help="Directory for WAF rule exports")
    vaccine_parser.add_argument("--ledger", type=str, default=None, help="Custom rollback ledger file path")
    vaccine_parser.add_argument("--reload", action="store_true", help="Gracefully reload PHP and web server services")
    vaccine_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    vaccine_parser.set_defaults(func=cmd_vaccine)

    rollback_parser = subparsers.add_parser("rollback", help="Restore original php.ini files using rollback ledger.")
    rollback_parser.add_argument("--target", type=str, default=None, help="Specific target file to rollback")
    rollback_parser.add_argument("--ledger", type=str, default=None, help="Custom rollback ledger file path")
    rollback_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    rollback_parser.set_defaults(func=cmd_rollback)

    hunt_parser = subparsers.add_parser("hunt", help="Analyze web server logs for PHP2Shell exploitation artifacts.")
    hunt_parser.add_argument("--log", type=str, required=True, help="Path to log file or log directory")
    hunt_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    hunt_parser.set_defaults(func=cmd_hunt)

    check_parser = subparsers.add_parser("check", help="Send safe diagnostic canary probe to target URL.")
    check_parser.add_argument("--url", type=str, required=True, help="Target URL (e.g., http://localhost/index.php)")
    check_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout in seconds")
    check_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    check_parser.set_defaults(func=cmd_check)

    return parser

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
