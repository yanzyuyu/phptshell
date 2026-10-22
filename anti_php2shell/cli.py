import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from anti_php2shell.checker import audit_url
from anti_php2shell.hunter import scan_log_directory
from anti_php2shell.ledger import RollbackLedger
from anti_php2shell.scanner import run_system_scan
from anti_php2shell.ui import (
    BOLD,
    COLOR_BLUE,
    COLOR_CYAN,
    COLOR_GRAY,
    COLOR_GREEN,
    COLOR_MAGENTA,
    COLOR_RED,
    COLOR_WHITE,
    COLOR_YELLOW,
    badge,
    badge_outline,
    c,
    print_card,
    print_header,
)
from anti_php2shell.vaccine import export_waf_rules, patch_single_ini, reload_php_services

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

    print_header("Host Security Audit", "Evaluating PHP runtime, SAPIs, and upload_progress directives")

    prog_text = (
        c("ENABLED (Dangerous)", COLOR_RED)
        if result.upload_progress_enabled
        else c("DISABLED (Safe)", COLOR_GREEN)
    )
    php_ver = (
        c(result.version_str or "Unknown", COLOR_RED if result.is_vulnerable_version else COLOR_GREEN)
    )

    level = result.risk_level
    if level == "CRITICAL":
        b_status = badge("CRITICAL RISK", "red")
    elif level == "HIGH":
        b_status = badge("HIGH RISK", "red")
    elif level == "MEDIUM":
        b_status = badge("MEDIUM RISK", "yellow")
    elif level == "IMMUNIZED":
        b_status = badge("IMMUNIZED", "green")
    else:
        b_status = badge(level, "blue")

    card_rows = [
        ("PHP Binary", c(result.binary_path or "Not found in PATH", COLOR_CYAN)),
        ("Detected Version", php_ver),
        ("Active SAPI(s)", c(", ".join(result.active_sapi) if result.active_sapi else "None detected", COLOR_YELLOW if "apache_mod_php" in result.active_sapi else COLOR_WHITE)),
        ("Upload Progress", prog_text),
        ("Discovered INIs", c(str(len(result.ini_files)), BOLD + COLOR_WHITE)),
        ("Audit Status", b_status),
    ]
    print_card("RUNTIME DIAGNOSTICS", card_rows)

    if result.ini_files:
        print(f" {c('Discovered Configuration Targets:', BOLD + COLOR_WHITE)}")
        for idx, ini in enumerate(result.ini_files):
            conn = "└─" if idx == len(result.ini_files) - 1 else "├─"
            print(f"  {c(conn, COLOR_GRAY)} {c(str(ini), COLOR_CYAN)}")
        print()

    print(f" {c('Recommendation:', BOLD + COLOR_WHITE)} {result.summary}\n")
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
                print(f"{badge('ERROR', 'red')} Specified ini file '{p}' not found.")
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

    print_header("Runtime Inoculation", "Applying atomic INI hardening and exporting WAF virtual patches")

    if not target_inis:
        print(f" {badge('NOTICE', 'blue')} No php.ini targets detected to inoculate.\n")
    else:
        print(f" {c('Configuration Inoculation Targets:', BOLD + COLOR_WHITE)}")
        for idx, pr in enumerate(patch_results):
            conn = "└─" if idx == len(patch_results) - 1 else "├─"
            if pr.get("status") == "DRY_RUN":
                print(f"  {c(conn, COLOR_GRAY)} {badge('DRY-RUN', 'yellow')} {c(pr['file'], COLOR_CYAN)}")
            elif pr.get("applied"):
                print(f"  {c(conn, COLOR_GRAY)} {badge('VACCINATED', 'green')} {c(pr['file'], COLOR_CYAN)}")
                if pr.get("backup"):
                    print(f"     {c('└─ Backup:', COLOR_GRAY)} {c(pr['backup'], COLOR_GRAY)}")
            else:
                print(f"  {c(conn, COLOR_GRAY)} {badge('FAILED', 'red')} {c(pr['file'], COLOR_RED)}: {pr['status']}")
        print()

    print(f" {c('Exported WAF Virtual Patch Rules:', BOLD + COLOR_WHITE)}")
    for idx, item in enumerate(waf_data):
        conn = "└─" if idx == len(waf_data) - 1 else "├─"
        print(f"  {c(conn, COLOR_GRAY)} {badge_outline('EXPORTED', 'cyan')} {c(item['name'], BOLD + COLOR_WHITE)}: {c(item['path'], COLOR_CYAN)}")
    print()

    if args.reload:
        print(f" {c('Graceful Service Reloads:', BOLD + COLOR_WHITE)}")
        for idx, r in enumerate(reload_data):
            conn = "└─" if idx == len(reload_data) - 1 else "├─"
            st = badge("RELOADED", "green") if r["success"] else badge("FAILED", "red")
            print(f"  {c(conn, COLOR_GRAY)} {st} {c(r['service'], BOLD + COLOR_WHITE)}: {r['detail']}")
        print()
    else:
        print(f" {badge('REMINDER', 'yellow')} Reload your web server or PHP-FPM service to activate configuration changes.\n")

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

    print_header("Rollback Engine", "Restoring configuration states via SHA-256 validated ledger")

    if not results:
        print(f" {badge('CLEAN', 'green')} No recorded transactions found in ledger to rollback.\n")
        return 0

    all_ok = True
    print(f" {c('Rollback Operations:', BOLD + COLOR_WHITE)}")
    for idx, (target, ok, detail) in enumerate(results):
        conn = "└─" if idx == len(results) - 1 else "├─"
        if ok:
            print(f"  {c(conn, COLOR_GRAY)} {badge('RESTORED', 'green')} {c(target, COLOR_CYAN)}: {detail}")
        else:
            all_ok = False
            print(f"  {c(conn, COLOR_GRAY)} {badge('FAILED', 'red')} {c(target, COLOR_RED)}: {detail}")
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

    print_header("Forensic Log Hunter", f"Scanning access & error logs in: {log_path}")

    summary_rows = [
        ("Lines Processed", c(f"{report.total_lines_scanned:,}", BOLD + COLOR_WHITE)),
        ("Suspicious Incidents", c(str(report.incidents_found), COLOR_RED if report.incidents_found > 0 else COLOR_GREEN)),
        ("Unique Suspect IPs", c(str(len(report.attacker_ips)), COLOR_YELLOW if report.attacker_ips else COLOR_GREEN)),
    ]
    print_card("LOG METRICS", summary_rows)

    if report.incidents_found > 0:
        print(f" {badge('INCIDENTS DETECTED', 'red')}\n")
        print(f" {c('Incident Signatures:', BOLD + COLOR_WHITE)}")
        for cat, cnt in report.categories.items():
            print(f"  {c('•', COLOR_RED)} {c(cat, COLOR_YELLOW)}: {c(str(cnt), BOLD + COLOR_WHITE)}")
        print()

        print(f" {c('Top Suspect Remote IPs:', BOLD + COLOR_WHITE)}")
        sorted_ips = sorted(report.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:8]
        for ip, cnt in sorted_ips:
            print(f"  {c('•', COLOR_YELLOW)} {c(ip, COLOR_CYAN)}: {cnt} attempts")
        print()

        print(f" {c('Recent Event Trace:', BOLD + COLOR_WHITE)}")
        for ev in report.events[:8]:
            ts = c(ev.timestamp or "NO_TS", COLOR_GRAY)
            ip_str = c(ev.client_ip or "unknown", COLOR_CYAN)
            cat_str = c(ev.category, COLOR_YELLOW)
            print(f"  [{ts}] [{cat_str}] IP: {ip_str} in {c(ev.log_file, COLOR_GRAY)}:{ev.line_number}")
        print()
    else:
        print(f" {badge('CLEAN', 'green')} No PHP2Shell attack signatures or memory corruption crashes detected.\n")

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

    print_header("Endpoint Exposure Auditor", "Testing remote HTTP headers, WAF filters, and canary parameters")

    php_str = (
        c(f"{report.php_version} (Vulnerable)", COLOR_RED)
        if report.is_php_vulnerable
        else c(report.php_version or "Hidden / Not exposed", COLOR_GREEN if report.php_version else COLOR_WHITE)
    )
    patch_str = (
        c("ACTIVE (HTTP 403 Forbidden)", COLOR_GREEN)
        if report.virtual_patch_active
        else c("UNFILTERED (Accepted)", COLOR_RED)
    )

    level = report.risk_level
    if level == "PROTECTED":
        b_risk = badge("PROTECTED", "green")
    elif level == "CRITICAL":
        b_risk = badge("CRITICAL EXPOSURE", "red")
    elif level == "EXPOSED":
        b_risk = badge("EXPOSED", "yellow")
    elif level == "LOW":
        b_risk = badge("LOW RISK", "blue")
    else:
        b_risk = badge(level, "red")

    endpoint_rows = [
        ("Target URL", c(report.target_url, COLOR_CYAN)),
        ("HTTP Response", c(str(report.status_code) if report.status_code is not None else "Unreachable", COLOR_GREEN if report.status_code == 200 else COLOR_YELLOW)),
        ("Server Header", c(report.server_header or "Hidden", COLOR_WHITE)),
        ("PHP Runtime", php_str),
        ("WAF Detected", c(report.waf_detected or "None detected", COLOR_MAGENTA if report.waf_detected else COLOR_GRAY)),
        ("Virtual Patch", patch_str),
        ("Audit Status", b_risk),
    ]
    print_card("ENDPOINT POSTURE", endpoint_rows)

    if report.missing_headers:
        print(f" {c('Missing Security Hardening Headers:', BOLD + COLOR_WHITE)}")
        for idx, h in enumerate(report.missing_headers):
            conn = "└─" if idx == len(report.missing_headers) - 1 else "├─"
            print(f"  {c(conn, COLOR_GRAY)} {c(h, COLOR_YELLOW)}")
        print()

    print(f" {c('Analysis:', BOLD + COLOR_WHITE)} {report.summary}\n")
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
