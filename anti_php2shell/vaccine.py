import datetime
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from anti_php2shell.fs import atomic_write, calculate_sha256
from anti_php2shell.ledger import LedgerEntry, RollbackLedger
from anti_php2shell.validator import validate_php_ini_content

@dataclass
class PatchResult:
    target_path: Path
    backup_path: Optional[Path]
    applied: bool
    status: str

def patch_single_ini(ini_path: Path, ledger: Optional[RollbackLedger] = None) -> PatchResult:
    if not ini_path.is_file():
        return PatchResult(ini_path, None, False, "File does not exist")
    try:
        content = ini_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return PatchResult(ini_path, None, False, f"Read error: {e}")

    sha_before = calculate_sha256(ini_path)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = ini_path.with_suffix(f".bak_{timestamp}")

    try:
        shutil.copy2(ini_path, backup_path)
    except Exception as e:
        return PatchResult(ini_path, None, False, f"Backup creation failed: {e}")

    pattern = r"^\s*;?\s*session\.upload_progress\.enabled\s*=\s*[^\r\n]*"
    new_directive = "session.upload_progress.enabled = 0"

    if re.search(pattern, content, flags=re.MULTILINE | re.IGNORECASE):
        updated_content = re.sub(
            pattern,
            new_directive,
            content,
            flags=re.MULTILINE | re.IGNORECASE,
        )
    else:
        session_header = re.search(r"^\s*\[Session\]", content, flags=re.MULTILINE | re.IGNORECASE)
        if session_header:
            idx = session_header.end()
            updated_content = content[:idx] + f"\n{new_directive}" + content[idx:]
        else:
            updated_content = content.rstrip() + f"\n\n[Session]\n{new_directive}\n"

    valid, err_msg = validate_php_ini_content(updated_content)
    if not valid:
        if backup_path.exists():
            backup_path.unlink()
        return PatchResult(ini_path, None, False, f"Pre-flight syntax check failed: {err_msg}")

    try:
        atomic_write(ini_path, updated_content)
    except Exception as e:
        return PatchResult(ini_path, backup_path, False, f"Atomic write error: {e}")

    sha_after = calculate_sha256(ini_path)
    if ledger:
        ledger.record(
            LedgerEntry(
                target_path=str(ini_path.resolve()),
                backup_path=str(backup_path.resolve()),
                sha256_before=sha_before,
                sha256_after=sha_after,
                timestamp=datetime.datetime.now().isoformat(),
            )
        )

    return PatchResult(ini_path, backup_path, True, "Inoculated and verified atomically")

def reload_php_services() -> List[Tuple[str, bool, str]]:
    results = []
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return [("init", False, "systemctl not found on host")]

    services = ["php*-fpm", "apache2", "httpd", "nginx"]
    for svc in services:
        try:
            check_run = subprocess.run(
                [systemctl, "is-active", svc],
                capture_output=True,
                text=True,
                check=False,
            )
            if "active" in check_run.stdout:
                reload_run = subprocess.run(
                    [systemctl, "reload", svc],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if reload_run.returncode == 0:
                    results.append((svc, True, "Service reloaded gracefully"))
                else:
                    results.append((svc, False, reload_run.stderr.strip() or "Reload returned non-zero code"))
        except Exception as e:
            results.append((svc, False, f"Execution failed: {e}"))
    return results

def generate_nginx_rule() -> str:
    return (
        "location ~ \\.php$ {\n"
        "    if ($args ~* \"PHP_SESSION_UPLOAD_PROGRESS\") {\n"
        "        return 403 \"Forbidden: PHP2Shell probe blocked\";\n"
        "    }\n"
        "    try_files $uri =404;\n"
        "    fastcgi_pass unix:/var/run/php/php-fpm.sock;\n"
        "    fastcgi_index index.php;\n"
        "    include fastcgi_params;\n"
        "}"
    )

def generate_apache_rule() -> str:
    return (
        "<IfModule mod_rewrite.c>\n"
        "RewriteEngine On\n"
        "RewriteCond %{QUERY_STRING} (?:PHP_SESSION_UPLOAD_PROGRESS) [NC,OR]\n"
        "RewriteCond %{THE_REQUEST} (?:PHP_SESSION_UPLOAD_PROGRESS) [NC]\n"
        "RewriteRule .* - [F,L]\n"
        "</IfModule>"
    )

def generate_caddy_rule() -> str:
    return (
        "@php2shell_blocked {\n"
        "    query *PHP_SESSION_UPLOAD_PROGRESS*\n"
        "}\n"
        "handle @php2shell_blocked {\n"
        "    respond \"Blocked by anti-php2shell\" 403\n"
        "}"
    )

def generate_cloudflare_rule() -> str:
    return (
        '(http.request.uri.query contains "PHP_SESSION_UPLOAD_PROGRESS") or '
        '(http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS")'
    )

def export_waf_rules(out_dir: Path) -> List[Tuple[str, Path]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = []

    nginx_file = out_dir / "nginx_anti_php2shell.conf"
    atomic_write(nginx_file, generate_nginx_rule())
    generated.append(("Nginx", nginx_file))

    apache_file = out_dir / "apache_anti_php2shell.conf"
    atomic_write(apache_file, generate_apache_rule())
    generated.append(("Apache (.htaccess)", apache_file))

    caddy_file = out_dir / "caddy_anti_php2shell.snippet"
    atomic_write(caddy_file, generate_caddy_rule())
    generated.append(("Caddy", caddy_file))

    cf_file = out_dir / "cloudflare_waf_rule.txt"
    atomic_write(cf_file, generate_cloudflare_rule())
    generated.append(("Cloudflare WAF Expression", cf_file))

    return generated
