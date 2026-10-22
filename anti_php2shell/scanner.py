import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

@dataclass
class ScanResult:
    binary_path: Optional[str]
    version_str: Optional[str]
    is_vulnerable_version: bool
    upload_progress_enabled: Optional[bool]
    active_sapi: List[str] = field(default_factory=list)
    ini_files: List[Path] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    summary: str = ""

def parse_php_version(version_output: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"PHP\s+(\d+)\.(\d+)\.(\d+)", version_output)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))

def is_version_vulnerable(ver: Tuple[int, int, int]) -> bool:
    major, minor, patch = ver
    if major < 8 or (major == 8 and minor < 2):
        return True
    if major == 8 and minor == 2:
        return patch < 35
    if major == 8 and minor == 3:
        return patch < 36
    if major == 8 and minor == 4:
        return patch < 27
    if major == 8 and minor == 5:
        return patch < 12
    return False

def find_ini_files(search_paths: Optional[List[Path]] = None) -> List[Path]:
    if search_paths is None:
        search_paths = [
            Path("/etc/php"),
            Path("/usr/local/etc/php"),
            Path("/etc/php.ini"),
            Path("/opt/homebrew/etc/php"),
        ]
    found: List[Path] = []
    for base in search_paths:
        if not base.exists():
            continue
        if base.is_file() and base.name.endswith(".ini"):
            found.append(base.resolve())
            continue
        try:
            for item in base.rglob("*.ini"):
                if item.is_file() and ("mods-available" not in item.parts and "conf.d" not in item.parts):
                    found.append(item.resolve())
        except PermissionError:
            continue
    return sorted(list(set(found)))

def check_ini_upload_progress(ini_path: Path) -> Optional[bool]:
    if not ini_path.is_file():
        return None
    try:
        content = ini_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    matches = re.findall(
        r"^\s*session\.upload_progress\.enabled\s*=\s*([^\s;]+)",
        content,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if not matches:
        return None
    val = matches[-1].strip().lower()
    return val in ("1", "on", "true", "yes")

def detect_active_sapis() -> List[str]:
    sapis: List[str] = []
    apache_cmds = [shutil.which("apache2ctl"), shutil.which("httpd")]
    for cmd in apache_cmds:
        if not cmd:
            continue
        try:
            res = subprocess.run([cmd, "-M"], capture_output=True, text=True, check=False)
            if "php" in res.stdout.lower():
                sapis.append("apache_mod_php")
                break
        except Exception:
            pass

    fpm_sockets = list(Path("/var/run").glob("*fpm*.sock")) + list(Path("/run").glob("*fpm*.sock"))
    if fpm_sockets:
        sapis.append("php-fpm")
    else:
        systemctl = shutil.which("systemctl")
        if systemctl:
            try:
                res = subprocess.run(
                    [systemctl, "is-active", "php*-fpm"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if "active" in res.stdout:
                    sapis.append("php-fpm")
            except Exception:
                pass

    if shutil.which("frankenphp"):
        sapis.append("frankenphp")
    return list(set(sapis))

def run_system_scan(custom_ini_dir: Optional[str] = None) -> ScanResult:
    php_bin = shutil.which("php")
    ver_tuple = None
    ver_str = None
    upload_prog_enabled = None

    if php_bin:
        try:
            res = subprocess.run([php_bin, "-v"], capture_output=True, text=True, check=False)
            ver_tuple = parse_php_version(res.stdout)
            if ver_tuple:
                ver_str = f"{ver_tuple[0]}.{ver_tuple[1]}.{ver_tuple[2]}"
        except Exception:
            pass

        try:
            res_ini = subprocess.run([php_bin, "-i"], capture_output=True, text=True, check=False)
            match = re.search(r"session\.upload_progress\.enabled\s*=>\s*([^\s]+)", res_ini.stdout)
            if match:
                val = match.group(1).lower()
                upload_prog_enabled = val in ("on", "1", "true")
        except Exception:
            pass

    search_dirs = [Path(custom_ini_dir)] if custom_ini_dir else None
    ini_files = find_ini_files(search_dirs)

    if upload_prog_enabled is None and ini_files:
        for ini in ini_files:
            state = check_ini_upload_progress(ini)
            if state is not None:
                upload_prog_enabled = state
                break

    if upload_prog_enabled is None:
        upload_prog_enabled = True

    is_vuln = False if ver_tuple is None else is_version_vulnerable(ver_tuple)
    sapis = detect_active_sapis()

    if not php_bin and not ini_files:
        risk = "CLEAN"
        summary = "No PHP installation or configuration detected on the host."
    elif not is_vuln and ver_tuple is not None:
        risk = "IMMUNIZED"
        summary = f"PHP {ver_str} is patched against CVE-2026-109618/19."
    elif is_vuln and upload_prog_enabled:
        if "apache_mod_php" in sapis:
            risk = "CRITICAL"
            summary = f"PHP {ver_str} vulnerable with mod_php active and upload_progress enabled."
        else:
            risk = "HIGH"
            summary = f"PHP {ver_str} vulnerable with session.upload_progress.enabled=1."
    elif is_vuln and not upload_prog_enabled:
        risk = "MEDIUM"
        summary = f"PHP {ver_str} binary unpatched, but session.upload_progress is disabled."
    else:
        risk = "UNKNOWN"
        summary = "Ambiguous state; manually verify PHP installation."

    return ScanResult(
        binary_path=php_bin,
        version_str=ver_str,
        is_vulnerable_version=is_vuln,
        upload_progress_enabled=upload_prog_enabled,
        active_sapi=sapis,
        ini_files=ini_files,
        risk_level=risk,
        summary=summary,
    )
