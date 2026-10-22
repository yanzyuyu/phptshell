import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from anti_php2shell.scanner import is_version_vulnerable, parse_php_version

@dataclass
class UrlAuditReport:
    target_url: str
    status_code: Optional[int]
    server_header: Optional[str]
    php_version: Optional[str]
    is_php_vulnerable: bool
    waf_detected: Optional[str]
    virtual_patch_active: bool
    missing_headers: List[str] = field(default_factory=list)
    risk_level: str = "UNKNOWN"
    summary: str = ""

def detect_waf(headers: Dict[str, str]) -> Optional[str]:
    lower_keys = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" in lower_keys or "cf-cache-status" in lower_keys:
        return "Cloudflare"
    if "x-amzn-requestid" in lower_keys or "x-amz-cf-id" in lower_keys:
        return "AWS WAF / CloudFront"
    if "x-sucuri-id" in lower_keys:
        return "Sucuri WAF"
    if "x-imperva-id" in lower_keys or "x-iinfo" in lower_keys:
        return "Imperva WAF"
    server = lower_keys.get("server", "").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    if "akamai" in server:
        return "Akamai"
    return None

def audit_url(target_url: str, timeout: float = 6.0) -> UrlAuditReport:
    headers_detected: Dict[str, str] = {}
    status_code: Optional[int] = None
    server_hdr: Optional[str] = None
    php_ver_str: Optional[str] = None
    is_vuln_php: bool = False
    missing_sec_headers: List[str] = []

    req_head = urllib.request.Request(
        target_url,
        headers={"User-Agent": "anti-php2shell-auditor/1.0"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req_head, timeout=timeout) as resp:
            status_code = resp.getcode()
            headers_detected = dict(resp.info())
    except urllib.error.HTTPError as e:
        status_code = e.code
        headers_detected = dict(e.headers)
    except Exception as e:
        return UrlAuditReport(
            target_url=target_url,
            status_code=None,
            server_header=None,
            php_version=None,
            is_php_vulnerable=False,
            waf_detected=None,
            virtual_patch_active=False,
            risk_level="UNREACHABLE",
            summary=f"Connection failed: {e}",
        )

    lower_headers = {k.lower(): v for k, v in headers_detected.items()}
    server_hdr = lower_headers.get("server")

    powered_by = lower_headers.get("x-powered-by", "")
    if "php" in powered_by.lower():
        ver_match = re.search(r"PHP/(\d+\.\d+\.\d+)", powered_by, re.IGNORECASE)
        if ver_match:
            php_ver_str = ver_match.group(1)
            parsed_ver = parse_php_version(f"PHP {php_ver_str}")
            if parsed_ver:
                is_vuln_php = is_version_vulnerable(parsed_ver)

    waf_name = detect_waf(headers_detected)

    for h in ["x-content-type-options", "x-frame-options", "content-security-policy"]:
        if h not in lower_headers:
            missing_sec_headers.append(h)

    boundary = "----AntiPhp2ShellCanaryBoundary987123"
    canary_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"diagnostic_probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="probe"; filename="test.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"healthcheck\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    probe_req = urllib.request.Request(
        target_url,
        data=canary_body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "anti-php2shell-auditor/1.0",
        },
        method="POST",
    )

    virtual_patch_blocked = False
    try:
        with urllib.request.urlopen(probe_req, timeout=timeout) as probe_resp:
            virtual_patch_blocked = False
    except urllib.error.HTTPError as e:
        if e.code in (400, 403, 406):
            virtual_patch_blocked = True
    except Exception:
        pass

    if virtual_patch_blocked:
        risk = "PROTECTED"
        summary = "Endpoint is hardened. Virtual patch or WAF is actively dropping PHP2Shell parameters."
    elif is_vuln_php:
        risk = "CRITICAL"
        summary = f"Vulnerable PHP version exposed ({php_ver_str}) without active virtual patch protection."
    elif php_ver_str and not is_vuln_php:
        risk = "LOW"
        summary = f"PHP version {php_ver_str} is patched against CVE-2026-109618/19."
    elif not virtual_patch_blocked:
        risk = "EXPOSED"
        summary = "Endpoint accepted upload progress multipart request without WAF blocking."
    else:
        risk = "NEUTRAL"
        summary = "Audit completed with inconclusive signature state."

    return UrlAuditReport(
        target_url=target_url,
        status_code=status_code,
        server_header=server_hdr,
        php_version=php_ver_str,
        is_php_vulnerable=is_vuln_php,
        waf_detected=waf_name,
        virtual_patch_active=virtual_patch_blocked,
        missing_headers=missing_sec_headers,
        risk_level=risk,
        summary=summary,
    )

def probe_endpoint(target_url: str, timeout: float = 6.0):
    report = audit_url(target_url, timeout=timeout)
    from dataclasses import dataclass

    @dataclass
    class LegacyCanaryResult:
        target_url: str
        status_code: Optional[int]
        is_blocked_by_waf: bool
        is_potentially_vulnerable: bool
        headers: Dict[str, str]
        message: str

    return LegacyCanaryResult(
        target_url=report.target_url,
        status_code=report.status_code,
        is_blocked_by_waf=report.virtual_patch_active,
        is_potentially_vulnerable=not report.virtual_patch_active and report.is_php_vulnerable,
        headers={},
        message=report.summary,
    )
