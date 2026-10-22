import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

@dataclass
class CanaryResult:
    target_url: str
    status_code: Optional[int]
    is_blocked_by_waf: bool
    is_potentially_vulnerable: bool
    headers: Dict[str, str]
    message: str

def probe_endpoint(target_url: str, timeout: float = 6.0) -> CanaryResult:
    boundary = "----AntiPhp2ShellCanaryBoundary987123"
    payload = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"canary_probe\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="canary_file"; filename="test.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"healthcheck\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    req = urllib.request.Request(
        target_url,
        data=payload,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "anti-php2shell-canary/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.getcode()
            headers = dict(response.info())
            msg = f"Endpoint responded with HTTP {status}. Server accepted upload progress field."
            return CanaryResult(
                target_url=target_url,
                status_code=status,
                is_blocked_by_waf=False,
                is_potentially_vulnerable=True,
                headers=headers,
                message=msg,
            )
    except urllib.error.HTTPError as e:
        status = e.code
        headers = dict(e.headers)
        if status in (403, 400, 406):
            msg = f"HTTP {status} returned. WAF or virtual patch is successfully blocking PHP2Shell parameters."
            return CanaryResult(
                target_url=target_url,
                status_code=status,
                is_blocked_by_waf=True,
                is_potentially_vulnerable=False,
                headers=headers,
                message=msg,
            )
        msg = f"HTTP {status} returned. Verify server behavior."
        return CanaryResult(
            target_url=target_url,
            status_code=status,
            is_blocked_by_waf=False,
            is_potentially_vulnerable=False,
            headers=headers,
            message=msg,
        )
    except Exception as e:
        return CanaryResult(
            target_url=target_url,
            status_code=None,
            is_blocked_by_waf=False,
            is_potentially_vulnerable=False,
            headers={},
            message=f"Connection failed: {e}",
        )
