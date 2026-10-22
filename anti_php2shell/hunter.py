import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, List, Optional

@dataclass
class IncidentEvent:
    log_file: str
    line_number: int
    raw_line: str
    category: str
    client_ip: Optional[str]
    timestamp: Optional[str]

@dataclass
class HuntReport:
    total_lines_scanned: int
    incidents_found: int
    categories: Dict[str, int] = field(default_factory=dict)
    attacker_ips: Dict[str, int] = field(default_factory=dict)
    events: List[IncidentEvent] = field(default_factory=list)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_REGEX = re.compile(r"\[([^\]]+)\]")
PHP2SHELL_PATTERNS = [
    (re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.IGNORECASE), "EXPLOIT_PROBE_UPLOAD_PROGRESS"),
    (re.compile(r"php_session_rfc1867_callback", re.IGNORECASE), "EXPLOIT_PRIMITIVE_RFC1867"),
    (re.compile(r"exited on signal 11 \(SIGSEGV\)", re.IGNORECASE), "WORKER_CRASH_SIGSEGV"),
    (re.compile(r"child \d+ exited with code 139", re.IGNORECASE), "WORKER_CRASH_SIGSEGV"),
    (re.compile(r"Allowed memory size of \d+ bytes exhausted", re.IGNORECASE), "HEAP_EXHAUSTION_OOM"),
]

def normalize_line(line: str) -> str:
    try:
        decoded = urllib.parse.unquote(line)
        return f"{line} {decoded}"
    except Exception:
        return line

def analyze_log_file(log_path: Path, max_events: int = 500) -> HuntReport:
    report = HuntReport(total_lines_scanned=0, incidents_found=0)
    if not log_path.is_file():
        return report

    try:
        with log_path.open("r", encoding="utf-8", errors="ignore", buffering=65536) as f:
            for idx, raw_line in enumerate(f, start=1):
                report.total_lines_scanned += 1
                search_target = normalize_line(raw_line)

                matched_category = None
                for regex, cat in PHP2SHELL_PATTERNS:
                    if regex.search(search_target):
                        matched_category = cat
                        break

                if matched_category:
                    report.incidents_found += 1
                    report.categories[matched_category] = report.categories.get(matched_category, 0) + 1

                    ip_match = IP_REGEX.search(raw_line)
                    client_ip = ip_match.group(0) if ip_match else "unknown"
                    report.attacker_ips[client_ip] = report.attacker_ips.get(client_ip, 0) + 1

                    time_match = TIMESTAMP_REGEX.search(raw_line)
                    ts = time_match.group(1) if time_match else None

                    if len(report.events) < max_events:
                        report.events.append(
                            IncidentEvent(
                                log_file=log_path.name,
                                line_number=idx,
                                raw_line=raw_line.strip(),
                                category=matched_category,
                                client_ip=client_ip,
                                timestamp=ts,
                            )
                        )
    except Exception:
        pass

    return report

def scan_log_directory(log_dir: Path) -> HuntReport:
    aggregate = HuntReport(total_lines_scanned=0, incidents_found=0)
    if not log_dir.exists():
        return aggregate

    files_to_check = []
    if log_dir.is_file():
        files_to_check.append(log_dir)
    else:
        for p in log_dir.rglob("*.log"):
            if p.is_file():
                files_to_check.append(p)

    for log_file in files_to_check:
        rep = analyze_log_file(log_file)
        aggregate.total_lines_scanned += rep.total_lines_scanned
        aggregate.incidents_found += rep.incidents_found
        for k, v in rep.categories.items():
            aggregate.categories[k] = aggregate.categories.get(k, 0) + v
        for ip, count in rep.attacker_ips.items():
            aggregate.attacker_ips[ip] = aggregate.attacker_ips.get(ip, 0) + count
        aggregate.events.extend(rep.events)

    return aggregate
