import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from anti_php2shell.fs import atomic_write, calculate_sha256

DEFAULT_LEDGER_PATH = Path(".anti-php2shell-state.json")

@dataclass
class LedgerEntry:
    target_path: str
    backup_path: str
    sha256_before: str
    sha256_after: str
    timestamp: str

class RollbackLedger:
    def __init__(self, ledger_path: Optional[Path] = None):
        self.ledger_path = ledger_path or DEFAULT_LEDGER_PATH

    def load(self) -> List[LedgerEntry]:
        if not self.ledger_path.is_file():
            return []
        try:
            data = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            return [LedgerEntry(**item) for item in data.get("transactions", [])]
        except Exception:
            return []

    def save(self, entries: List[LedgerEntry]) -> None:
        raw = {"transactions": [asdict(e) for e in entries]}
        atomic_write(self.ledger_path, json.dumps(raw, indent=2))

    def record(self, entry: LedgerEntry) -> None:
        entries = self.load()
        entries = [e for e in entries if e.target_path != entry.target_path]
        entries.append(entry)
        self.save(entries)

    def rollback(self, target_filter: Optional[str] = None) -> List[Tuple[str, bool, str]]:
        entries = self.load()
        if not entries:
            return []

        remaining = []
        results = []

        for entry in reversed(entries):
            if target_filter and entry.target_path != target_filter:
                remaining.append(entry)
                continue

            target = Path(entry.target_path)
            backup = Path(entry.backup_path)

            if not backup.is_file():
                results.append((entry.target_path, False, f"Backup file not found: {backup}"))
                remaining.append(entry)
                continue

            current_backup_hash = calculate_sha256(backup)
            if current_backup_hash != entry.sha256_before:
                results.append(
                    (
                        entry.target_path,
                        False,
                        "Backup hash mismatch, aborting restore to prevent corruption",
                    )
                )
                remaining.append(entry)
                continue

            try:
                content = backup.read_text(encoding="utf-8", errors="ignore")
                atomic_write(target, content)
                restored_hash = calculate_sha256(target)
                if restored_hash != entry.sha256_before:
                    results.append((entry.target_path, False, "Hash verification failed after write"))
                    remaining.append(entry)
                    continue
                results.append((entry.target_path, True, "Restored and verified successfully"))
            except Exception as e:
                results.append((entry.target_path, False, f"Write error: {e}"))
                remaining.append(entry)

        self.save(list(reversed(remaining)))
        return results
