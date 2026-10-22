import hashlib
import os
import tempfile
from pathlib import Path
from typing import Optional

def calculate_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def atomic_write(target_path: Path, content: str) -> None:
    parent = target_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    
    stat_info = None
    if target_path.exists():
        stat_info = target_path.stat()

    with tempfile.NamedTemporaryFile(
        mode="w",
        dir=parent,
        prefix=f".tmp_{target_path.name}_",
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)

    try:
        if stat_info is not None:
            os.chmod(tmp_path, stat_info.st_mode)
            try:
                os.chown(tmp_path, stat_info.st_uid, stat_info.st_gid)
            except (PermissionError, OSError):
                pass
        os.replace(tmp_path, target_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
