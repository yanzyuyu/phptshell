import configparser
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Tuple

def validate_php_ini_content(content: str) -> Tuple[bool, str]:
    wrapped = content if content.strip().startswith("[") else f"[__global__]\n{content}"
    parser = configparser.ConfigParser(strict=False)
    try:
        parser.read_string(wrapped)
    except Exception as e:
        return False, f"INI syntax parser error: {e}"

    php_bin = shutil.which("php")
    if php_bin:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            res = subprocess.run(
                [php_bin, "-c", str(tmp_path), "-v"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                err_msg = res.stderr.strip() or f"PHP binary rejected config with exit code {res.returncode}"
                return False, err_msg
            if "PHP:  syntax error" in res.stderr:
                return False, res.stderr.strip()
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    return True, "Syntax valid"
