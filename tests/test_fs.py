import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anti_php2shell.fs import atomic_write, calculate_sha256

class TestFs(unittest.TestCase):
    def test_atomic_write_and_sha256(self):
        with TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "test.txt"
            content = "hello production security"
            atomic_write(target, content)

            self.assertTrue(target.is_file())
            self.assertEqual(target.read_text(encoding="utf-8"), content)

            sha1 = calculate_sha256(target)
            self.assertEqual(len(sha1), 64)

            atomic_write(target, "updated content")
            sha2 = calculate_sha256(target)
            self.assertNotEqual(sha1, sha2)
            self.assertEqual(target.read_text(encoding="utf-8"), "updated content")

    def test_permission_preservation(self):
        with TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "perm.txt"
            target.write_text("initial", encoding="utf-8")
            os.chmod(target, 0o600)

            atomic_write(target, "rewritten")
            new_mode = target.stat().st_mode & 0o777
            self.assertEqual(new_mode, 0o600)

if __name__ == "__main__":
    unittest.main()
