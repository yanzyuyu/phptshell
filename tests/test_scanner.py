import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anti_php2shell.scanner import (
    check_ini_upload_progress,
    find_ini_files,
    is_version_vulnerable,
    parse_php_version,
)

class TestScanner(unittest.TestCase):
    def test_version_parsing(self):
        output = "PHP 8.3.20 (cli) (built: Apr 12 2024 10:00:00) (NTS)"
        ver = parse_php_version(output)
        self.assertEqual(ver, (8, 3, 20))

        invalid_output = "command not found: php"
        self.assertIsNone(parse_php_version(invalid_output))

    def test_vulnerability_matrix(self):
        self.assertTrue(is_version_vulnerable((5, 6, 40)))
        self.assertTrue(is_version_vulnerable((7, 4, 33)))
        self.assertTrue(is_version_vulnerable((8, 0, 30)))
        self.assertTrue(is_version_vulnerable((8, 1, 28)))
        self.assertTrue(is_version_vulnerable((8, 2, 34)))
        self.assertFalse(is_version_vulnerable((8, 2, 35)))
        self.assertTrue(is_version_vulnerable((8, 3, 35)))
        self.assertFalse(is_version_vulnerable((8, 3, 36)))
        self.assertTrue(is_version_vulnerable((8, 4, 26)))
        self.assertFalse(is_version_vulnerable((8, 4, 27)))
        self.assertTrue(is_version_vulnerable((8, 5, 11)))
        self.assertFalse(is_version_vulnerable((8, 5, 12)))
        self.assertFalse(is_version_vulnerable((8, 6, 0)))

    def test_check_ini_upload_progress(self):
        with TemporaryDirectory() as tmp_dir:
            p_on = Path(tmp_dir) / "on.ini"
            p_on.write_text("session.upload_progress.enabled = 1\n", encoding="utf-8")
            self.assertTrue(check_ini_upload_progress(p_on))

            p_off = Path(tmp_dir) / "off.ini"
            p_off.write_text("session.upload_progress.enabled = 0\n", encoding="utf-8")
            self.assertFalse(check_ini_upload_progress(p_off))

            p_none = Path(tmp_dir) / "none.ini"
            p_none.write_text("memory_limit = 128M\n", encoding="utf-8")
            self.assertIsNone(check_ini_upload_progress(p_none))

    def test_find_ini_files(self):
        with TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / "a.ini").write_text("", encoding="utf-8")
            sub = base / "sub"
            sub.mkdir()
            (sub / "b.ini").write_text("", encoding="utf-8")
            (sub / "c.txt").write_text("", encoding="utf-8")

            results = find_ini_files([base])
            self.assertEqual(len(results), 2)

if __name__ == "__main__":
    unittest.main()
