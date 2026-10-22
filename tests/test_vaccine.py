import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anti_php2shell.vaccine import export_waf_rules, patch_single_ini

class TestVaccine(unittest.TestCase):
    def test_patch_existing_directive(self):
        with TemporaryDirectory() as tmp_dir:
            ini_file = Path(tmp_dir) / "php.ini"
            ini_file.write_text("session.upload_progress.enabled = 1\n", encoding="utf-8")

            res = patch_single_ini(ini_file)
            self.assertTrue(res.applied)
            self.assertIsNotNone(res.backup_path)
            self.assertTrue(res.backup_path.is_file())

            updated = ini_file.read_text(encoding="utf-8")
            self.assertIn("session.upload_progress.enabled = 0", updated)
            self.assertNotIn("session.upload_progress.enabled = 1", updated)

    def test_patch_missing_directive_with_section(self):
        with TemporaryDirectory() as tmp_dir:
            ini_file = Path(tmp_dir) / "php.ini"
            ini_file.write_text("[Session]\nsession.save_path = /tmp\n", encoding="utf-8")

            res = patch_single_ini(ini_file)
            self.assertTrue(res.applied)

            updated = ini_file.read_text(encoding="utf-8")
            self.assertIn("session.upload_progress.enabled = 0", updated)

    def test_export_waf_rules(self):
        with TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "waf"
            rules = export_waf_rules(out_dir)
            self.assertEqual(len(rules), 4)
            for _, path in rules:
                self.assertTrue(path.is_file())
                content = path.read_text(encoding="utf-8")
                self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", content)

    def test_patch_with_ledger(self):
        from anti_php2shell.ledger import RollbackLedger
        with TemporaryDirectory() as tmp_dir:
            ini_file = Path(tmp_dir) / "php.ini"
            ini_file.write_text("session.upload_progress.enabled = 1\n", encoding="utf-8")
            ledger_file = Path(tmp_dir) / "state.json"
            ledger = RollbackLedger(ledger_file)

            res = patch_single_ini(ini_file, ledger=ledger)
            self.assertTrue(res.applied)
            entries = ledger.load()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].target_path, str(ini_file.resolve()))

if __name__ == "__main__":
    unittest.main()
