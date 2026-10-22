import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anti_php2shell.fs import calculate_sha256
from anti_php2shell.ledger import LedgerEntry, RollbackLedger

class TestLedger(unittest.TestCase):
    def test_record_and_rollback(self):
        with TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            target = base / "php.ini"
            backup = base / "php.ini.bak"
            ledger_file = base / "ledger.json"

            target.write_text("session.upload_progress.enabled = 1\n", encoding="utf-8")
            sha_orig = calculate_sha256(target)

            backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
            target.write_text("session.upload_progress.enabled = 0\n", encoding="utf-8")
            sha_patched = calculate_sha256(target)

            ledger = RollbackLedger(ledger_file)
            entry = LedgerEntry(
                target_path=str(target),
                backup_path=str(backup),
                sha256_before=sha_orig,
                sha256_after=sha_patched,
                timestamp="2026-10-22T08:00:00",
            )
            ledger.record(entry)

            entries = ledger.load()
            self.assertEqual(len(entries), 1)

            results = ledger.rollback()
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0][1])

            self.assertEqual(target.read_text(encoding="utf-8"), "session.upload_progress.enabled = 1\n")
            self.assertEqual(calculate_sha256(target), sha_orig)

            remaining = ledger.load()
            self.assertEqual(len(remaining), 0)

    def test_rollback_corrupted_backup_protection(self):
        with TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            target = base / "php.ini"
            backup = base / "php.ini.bak"
            ledger_file = base / "ledger.json"

            target.write_text("original", encoding="utf-8")
            backup.write_text("tampered", encoding="utf-8")

            ledger = RollbackLedger(ledger_file)
            entry = LedgerEntry(
                target_path=str(target),
                backup_path=str(backup),
                sha256_before="fake_sha",
                sha256_after="fake_sha2",
                timestamp="2026-10-22T08:00:00",
            )
            ledger.record(entry)

            results = ledger.rollback()
            self.assertFalse(results[0][1])
            self.assertIn("mismatch", results[0][2].lower())

if __name__ == "__main__":
    unittest.main()
