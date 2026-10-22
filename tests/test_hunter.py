import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anti_php2shell.hunter import analyze_log_file, scan_log_directory

SAMPLE_ACCESS_LOG = """
192.168.1.10 - - [22/Oct/2026:06:10:00 +0000] "GET /index.php HTTP/1.1" 200 4500
10.0.0.55 - - [22/Oct/2026:06:12:30 +0000] "POST /upload.php?PHP_SESSION_UPLOAD_PROGRESS=payload HTTP/1.1" 500 230
10.0.0.55 - - [22/Oct/2026:06:12:31 +0000] "POST /api.php HTTP/1.1" 500 120
"""

SAMPLE_ERROR_LOG = """
[22-Oct-2026 06:12:31] WARNING: [pool www] child 4120 exited on signal 11 (SIGSEGV) after 10.23 seconds from start
[22-Oct-2026 06:13:00] ERROR: [pool www] child 4125 exited with code 139
"""

class TestHunter(unittest.TestCase):
    def test_log_forensics(self):
        with TemporaryDirectory() as tmp_dir:
            access_log = Path(tmp_dir) / "access.log"
            access_log.write_text(SAMPLE_ACCESS_LOG.strip(), encoding="utf-8")

            error_log = Path(tmp_dir) / "error.log"
            error_log.write_text(SAMPLE_ERROR_LOG.strip(), encoding="utf-8")

            rep_access = analyze_log_file(access_log)
            self.assertEqual(rep_access.incidents_found, 1)
            self.assertIn("10.0.0.55", rep_access.attacker_ips)
            self.assertEqual(rep_access.categories.get("EXPLOIT_PROBE_UPLOAD_PROGRESS"), 1)

            rep_error = analyze_log_file(error_log)
            self.assertEqual(rep_error.incidents_found, 2)
            self.assertEqual(rep_error.categories.get("WORKER_CRASH_SIGSEGV"), 2)

            rep_all = scan_log_directory(Path(tmp_dir))
            self.assertEqual(rep_all.incidents_found, 3)

if __name__ == "__main__":
    unittest.main()
