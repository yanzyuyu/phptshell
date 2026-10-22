import unittest
from anti_php2shell.validator import validate_php_ini_content

class TestValidator(unittest.TestCase):
    def test_valid_ini(self):
        valid_content = "[Session]\nsession.upload_progress.enabled = 0\nmemory_limit = 128M\n"
        ok, msg = validate_php_ini_content(valid_content)
        self.assertTrue(ok)
        self.assertEqual(msg, "Syntax valid")

    def test_invalid_ini_syntax(self):
        corrupted_content = "[Session\nthis is invalid syntax without key value or section close\n"
        ok, msg = validate_php_ini_content(corrupted_content)
        self.assertFalse(ok)
        self.assertIn("error", msg.lower())

if __name__ == "__main__":
    unittest.main()
