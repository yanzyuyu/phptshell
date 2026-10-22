import unittest
from anti_php2shell.ui import badge, badge_outline, c, is_color_enabled

class TestUi(unittest.TestCase):
    def test_badge_and_color(self):
        txt = badge("CRITICAL", "red")
        self.assertIn("CRITICAL", txt)

        outline = badge_outline("EXPORTED", "cyan")
        self.assertIn("EXPORTED", outline)

        colored = c("hello", "\033[1;31m")
        self.assertIn("hello", colored)

if __name__ == "__main__":
    unittest.main()
