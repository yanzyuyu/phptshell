import unittest
from anti_php2shell.checker import audit_url, detect_waf

class TestChecker(unittest.TestCase):
    def test_waf_detection(self):
        cf_headers = {"cf-ray": "8d3912903120-SIN", "server": "cloudflare"}
        self.assertEqual(detect_waf(cf_headers), "Cloudflare")

        aws_headers = {"x-amzn-requestid": "c19283-abc", "server": "AmazonS3"}
        self.assertEqual(detect_waf(aws_headers), "AWS WAF / CloudFront")

        plain_headers = {"server": "nginx/1.18.0", "content-type": "text/html"}
        self.assertIsNone(detect_waf(plain_headers))

    def test_unreachable_endpoint(self):
        report = audit_url("http://127.0.0.1:59999/nonexistent", timeout=0.5)
        self.assertEqual(report.risk_level, "UNREACHABLE")
        self.assertIsNone(report.status_code)

if __name__ == "__main__":
    unittest.main()
