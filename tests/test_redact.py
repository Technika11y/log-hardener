import unittest

from loghardener.redact import redact, redact_lines


class RedactTests(unittest.TestCase):
    def test_email(self):
        out, found = redact("user=jeff@example.com")
        self.assertIn("[REDACTED:email]", out)
        self.assertEqual(found.get("email"), 1)

    def test_ipv4(self):
        out, found = redact("from 10.0.0.5")
        self.assertIn("[REDACTED:ip]", out)
        self.assertEqual(found.get("ipv4"), 1)

    def test_ssn(self):
        out, _ = redact("ssn=123-45-6789")
        self.assertIn("[REDACTED:ssn]", out)

    def test_credit_card(self):
        out, _ = redact("card=4111 1111 1111 1111")
        self.assertIn("[REDACTED:card]", out)

    def test_jwt(self):
        out, _ = redact("tok=eyJhbGc.eyJzdWI.sig123")
        self.assertIn("[REDACTED:jwt]", out)

    def test_bearer(self):
        out, _ = redact("Authorization: Bearer abc.def-123")
        self.assertIn("[REDACTED:bearer]", out)

    def test_aws_key(self):
        out, _ = redact("key=AKIAIOSFODNN7EXAMPLE")
        self.assertIn("[REDACTED:aws_key]", out)

    def test_clean_line_unchanged(self):
        out, found = redact("healthy request id=42")
        self.assertEqual(out, "healthy request id=42")
        self.assertEqual(found, {})

    def test_multiple_types_counted(self):
        _, total = redact_lines(["a@b.com from 1.2.3.4", "ssn 123-45-6789"])
        self.assertEqual(total.get("email"), 1)
        self.assertEqual(total.get("ipv4"), 1)
        self.assertEqual(total.get("ssn"), 1)


if __name__ == "__main__":
    unittest.main()
