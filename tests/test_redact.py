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

    def test_private_key_header(self):
        out, found = redact("-----BEGIN RSA PRIVATE KEY-----")
        self.assertIn("[REDACTED:private_key]", out)
        self.assertEqual(found.get("private_key"), 1)

    def test_github_token(self):
        out, _ = redact("cloned with ghp_" + "a" * 40)
        self.assertIn("[REDACTED:github_token]", out)

    def test_google_api_key(self):
        out, _ = redact("key=AIza" + "b" * 35)
        self.assertIn("[REDACTED:google_api_key]", out)

    def test_slack_token(self):
        out, _ = redact("slack xoxb-" + "c" * 20)
        self.assertIn("[REDACTED:slack_token]", out)

    def test_generic_secret_assignment_keeps_key_name(self):
        out, found = redact("password=hunter2")
        self.assertEqual(out, "password=[REDACTED:secret]")
        self.assertEqual(found.get("secret"), 1)

    def test_quoted_secret_value(self):
        out, _ = redact('secret: "swordfish and more"')
        self.assertIn("[REDACTED:secret]", out)

    def test_typed_token_keeps_its_label_not_generic_secret(self):
        # api_key= is a secret keyword, but the value is an AWS key — it must stay labelled aws_key.
        out, found = redact("api_key=AKIAIOSFODNN7EXAMPLE")
        self.assertIn("[REDACTED:aws_key]", out)
        self.assertNotIn("[REDACTED:secret]", out)

    def test_keyword_without_assignment_is_not_redacted(self):
        out, found = redact("auth token refreshed for the session")
        self.assertEqual(out, "auth token refreshed for the session")
        self.assertEqual(found, {})


if __name__ == "__main__":
    unittest.main()
