"""Randomized property tests — invariants, not examples.

Example tests prove the cases we thought of. These generate hundreds of secrets and assert
the properties that must hold for ALL of them. Seeded, so a failure is reproducible.
"""
import random
import string
import unittest

from loghardener.redact import redact

SEED = 1337
ALNUM = string.ascii_letters + string.digits
UPPER_NUM = string.ascii_uppercase + string.digits


def _s(alphabet, n, rng):
    return "".join(rng.choice(alphabet) for _ in range(n))


def _secrets(rng):
    """One freshly generated secret of each class we claim to redact."""
    word = _s(string.ascii_lowercase, 6, rng)
    return {
        "email": f"{word}@{_s(string.ascii_lowercase, 5, rng)}.com",
        "aws_key": "AKIA" + _s(UPPER_NUM, 16, rng),
        "github_token": "ghp_" + _s(ALNUM, 40, rng),
        "google_api_key": "AIza" + _s(ALNUM, 35, rng),
        "slack_token": "xoxb-" + _s(ALNUM, 15, rng),
        "jwt": f"eyJ{_s(ALNUM, 8, rng)}.{_s(ALNUM, 8, rng)}.{_s(ALNUM, 8, rng)}",
        "ssn": f"{rng.randint(100,999)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}",
        "ipv4": ".".join(str(rng.randint(1, 254)) for _ in range(4)),
    }


def _benign(rng):
    """A log line with nothing sensitive: no @, no dotted quads, no long digit runs,
    no secret keywords — so a match here is a false positive."""
    return (f"level=info svc={_s(string.ascii_lowercase, 5, rng)} "
            f"msg={_s(string.ascii_lowercase, 8, rng)} id={rng.randint(1,99)} "
            f"status={rng.randint(200,599)} dur={rng.randint(1,99)}ms")


class PropertyTests(unittest.TestCase):
    def test_no_generated_secret_ever_survives_verbatim(self):
        rng = random.Random(SEED)
        for _ in range(150):
            for kind, secret in _secrets(rng).items():
                line = f"{_s(string.ascii_lowercase, 4, rng)} {secret} trailing"
                out, found = redact(line)
                self.assertNotIn(secret, out, f"{kind} survived redaction: {line!r}")
                self.assertTrue(found, f"{kind} produced no finding: {line!r}")

    def test_key_value_secret_values_never_survive(self):
        rng = random.Random(SEED + 1)
        for _ in range(150):
            for key in ("password", "api_key", "secret", "auth_token"):
                value = _s(ALNUM, rng.randint(6, 20), rng)
                out, _ = redact(f"{key}={value} rest=ok")
                self.assertNotIn(value, out)
                self.assertIn(key, out, "the key name should survive for debuggability")

    def test_redaction_is_idempotent(self):
        rng = random.Random(SEED + 2)
        for _ in range(150):
            line = " ".join(list(_secrets(rng).values()))
            once, _ = redact(line)
            twice, _ = redact(once)
            self.assertEqual(once, twice, "redacting twice must not change the result")

    def test_benign_lines_are_never_touched(self):
        rng = random.Random(SEED + 3)
        for _ in range(400):
            line = _benign(rng)
            out, found = redact(line)
            self.assertEqual(out, line, f"false positive on: {line!r}")
            self.assertEqual(found, {}, f"false finding on: {line!r}")

    def test_any_change_is_always_accounted_for(self):
        rng = random.Random(SEED + 4)
        for _ in range(150):
            secret = rng.choice(list(_secrets(rng).values()))
            line = f"begin {secret} end"
            out, found = redact(line)
            if out != line:
                self.assertTrue(found, "text changed but nothing was counted")


if __name__ == "__main__":
    unittest.main()
