"""Redact PII / secrets from log text before it reaches a SIEM.

Pure functions over strings — unit-testable, no I/O. Patterns run most-specific-first so structured
tokens (JWT, SSN) are caught before broad numeric patterns. This reduces exposure; it is NOT a
guarantee of full de-identification.
"""
import re

def _redact_secret(m):
    # Keep the key name and separator for debuggability; redact only the value.
    return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"


# key=value / key: value secret assignments (password=..., api_key: ...). The value's negative
# lookahead means an already-redacted value keeps its specific label instead of being re-wrapped.
_SECRET_KV = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)"
    r"(\s*[=:]\s*)"
    r"(?:\"[^\"]+\"|'[^']+'|(?!\[REDACTED:)[^\s,;]+)"
)

# (name, compiled pattern, replacement) — ORDER MATTERS. Most-specific first; the generic
# key=value sweep runs last so typed tokens (jwt, aws_key, …) keep their own labels.
_PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED:email]"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED:jwt]"),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "[REDACTED:bearer]"),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), "[REDACTED:private_key]"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED:github_token]"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED:google_api_key]"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack_token]"),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws_key]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:ssn]"),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED:ip]"),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED:card]"),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED:phone]"),
    ("secret", _SECRET_KV, _redact_secret),
]


def redact(text):
    """Return (redacted_text, {type: count})."""
    found = {}
    out = text
    for name, rx, repl in _PATTERNS:
        out, n = rx.subn(repl, out)
        if n:
            found[name] = found.get(name, 0) + n
    return out, found


def redact_lines(lines):
    """Return (redacted_lines, {type: total_count})."""
    redacted, total = [], {}
    for line in lines:
        r, found = redact(line)
        redacted.append(r)
        for k, v in found.items():
            total[k] = total.get(k, 0) + v
    return redacted, total
