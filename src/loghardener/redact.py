"""Redact PII / secrets from log text before it reaches a SIEM.

Pure functions over strings — unit-testable, no I/O. Patterns run most-specific-first so structured
tokens (JWT, SSN) are caught before broad numeric patterns. This reduces exposure; it is NOT a
guarantee of full de-identification.
"""
import re

# (name, compiled pattern, replacement) — ORDER MATTERS.
_PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED:email]"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED:jwt]"),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "[REDACTED:bearer]"),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws_key]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:ssn]"),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED:ip]"),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[REDACTED:card]"),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED:phone]"),
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
