"""log-hardener [file] — redact PII/secrets from a log stream (or stdin).

  (default)  write redacted output to stdout, a summary to stderr
  --check    emit nothing; exit 1 if any PII is found (use as a pre-ingestion gate)
"""
import argparse
import sys

from .redact import redact_lines


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="log-hardener")
    parser.add_argument("file", nargs="?", help="log file (default: stdin)")
    parser.add_argument("--check", action="store_true", help="don't emit output; exit 1 if PII found")
    args = parser.parse_args(argv)

    src = open(args.file) if args.file else sys.stdin
    try:
        lines = [ln.rstrip("\n") for ln in src]
    finally:
        if args.file:
            src.close()

    redacted, total = redact_lines(lines)
    if not args.check:
        sys.stdout.write("\n".join(redacted) + ("\n" if redacted else ""))

    summary = ", ".join(f"{k}={v}" for k, v in sorted(total.items())) or "none"
    print(f"pii found: {summary}", file=sys.stderr)

    if args.check:
        return 1 if total else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
