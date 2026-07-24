# Log-Aggregator Hardener

> Strips PII and secrets from log streams **before they hit your SIEM** — emails, IPs, SSNs, card
> numbers, JWTs, bearer/AWS/GitHub/Google/Slack tokens, private keys, and `key=value` secrets.
> Privacy compliance at the ingestion layer.
>
> Part of the **Technika11y** suite · *Root access for everyone.*

[![ci](https://github.com/technika11y/log-hardener/actions/workflows/ci.yml/badge.svg)](https://github.com/technika11y/log-hardener/actions/workflows/ci.yml)
![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-informational)

---

## Quick start

```bash
git clone https://github.com/technika11y/log-hardener && cd log-hardener
PYTHONPATH=src python3 -m loghardener.cli examples/sample.log
```

## Status — read this first

**Pre-alpha (`v0.1.0a0`). Honest state of the code:**

| Capability | State |
|---|---|
| Redact: email, IPv4, US SSN, card numbers, JWT, bearer tokens, AWS keys | ✅ works, tested |
| Redact secrets: private-key PEM headers, GitHub / Google / Slack tokens | ✅ works, tested |
| Redact generic `key=value` secrets (`password=`, `api_key:` …), keeping the key name | ✅ works, tested |
| Typed tokens keep their own label even inside a `key=value` (no double-wrapping) | ✅ works, tested |
| Per-type match counts + multi-type lines | ✅ works, tested |
| `--check` gate: exit 1 if any PII is present (no output) | ✅ works |
| Streaming stdin / file input | ✅ works |
| IPv6, international phone/ID formats, Luhn validation, config-driven patterns | ⚠️ not built — [roadmap](#roadmap) |

**This is a mitigation, not a guarantee.** The pattern set is deliberately conservative and will
miss formats it doesn't know. Validate coverage against your own data before relying on it for
regulated logs — see [`SECURITY.md`](SECURITY.md).

## Why it exists

The cheapest place to stop a privacy incident is *before* the data lands in a searchable index.
This runs at the ingestion layer: pipe logs through it, or drop the `--check` mode into CI to fail
a build that would ship PII into telemetry.

## Usage

```bash
# redact a file to stdout
PYTHONPATH=src python -m loghardener.cli examples/sample.log

# or stream
cat app.log | PYTHONPATH=src python -m loghardener.cli

# gate: exit 1 if the file contains PII
PYTHONPATH=src python -m loghardener.cli --check examples/sample.log
```

## Roadmap

- [ ] IPv6, international phone/ID formats
- [ ] Luhn check to cut card false positives
- [ ] Config-driven custom patterns + allowlists
- [ ] Structured-log (JSON) field-aware mode
- [ ] SARIF output + the shared Technika11y CI gate

## License

[Apache-2.0](LICENSE). See [`SECURITY.md`](SECURITY.md).

---

**Part of the [Technika11y](https://github.com/technika11y) suite** · [technika11y.github.io](https://technika11y.github.io/) · security, compliance, and accessibility as one discipline.
