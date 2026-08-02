# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Pre-1.0, only the latest minor version receives security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/kingsokafor777-droid/basalt-core/security/advisories/new)
rather than a public issue.

Include the affected version, reproduction steps, and what an attacker gains. You should
get an acknowledgement within 72 hours and an assessment within 7 days. Please give us 90
days before public disclosure, or less if a fix ships sooner — we will credit you in the
advisory unless you prefer otherwise.

## Threat model

This package parses untrusted input. A scan result document may originate from a scanner
you do not control, and a control catalog may be supplied by path. The relevant surface is:

- **Deserialization.** `ScanResult.model_validate` and `load_catalog` accept arbitrary
  JSON. Pydantic validates structurally; there is no code execution path through either.
- **Plugin loading.** `discover_scanners()` imports any distribution registering under the
  `basalt.scanners` entry point group. **Installing a Basalt scanner is equivalent to
  trusting its code**, exactly as with any Python package. Discovery does not sandbox.
- **Emitters.** Output is data, not templates. No emitter interpolates input into a shell
  command, SQL statement or HTML document.

Not in scope: the security of cloud credentials handled by scanner packages (report those
to the scanner's repository), and the correctness of compliance mappings, which are seed
data explicitly flagged non-authoritative — see ADR 0005.

## What findings contain

Findings can carry account identifiers, resource ARNs, resource tags and source snippets.
Treat scan output as sensitive: it is a map of where your weaknesses are. Do not commit it
to a public repository. The `.gitignore` in this project excludes `scan.json` and `*.sarif`
by default for that reason.
