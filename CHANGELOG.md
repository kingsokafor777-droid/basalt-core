# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The schema carries its own `SCHEMA_VERSION`, independent of the package version. A
breaking schema change requires a major package release and an ADR.

## [Unreleased]

## [0.1.1] - 2026-08-02

### Fixed

- `ResourceRef` URN escaping is now lossless. Unsafe characters were previously replaced
  with `_`, which meant `parse_urn` did not actually invert `urn` and — more seriously —
  two distinct resources (`a*b` and `a_b`) could collapse onto the same URN. Since the URN
  is a join key in `basalt-warehouse`, that was a silent data-integrity defect. Segments are
  now percent-encoded. Found by the ecosystem contract tests in `basalt-aws`.

  **Note:** URNs for resources containing characters outside `[A-Za-z0-9._@/-]` change
  with this release, and so do their fingerprints. Any history stored under 0.1.0 for such
  resources will not match. Rescan rather than migrate.

### Changed

- Lowered the supported Python floor from 3.11 to 3.10 so that Ubuntu 22.04 LTS can run
  the package without a toolchain upgrade. `enum.StrEnum` and `datetime.UTC` are replaced
  by a compat shim and `timezone.utc`; enum rendering behaviour is unchanged and now
  locked by tests.

## [0.1.0] - 2026-08-02

Initial release. Schema version `1.0.0`.

### Added

- `Finding` model with a derived `fingerprint` (SHA-256 over rule, resource URN and
  location) that is stable across scans and unaffected by severity retuning.
- `ResourceRef` with a fixed-arity, reversible URN:
  `urn:basalt:<provider>:<account>:<region>:<type>:<uid>`. Colons inside segments are
  percent-escaped so ARNs and CloudFormation type names cannot inject separators.
- Deterministic risk scoring: `base(severity) x exposure x exploitability`, clamped to
  0-100, returning a `RiskScore` that carries its own factors and an `explain()`.
- `ControlCatalog` loaded from JSON, with seed subsets for NIST SP 800-53 Rev 5, CIS AWS,
  CIS Azure and CIS Kubernetes. All are flagged `authoritative: false`.
- `Scanner` ABC and `ScanContext`, with discovery through the `basalt.scanners` entry
  point group. Scan exceptions are captured in metadata rather than raised.
- Emitters: SARIF 2.1.0, OCSF 1.3.0 Compliance Finding, lossless native JSON, and
  flattened NDJSON for warehouse loading.
- `basalt` CLI: `validate`, `convert`, `controls`, `scanners`, `schema`.
- ADRs 0001-0005 recording the schema, scoring, wire format, plugin and catalog decisions.

[Unreleased]: https://github.com/basalt-sec/basalt-core/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/basalt-sec/basalt-core/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basalt-sec/basalt-core/releases/tag/v0.1.0
