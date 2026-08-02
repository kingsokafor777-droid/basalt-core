# ADR 0003: SARIF and OCSF as wire formats

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

A normalized internal schema solves interoperability *within* Basalt. It does nothing for
interoperability with tools an organisation already runs: GitHub Code Scanning, a SIEM, a
data lake.

Publishing only a proprietary format would force every external integration to be custom
— the exact failure mode ADR 0001 set out to avoid, displaced one layer outward.

## Decision

Ship SARIF 2.1.0 and OCSF (Compliance Finding, `class_uid` 2003) as first-class emitters
alongside the native format.

- **SARIF** is what GitHub Code Scanning ingests, so Basalt findings annotate pull
  requests with no glue code. The risk score is rescaled into `security-severity` so
  GitHub's bucketing agrees with ours, and `fingerprint` is written to
  `partialFingerprints` so GitHub tracks alert identity across runs.
- **OCSF** is consumed natively by AWS Security Lake and a growing set of SIEMs, so
  findings reach an enterprise lake without a bespoke parser.

Basalt-specific fields go under `properties` (SARIF) and `unmapped.basalt` (OCSF) rather
than as invented top-level keys, so both documents stay schema-valid.

## Consequences

**Positive.** Two of the highest-value integrations in the domain require no integration
work. Emitting a standard also disciplines the internal model: a field that cannot be
expressed in either standard is usually a field that should not exist.

**Negative.** Both standards version independently of Basalt and will drift. The mappings
are lossy in both directions — SARIF has no concept of a cloud account, OCSF has no
concept of a source line.

**Mitigation.** Emitters are pure functions with no I/O, individually tested against the
structural guarantees of each standard, so a version bump stays contained. Lossless
round-tripping is the native format's job, not theirs.
