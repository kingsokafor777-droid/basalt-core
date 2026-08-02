# ADR 0005: Control catalogs as versioned data

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

Compliance frameworks renumber. CIS benchmark revisions move and retire recommendations
between major versions; NIST 800-53 changed substantially between Rev 4 and Rev 5. A
mapping hard-coded into scanner source rots silently — the code keeps emitting an ID that
no longer means what it did.

There is also a licensing dimension: benchmark documents are published under terms that do
not sit comfortably with redistributing their full text inside an Apache-2.0 package.

## Decision

Catalogs are JSON data loaded at runtime, not constants in code. Each framework declares
`id`, `version`, `source` and an `authoritative` flag. Control IDs are namespaced
`framework:control`, so a finding can carry mappings from several frameworks without
collision.

The bundled catalogs are **seed subsets** with `authoritative: false`. The CIS entries use
descriptive keys (`iam.root-mfa`) rather than benchmark section numbers, precisely because
section numbers are the part that changes between revisions — and a wrong number is worse
than no number.

`load_catalog(path)` accepts a replacement. `ControlCatalog.unknown()` returns IDs that do
not resolve, and `basalt validate --strict` exits non-zero on any, so a typo in scanner
rule metadata fails CI rather than reaching a compliance report.

## Consequences

**Positive.** An organisation can pin an exact benchmark revision and supply correct
numbering without forking the library. No benchmark text is redistributed. Adding a
framework is a data change.

**Negative.** The shipped catalog is not sufficient for an audit, and a user who does not
read the flag may assume that it is.

**Mitigation.** The `authoritative` flag is on every framework; the CLI prints
`[seed subset - verify against source]` beside any catalog carrying it; a test asserts the
flag is set; and the README states the limitation directly.
