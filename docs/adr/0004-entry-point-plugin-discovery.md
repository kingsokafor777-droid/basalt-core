# ADR 0004: Scanner discovery through Python entry points

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

Scanners need cloud SDKs: `boto3` for AWS, `azure-mgmt-*` for Azure, `kubernetes` for
clusters. Vendoring all of them into one package would mean a user who only scans
Terraform still installs the entire AWS and Azure SDK surface, and every scanner's
dependency bumps would become everyone's dependency bumps.

## Decision

Scanners live in separate distributions and register under the `basalt.scanners` entry
point group. This package defines the `Scanner` ABC and the discovery function, and
imports no scanner.

`Scanner.run()` wraps the subclass `scan()` with timing, provenance and error capture. An
exception inside a scan is recorded in `ScanResult.metadata.errors` rather than raised, so
one failing region does not discard findings already collected. Discovery skips any entry
point that fails to import, so a broken plugin cannot take down the toolchain.

`ScanContext` carries credentials, targeting and options explicitly rather than having
scanners read ambient environment, which keeps a scan reproducible from its recorded
context and keeps scanners testable without cloud access.

## Consequences

**Positive.** `basalt-core` has one runtime dependency. Users install only the scanners
they need. Scanner release cadence is decoupled from the schema's. Third parties can add
scanners without a pull request here.

**Negative.** Discovery is implicit: installing a package changes behaviour. Version skew
between a scanner and the schema it was built against becomes possible.

**Mitigation.** `basalt scanners` lists what is installed. Every finding records `scanner`,
`scanner_version` and `schema_version`, so skew is visible in the data rather than silent.
