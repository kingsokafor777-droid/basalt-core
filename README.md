# Basalt Core

[![CI](https://github.com/basalt-sec/basalt-core/actions/workflows/ci.yml/badge.svg)](https://github.com/basalt-sec/basalt-core/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/basalt-core.svg)](https://pypi.org/project/basalt-core/)
[![Python](https://img.shields.io/pypi/pyversions/basalt-core.svg)](https://pypi.org/project/basalt-core/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**One finding schema for cloud posture, IaC and Kubernetes security scanners.**

Security tooling fragments at the seams. An AWS scanner emits one JSON shape, a
Terraform analyzer emits another, a Kubernetes checker emits a third, and every
dashboard, data warehouse and ticketing integration downstream needs a bespoke adapter
for each. Basalt Core removes that adapter layer by defining the contract once:

- a **normalized finding model** that is provider-neutral and warehouse-friendly
- a **deterministic risk score** that ships with the factors that produced it
- **versioned control catalogs** as replaceable data, not hard-coded mappings
- a **scanner plugin interface** discovered through Python entry points
- **SARIF 2.1.0 and OCSF** emitters, so findings land in GitHub Code Scanning and
  OCSF-native data lakes without a translation step

This package scans nothing. It is the foundation the scanners are built on.

---

## Install

```bash
pip install basalt-core
```

Requires Python 3.10+. The only runtime dependency is Pydantic v2.

## Quick start

```python
from basalt_core import (
    Evidence,
    Exploitability,
    Exposure,
    Finding,
    Provider,
    Remediation,
    ResourceRef,
    Severity,
    get_emitter,
)

finding = Finding(
    rule_id="s3.public-read",
    title="S3 bucket allows public read access",
    description="The bucket ACL grants READ to the AllUsers group.",
    severity=Severity.CRITICAL,
    exposure=Exposure.PUBLIC,
    exploitability=Exploitability.TRIVIAL,
    resource=ResourceRef(
        provider=Provider.AWS,
        resource_type="AWS::S3::Bucket",
        uid="arn:aws:s3:::example-bucket",
        account="123456789012",
        region="ca-central-1",
    ),
    scanner="basalt-aws",
    control_ids=["cis-aws:storage.bucket-public-access", "nist-800-53-r5:AC-3"],
    evidence=[
        Evidence(
            description="Bucket ACL grant",
            observed="AllUsers:READ",
            expected="no public grants",
            source="s3:GetBucketAcl",
        )
    ],
    remediation=Remediation(summary="Enable S3 Block Public Access."),
)

print(finding.risk.value)  # 90
print(finding.risk.band)  # critical
print(finding.risk.explain())  # 90 (severity=critical) x 1.00 (exposure=public) ...
print(finding.fingerprint)  # stable 32-hex identity, unchanged across scans
print(finding.resource.urn)  # urn:basalt:aws:123456789012:ca-central-1:...
```

## Core concepts

### The finding

Every scanner in the Basalt ecosystem emits `Finding` objects and returns them wrapped
in a `ScanResult`. A finding carries what was observed, on which resource, how severe
it is, which compliance controls it maps to, and how to fix it.

Two derived properties do most of the work downstream:

**`fingerprint`** — a stable SHA-256 identity over `(rule_id, resource URN, location)`.
It deliberately excludes severity, timestamps and observed values, so retuning a rule's
severity does not orphan its history. This is what makes drift-over-time possible in
`basalt-warehouse` without any scanner-side state.

**`resource.urn`** — a normalized address of fixed arity:

```
urn:basalt:<provider>:<account>:<region>:<type>:<uid>
```

Empty segments collapse to `-`, so the URN is always parseable and safe as a join key
across scanners and clouds.

### The risk model

Risk is a pure function. No ML, no hidden state, no network call:

```
risk = base(severity) × exposure_factor × exploitability_factor
```

| Severity | Base | | Exposure | Factor | | Exploitability | Factor |
|---|---|---|---|---|---|---|---|
| critical | 90 | | public | 1.00 | | trivial | 1.00 |
| high | 70 | | external | 0.90 | | moderate | 0.85 |
| medium | 45 | | internal | 0.75 | | difficult | 0.65 |
| low | 20 | | isolated | 0.55 | | theoretical | 0.40 |
| info | 5 | | | | | | |

Multiplicative rather than additive, so a critical finding on an isolated resource with
only theoretical exploitability never outranks a trivially exploitable high on a public
one — which is the ordering an on-call engineer actually wants. Every score ships as a
`RiskScore` carrying its own factors, so a dashboard can answer "why is this a 72?"
without re-deriving it.

### Control catalogs

Controls are namespaced `framework:control` and live in JSON, not code:

```python
from basalt_core import load_catalog

catalog = load_catalog()  # built-in seed catalog
catalog.get("nist-800-53-r5:AC-6")  # -> Control(title="Least Privilege", ...)
catalog.unknown(["cis-aws:iam.root-mfa", "typo:X"])  # -> ["typo:X"]

custom = load_catalog("./my-catalog.json")  # bring your own
```

> **On catalog accuracy.** The bundled catalogs are **seed subsets**, flagged
> `authoritative: false`, and the CIS frameworks use descriptive control keys rather
> than benchmark section numbers, which are renumbered between revisions. Before using
> Basalt output for an audit or attestation, pin the official benchmark revision and
> supply your own catalog with the correct numbering. The library is built for this:
> catalogs are data, and `unknown()` gives CI a way to catch mapping typos.

### Scanners

Scanners subclass `Scanner` and register through the `basalt.scanners` entry point:

```python
from typing import Iterable
from basalt_core import Finding, Provider, Scanner, ScanContext


class S3Scanner(Scanner):
    name = "basalt-aws"
    version = "0.1.0"
    provider = Provider.AWS
    description = "AWS posture checks"

    def scan(self, context: ScanContext) -> Iterable[Finding]:
        for bucket in list_buckets(context.credentials):
            if is_public(bucket):
                yield Finding(...)
```

```toml
[project.entry-points."basalt.scanners"]
aws = "basalt_aws.scanner:S3Scanner"
```

`Scanner.run()` wraps `scan()` with timing, provenance and error capture. An exception
inside a scan is recorded in `ScanResult.metadata.errors` rather than raised, so one
failing region never discards findings already collected. A plugin that fails to import
is skipped by discovery rather than breaking the whole toolchain.

### Emitters

| Format | Purpose |
|---|---|
| `sarif` | SARIF 2.1.0 — uploads directly to GitHub Code Scanning |
| `ocsf` | OCSF 1.3.0 Compliance Finding — for Security Lake and OCSF-native SIEMs |
| `basalt` | Lossless native JSON, round-trips through `ScanResult` |
| `jsonl` | Newline-delimited, flattened, derived columns materialized — the warehouse loader |

```python
from basalt_core import get_emitter

sarif = get_emitter("sarif").emit_json(result)
```

The SARIF emitter rescales the Basalt risk score into `security-severity` so GitHub
buckets alerts consistently, and writes the fingerprint into `partialFingerprints` so
GitHub tracks alert identity across runs.

## CLI

```bash
basalt validate scan.json --strict     # validate a document; fail on unknown control ids
basalt convert scan.json --to sarif -o results.sarif
basalt convert scan.json --to jsonl --dedupe
basalt controls --framework cis-k8s    # inspect the catalog
basalt scanners                        # list installed scanner plugins
basalt schema                          # JSON Schema for a scan result
```

Feeding SARIF to GitHub Code Scanning:

```yaml
- run: basalt convert scan.json --to sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Where this sits

Basalt Core is the foundation of a set of interoperating repositories. Each is
independently useful; together they form one pipeline.

```
basalt-aws ─┐
basalt-azure├─→ ScanResult ─→ basalt-warehouse ─→ basalt-dashboard
basalt-iac  │                       │
basalt-k8s ─┘                       └──────────→ basalt-rag ─→ basalt-agent
                                                                    │
                    ┌───────────────────────────────────────────────┘
                    └─→ Terraform remediation PR
```

Everything above the line depends only on this package. Nothing in this package
depends on anything above it.

## Design decisions

Recorded as ADRs in [`docs/adr/`](docs/adr/):

| # | Decision |
|---|---|
| [0001](docs/adr/0001-normalized-finding-schema.md) | One provider-neutral finding model rather than per-provider schemas |
| [0002](docs/adr/0002-deterministic-risk-scoring.md) | Deterministic multiplicative risk scoring, no ML in the scoring path |
| [0003](docs/adr/0003-sarif-and-ocsf-as-wire-formats.md) | SARIF and OCSF as wire formats instead of a proprietary schema |
| [0004](docs/adr/0004-entry-point-plugin-discovery.md) | Entry-point plugin discovery over a monolithic scanner package |
| [0005](docs/adr/0005-control-catalogs-as-data.md) | Control catalogs as versioned data, not hard-coded mappings |
| [0006](docs/adr/0006-python-310-floor.md) | Python 3.10 as the supported floor |

## Scope

**In scope:** the finding model, risk scoring, control catalog loading, the scanner
interface, and emitters.

**Deliberately out of scope:** cloud SDK calls, credential handling, storage, scheduling,
notification, and any user interface. Those belong to the scanner and consumer
repositories. Keeping this package free of cloud dependencies is what makes it cheap to
depend on — the entire runtime dependency set is Pydantic.

**Not yet implemented:** finding suppression rules, catalog cross-framework mapping
(CIS ↔ NIST), and a JSON Schema published as a versioned artifact. Tracked in issues.

## Development

```bash
git clone https://github.com/basalt-sec/basalt-core
cd basalt-core
make install     # editable install with dev extras
make check       # lint, type-check and test
```

`make check` runs Ruff, mypy in strict mode, and the full pytest suite with coverage
gated at 85%. CI runs the same on Python 3.10, 3.11, 3.12 and 3.13.

The 3.10 floor is deliberate: Ubuntu 22.04 LTS ships Python 3.10 and is supported into
2027, and a library every scanner depends on should not force a toolchain upgrade on the
boxes where scanners actually run. The two 3.11-only conveniences this costs
(`enum.StrEnum`, `datetime.UTC`) are handled in `_compat.py`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Schema changes require an ADR — the model is a
published contract and other repositories deserialize against it.

## Security

Vulnerability reporting is described in [SECURITY.md](SECURITY.md). Please do not open
public issues for suspected vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE).
