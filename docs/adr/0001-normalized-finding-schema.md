# ADR 0001: A single normalized finding schema

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

The Basalt platform will ship several scanners (AWS, Azure, Terraform, Kubernetes) and
several consumers (warehouse, dashboard, RAG index, remediation agent). With N scanners
and M consumers, per-provider schemas require up to N×M adapters, and every new scanner
forces a change in every consumer.

Provider-native output shapes are also structurally incompatible. An AWS Config
evaluation, a Terraform plan diff and a Kubernetes admission decision share almost no
fields, yet they describe the same class of thing: a resource that violates a rule.

## Decision

Define one provider-neutral `Finding` model in this package. Every scanner emits it;
every consumer reads it. Provider-specific detail lives in `ResourceRef.resource_type`,
`ResourceRef.tags` and `Evidence` — not in the shape of the schema.

Two derived properties carry the interoperability weight:

- **`resource.urn`** — a fixed-arity address,
  `urn:basalt:<provider>:<account>:<region>:<type>:<uid>`, with `:` percent-escaped
  inside segments so that ARNs and CloudFormation type names cannot inject extra
  separators. Reversible via `ResourceRef.parse_urn`.
- **`fingerprint`** — SHA-256 over `(rule_id, urn, location)`, deliberately excluding
  severity, timestamps and observed values.

## Consequences

**Positive.** Consumers are written once. The warehouse computes drift by grouping on
fingerprint with no scanner-side state. Retuning a rule's severity does not orphan its
history. Adding a scanner is purely additive.

**Negative.** Provider-specific richness is flattened into `Evidence`, which is less
queryable than a first-class column. A schema change is a breaking change for every
repository in the ecosystem.

**Mitigation.** `SCHEMA_VERSION` is carried on every document so consumers can branch on
it; `basalt schema` publishes the JSON Schema for non-Python consumers; and schema
changes require an ADR, which is why this constraint is recorded here.
