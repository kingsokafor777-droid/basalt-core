# ADR 0002: Deterministic risk scoring, with no model in the scoring path

- **Status:** Accepted
- **Date:** 2026-08-02

## Context

Severity alone is a poor prioritisation signal. A critical misconfiguration on an
isolated resource is usually less urgent than a high one on an internet-facing resource,
and a severity-only ranking cannot express that.

The obvious alternative is a learned risk model. It was considered and rejected.

## Decision

Risk is a pure function of three declared inputs:

```
risk = base(severity) × exposure_factor × exploitability_factor
```

clamped to `[0, 100]`. Multiplicative rather than additive, so that reachability can
suppress an unreachable critical below a trivially exploitable high.

The function returns a `RiskScore` carrying the factors that produced it plus an
`explain()` rendering, so consumers never recompute a score in order to display its
rationale.

No machine-learned model participates in scoring. If a model is later used to *infer*
inputs — estimating exposure from network topology, say — it sets `Finding.exposure`
before scoring, and the scoring step itself stays deterministic.

## Consequences

**Positive.** The same finding always scores the same, which makes tests meaningful and
makes drift in the warehouse attributable to the environment rather than the scorer. An
auditor can reproduce any score by hand. Scoring needs no network call and no inference
budget.

**Negative.** The weights are judgement, not evidence, and will be wrong for some
organisations.

**Mitigation.** The factor tables are module-level constants in `severity.py` with a
single point of change, and every score ships with its inputs, so a downstream consumer
can rescore under its own weights without losing information.
