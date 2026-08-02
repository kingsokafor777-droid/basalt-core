# ADR 0006: Python 3.10 as the supported floor

- **Status:** Accepted
- **Date:** 2026-08-02
- **Supersedes:** the implicit 3.11 floor set in 0.1.0 development

## Context

The package was initially written against Python 3.11 for two conveniences: `enum.StrEnum`
and the `datetime.UTC` alias. Both were adopted on the suggestion of a linter rule rather
than a deliberate compatibility decision.

That floor turned out to exclude a meaningful share of the environments this library is
built for. Ubuntu 22.04 LTS ships Python 3.10 and carries standard support into 2027; it is
common on CI runners and on the operations hosts where a cloud security scanner is
installed. `basalt-core` is a dependency of every scanner in the ecosystem, so its floor
propagates to all of them — a user who wants only the Terraform scanner inherits whatever
this package requires.

Neither 3.11 feature is load-bearing. `enum.StrEnum` is a rendering convenience;
`datetime.UTC` is an alias for `timezone.utc`.

## Decision

Support Python 3.10 and later.

`datetime.UTC` is replaced by `timezone.utc`. `enum.StrEnum` is replaced by a small shim in
`basalt_core._compat` that subclasses `(str, Enum)` and defines `__str__` and `__format__`
to return the member value.

The shim exists because plain `(str, Enum)` renders as `Severity.HIGH` in f-strings and
`str()` rather than `high` — a defect that does not raise, and instead corrupts log lines
and any consumer that formats a member instead of reading `.value`. Tests lock the
rendering behaviour so it cannot regress.

3.10 is also the natural floor for the rest of the design: `importlib.metadata.entry_points(group=...)`
(ADR 0004) and PEP 604 `X | None` annotations both arrive in 3.10.

Ruff rules `UP042` and `UP017` are disabled with the reason recorded in `pyproject.toml`,
since both exist to push code toward the 3.11 constructs this ADR deliberately avoids.

## Consequences

**Positive.** The package installs on Ubuntu 22.04 LTS and on any CI runner defaulting to
3.10, without a toolchain upgrade. Every downstream scanner inherits the wider floor. CI
now covers 3.10 through 3.13.

**Negative.** A compat module exists that would otherwise not. Two lint rules are
suppressed. The 3.10 grammar constrains future code — no exception groups, no `Self`, no
`tomllib`.

**Mitigation.** `_compat.py` is intentionally tiny and its docstring states the condition
for deletion. CI runs the full suite on 3.10, so an accidental 3.11-only construct fails
before merge rather than at a user's install.

## Revisit when

Ubuntu 22.04 LTS reaches end of standard support (April 2027), or when a 3.11+ feature is
needed that cannot be shimmed in comparable size. At that point, delete `_compat.py`, drop
the two ruff suppressions, and raise the floor in a major release.
