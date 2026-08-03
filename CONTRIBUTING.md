# Contributing

Thanks for considering a contribution. This package is the schema every other Basalt
repository deserializes against, so the bar for changes is deliberately uneven: bug fixes
and new emitters are easy, schema changes are not.

## Setup

```bash
git clone https://github.com/basalt-sec/basalt-core
cd basalt-core
make install
make check
```

`make check` runs exactly what CI runs: Ruff lint, Ruff format check, mypy in strict mode,
and pytest with coverage gated at 85%. If it passes locally it passes in CI.

## What changes need

**Bug fix or new test** — a pull request with a test that fails before your change.

**New emitter** — subclass `Emitter`, decorate with `@register_emitter`, and add it to
`emitters/__init__.py`. Emitters must be pure: no I/O, no network, no clock reads. Tests
should assert against the structural guarantees of the target format, not a golden file.

**New control framework** — a data change to `src/basalt_core/data/controls.json`. Set
`authoritative: false` unless you are shipping the complete, verified catalog for a pinned
revision, and always include a `source` URL.

**Schema change** — open an issue first, and expect to write an ADR. Adding an optional
field with a default is a minor change. Renaming, removing or retyping a field, or
changing how `fingerprint` or `urn` are derived, is breaking: it invalidates stored history
in every downstream warehouse. That is not a reason never to do it, but it is a reason to
do it deliberately and in a major release.

## House rules

- **Determinism.** Nothing in the scoring path may consult a clock, a network, a random
  source or a model. ADR 0002 explains why.
- **Typing.** mypy strict is not negotiable. `Any` needs a comment justifying it.
- **Comments explain why.** The code already says what it does. Comments should carry the
  reasoning that is not recoverable from reading it.
- **Tests assert behaviour, not implementation.** A test that breaks on a refactor without
  a behaviour change is a bad test.
- **No new runtime dependencies** without an issue first. The single-dependency footprint
  is a feature; it is what makes this package cheap for every scanner to depend on.

## Commits and pull requests

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). Keep pull
requests focused on one thing. If you found two problems, that is two pull requests.

Update `CHANGELOG.md` under `[Unreleased]` for anything user-visible.

## Releasing

Maintainers only. Bump the version in `pyproject.toml`, move the `[Unreleased]` entries
under the new version in `CHANGELOG.md`, tag `vX.Y.Z`, and publish a GitHub release. The
release workflow publishes to PyPI through OIDC trusted publishing — no API token is stored
in this repository.
