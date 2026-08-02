"""``basalt`` command line interface.

Deliberately small. This package scans nothing; the CLI exists to validate documents,
convert between formats, inspect the control catalog and list installed scanners. The
scanner repositories add their own subcommands through the plugin registry.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .controls import load_catalog
from .emitters import available_formats, get_emitter
from .models import ScanResult
from .plugin import discover_scanners


def _load_result(path: str) -> ScanResult:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return ScanResult.model_validate(json.loads(text))


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        result = _load_result(args.path)
    except Exception as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1

    catalog = load_catalog(args.catalog)
    unknown = sorted({c for f in result.findings for c in catalog.unknown(f.control_ids)})

    print(f"valid: {len(result.findings)} findings, schema {result.schema_version}")
    counts = result.severity_counts()
    print("  " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"  max risk: {result.max_risk()}")
    if unknown:
        print(f"  unknown control ids ({len(unknown)}): {', '.join(unknown)}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    result = _load_result(args.path)
    if args.dedupe:
        result = result.deduplicate()
    emitter = get_emitter(args.to)
    output = emitter.emit_json(result, indent=None if args.compact else 2)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"wrote {args.output} ({emitter.format})", file=sys.stderr)
    else:
        print(output)
    return 0


def _cmd_controls(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    if args.json:
        print(json.dumps(catalog.model_dump(mode="json"), indent=2))
        return 0
    for fw in catalog.frameworks:
        if args.framework and fw.id != args.framework:
            continue
        flag = "" if fw.authoritative else "  [seed subset - verify against source]"
        print(f"\n{fw.id}  {fw.name} {fw.version}{flag}")
        for control in fw.controls:
            family = f"  ({control.family})" if control.family else ""
            print(f"  {control.id:<34} {control.title}{family}")
    print(f"\n{len(catalog)} controls across {len(catalog.frameworks)} frameworks")
    return 0


def _cmd_scanners(_: argparse.Namespace) -> int:
    scanners = discover_scanners()
    if not scanners:
        print("no scanners installed (try: pip install basalt-aws)")
        return 0
    for name, cls in sorted(scanners.items()):
        print(f"{name:<14} {cls.provider.value:<11} v{cls.version}  {cls.description}")
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    print(json.dumps(ScanResult.model_json_schema(), indent=2 if not args.compact else None))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basalt",
        description="Basalt Core - normalized security finding toolkit.",
    )
    parser.add_argument("--version", action="version", version=f"basalt-core {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="Validate a Basalt scan result document")
    p_validate.add_argument("path", help="Path to a scan result JSON file, or '-' for stdin")
    p_validate.add_argument("--catalog", help="Custom control catalog JSON")
    p_validate.add_argument(
        "--strict", action="store_true", help="Exit non-zero if any control id is unknown"
    )
    p_validate.set_defaults(func=_cmd_validate)

    p_convert = sub.add_parser("convert", help="Convert a scan result to another format")
    p_convert.add_argument("path", help="Path to a scan result JSON file, or '-' for stdin")
    p_convert.add_argument("--to", required=True, choices=available_formats(), help="Target format")
    p_convert.add_argument("-o", "--output", help="Write to a file instead of stdout")
    p_convert.add_argument("--dedupe", action="store_true", help="Collapse duplicate fingerprints")
    p_convert.add_argument("--compact", action="store_true", help="Minify JSON output")
    p_convert.set_defaults(func=_cmd_convert)

    p_controls = sub.add_parser("controls", help="Inspect the control catalog")
    p_controls.add_argument("--framework", help="Limit to one framework id")
    p_controls.add_argument("--catalog", help="Custom control catalog JSON")
    p_controls.add_argument("--json", action="store_true", help="Emit the catalog as JSON")
    p_controls.set_defaults(func=_cmd_controls)

    p_scanners = sub.add_parser("scanners", help="List installed scanner plugins")
    p_scanners.set_defaults(func=_cmd_scanners)

    p_schema = sub.add_parser("schema", help="Print the JSON Schema for a scan result")
    p_schema.add_argument("--compact", action="store_true")
    p_schema.set_defaults(func=_cmd_schema)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
