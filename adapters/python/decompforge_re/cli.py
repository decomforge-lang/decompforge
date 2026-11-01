"""CLI del cliente Python (`python -m decompforge_re ...`)."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from .document import dumps, load, make_updates, merge_updates, save, validate_document
from .errors import DecompForgeError
from .schema import SCHEMA_VERSION, canonical_address


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decompforge-re",
        description=(
            "Valida, normaliza y fusiona documentos re-1.0 de DecompForge. "
            "La CLI de Rust los exporta con `decompforge export --format re-json` "
            "y los importa con `decompforge apply`."
        ),
    )
    parser.add_argument("--version", action="version", version=f"decompforge-re {SCHEMA_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="valida un documento contra el esquema")
    validate.add_argument("document")
    validate.add_argument("--schema", help="ruta alternativa del esquema JSON")

    merge = sub.add_parser("merge", help="aplica un parche de actualizaciones a una exportación")
    merge.add_argument("base")
    merge.add_argument("updates")
    merge.add_argument("-o", "--output", help="fichero de salida (por defecto, stdout)")
    merge.add_argument("--schema", help="ruta alternativa del esquema JSON")

    make = sub.add_parser("make-updates", help="genera un parche desde una exportación")
    make.add_argument("export")
    make.add_argument("-o", "--output", help="fichero de salida (por defecto, stdout)")
    make.add_argument(
        "--address",
        action="append",
        default=None,
        help="incluye solo esta dirección (repetible)",
    )
    make.add_argument("--no-names", action="store_true", help="omite los nombres")
    make.add_argument("--no-signatures", action="store_true", help="omite las firmas")
    make.add_argument("--no-comments", action="store_true", help="omite los comentarios")
    make.add_argument(
        "--include-fallback-names",
        action="store_true",
        help="incluye nombres sub_<dirección> (por defecto se omiten)",
    )
    make.add_argument("--generated-at", help="marca ISO-8601 informativa (no determinista)")
    make.add_argument("--schema", help="ruta alternativa del esquema JSON")

    return parser


def _schema_arg(args: argparse.Namespace) -> str | os.PathLike[str] | None:
    return args.schema


def _write_or_print(document: dict, output: str | None) -> None:
    if output is None:
        sys.stdout.write(dumps(document))
        return
    save(document, output)
    print(f"escrito: {output}")


def _cmd_validate(args: argparse.Namespace) -> int:
    document = load(args.document, check=False)
    validate_document(document, _schema_arg(args))
    functions = document.get("functions", [])
    print(
        f"OK: {args.document} cumple {SCHEMA_VERSION} "
        f"(kind={document.get('kind')}, {len(functions)} funciones)"
    )
    return 0


def _cmd_merge(args: argparse.Namespace) -> int:
    base = load(args.base, check=False)
    updates = load(args.updates, check=False)
    validate_document(base, _schema_arg(args))
    validate_document(updates, _schema_arg(args))
    merged = merge_updates(base, updates, check=False)
    _write_or_print(merged, args.output)
    if args.output is not None:
        print(
            f"fusionado: {len(updates['functions'])} actualizaciones sobre "
            f"{len(base['functions'])} funciones"
        )
    return 0


def _cmd_make_updates(args: argparse.Namespace) -> int:
    export = load(args.export, check=False)
    validate_document(export, _schema_arg(args))
    addresses = None
    if args.address:
        addresses = [canonical_address(item) for item in args.address]
    updates = make_updates(
        export,
        addresses=addresses,
        include_names=not args.no_names,
        include_signatures=not args.no_signatures,
        include_comments=not args.no_comments,
        include_fallback_names=args.include_fallback_names,
        generated_at=args.generated_at,
        check=False,
    )
    validate_document(updates, _schema_arg(args))
    _write_or_print(updates, args.output)
    if args.output is not None:
        print(f"parche: {len(updates['functions'])} funciones")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "merge":
            return _cmd_merge(args)
        if args.command == "make-updates":
            return _cmd_make_updates(args)
    except DecompForgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.error(f"comando desconocido: {args.command}")  # pragma: no cover
    return 2


__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
