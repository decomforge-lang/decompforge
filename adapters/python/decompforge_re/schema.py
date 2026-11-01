"""Carga y validación del esquema `re-1.0`.

Se usa `jsonschema` (dependencia externa) porque el esquema es la fuente de
verdad compartida con el núcleo Rust y los tests. El esquema se busca, por
orden, en:

1. la variable de entorno ``DECOMPFORGE_RE_SCHEMA``;
2. la copia empaquetada junto a este módulo;
3. ``schemas/decompforge-re-1.0.schema.json`` en la raíz del repositorio.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .errors import SchemaError

SCHEMA_VERSION = "re-1.0"

#: Nombres admitidos en `xref.kind` y en el `kind` de un tipo. Se mantienen
#: aquí para que el cliente pueda normalizar sin consultar el esquema.
XREF_KINDS = frozenset(
    {"call", "jump", "cond_jump", "data", "read", "write", "read_write", "ref", "other"}
)

TYPE_KINDS = frozenset(
    {"struct", "union", "enum", "typedef", "function", "pointer", "array", "other"}
)


def schema_path() -> Path:
    """Devuelve la ruta del esquema `re-1.0` que se va a usar."""
    override = os.environ.get("DECOMPFORGE_RE_SCHEMA")
    if override:
        return Path(override)
    packaged = Path(__file__).resolve().parent / "schemas" / "decompforge-re-1.0.schema.json"
    if packaged.is_file():
        return packaged
    repo = Path(__file__).resolve().parents[3] / "schemas" / "decompforge-re-1.0.schema.json"
    return repo


def load_schema(path: str | os.PathLike[str] | None = None) -> Mapping[str, Any]:
    """Lee el esquema JSON y comprueba que sea un esquema válido."""
    target = Path(path) if path is not None else schema_path()
    try:
        schema = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SchemaError(f"no se puede leer el esquema {target}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SchemaError(f"el esquema {target} no es JSON válido: {exc}") from exc
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:  # jsonschema usa SchemaError propia
        raise SchemaError(f"el esquema {target} no es válido: {exc}") from exc
    return schema


def validate(doc: Any, path: str | os.PathLike[str] | None = None) -> None:
    """Valida ``doc`` contra el esquema; lanza :class:`SchemaError` con detalle."""
    schema = load_schema(path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if not errors:
        return
    lines = []
    for error in errors[:20]:
        where = "/".join(str(part) for part in error.path) or "<raíz>"
        lines.append(f"{where}: {error.message}")
    if len(errors) > 20:
        lines.append(f"... y {len(errors) - 20} errores más")
    raise SchemaError("documento inválido:\n" + "\n".join(lines))


def canonical_address(value: Any) -> str:
    """Convierte una dirección a la forma canónica del esquema.

    Acepta enteros y cadenas con o sin ``0x``. Las direcciones de 32 bits se
    escriben con 8 dígitos y las de 64 bits con 16, que es lo que produce el
    núcleo Rust y lo que exige el patrón del esquema.
    """
    if isinstance(value, bool):
        raise SchemaError(f"dirección inválida: {value!r}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            number = int(text, 16)
        except ValueError as exc:
            raise SchemaError(f"dirección inválida: {value!r}") from exc
    else:
        raise SchemaError(f"dirección inválida: {value!r}")
    if number < 0 or number > 0xFFFF_FFFF_FFFF_FFFF:
        raise SchemaError(f"dirección fuera de rango: {value!r}")
    width = 8 if number <= 0xFFFF_FFFF else 16
    return f"0x{number:0{width}x}"


def address_number(value: str) -> int:
    """Devuelve el entero de una dirección canónica."""
    return int(value[2:], 16)


__all__ = [
    "SCHEMA_VERSION",
    "TYPE_KINDS",
    "XREF_KINDS",
    "address_number",
    "canonical_address",
    "load_schema",
    "schema_path",
    "validate",
]
