"""Cliente Python para el intercambio `re-1.0` de DecompForge.

El paquete no depende del núcleo Rust: trabaja con documentos JSON ya
exportados por `decompforge export --format re-json`. Sirve para validar,
normalizar, fusionar actualizaciones y generar parches que luego se aplican con
`decompforge apply`.

Uso rápido::

    from decompforge_re import load, merge_updates, make_updates, save

    base = load("export.json")
    updates = load("updates.json")
    merged = merge_updates(base, updates)
    save(merged, "merged.json")

También hay una CLI::

    python -m decompforge_re validate export.json
    python -m decompforge_re merge base.json updates.json -o merged.json
    python -m decompforge_re make-updates export.json -o updates.json
"""

from .document import (
    canonicalize,
    dumps,
    load,
    loads,
    make_updates,
    merge_updates,
    save,
    validate_document,
)
from .errors import DecompForgeError, DocumentError, SchemaError
from .schema import canonical_address, schema_path

__all__ = [
    "DecompForgeError",
    "DocumentError",
    "SchemaError",
    "canonical_address",
    "canonicalize",
    "dumps",
    "load",
    "loads",
    "make_updates",
    "merge_updates",
    "save",
    "schema_path",
    "validate_document",
]

__version__ = "0.1.0"
