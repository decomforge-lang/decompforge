#!/usr/bin/env python3
"""Valida un JSON exportado por `decompforge export` contra el esquema 1.0.

Uso: python scripts/validate_export.py export.json [esquema.json]
Requiere: pip install jsonschema
"""
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

root = pathlib.Path(__file__).resolve().parent.parent
schema_path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else root / "schemas" / "decompforge-exchange-1.0.schema.json"
doc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
schema = json.loads(schema_path.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
if errors:
    for e in errors:
        print(f"ERROR en {'/'.join(map(str, e.path)) or '<raiz>'}: {e.message}")
    sys.exit(1)
print(f"OK: {sys.argv[1]} cumple el esquema")
