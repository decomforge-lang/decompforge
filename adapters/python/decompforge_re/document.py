"""Lectura, escritura determinista y fusión de documentos `re-1.0`."""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

from .errors import DocumentError, SchemaError
from .schema import SCHEMA_VERSION, address_number, canonical_address, validate

#: Nombre que el núcleo Rust usa cuando una función todavía no tiene nombre.
FALLBACK_NAME = re.compile(r"^sub_[0-9a-f]{8,16}$")


def _copy(doc: Any) -> Any:
    return copy.deepcopy(doc)


def _address_key(value: Any) -> int:
    try:
        return address_number(canonical_address(value))
    except SchemaError:
        # Dejamos que el validador produzca el mensaje definitivo.
        return 0


def _clean_list(items: Iterable[Any], key: Any) -> list[Any]:
    result = list(items)
    result.sort(key=key)
    return result


def canonicalize(doc: Any) -> Any:
    """Devuelve una copia con direcciones y listas ordenadas de forma estable.

    El orden de las listas no lo impone el esquema, así que el cliente lo fija
    para que dos ejecuciones con la misma información produzcan exactamente el
    mismo texto. Los diccionarios se ordenan al serializar (``sort_keys``).
    """
    out = _copy(doc)
    if not isinstance(out, dict):
        return out

    project = out.get("project")
    if isinstance(project, dict) and isinstance(project.get("entry"), str):
        project["entry"] = canonical_address(project["entry"])

    functions = out.get("functions")
    if isinstance(functions, list):
        for function in functions:
            if not isinstance(function, dict):
                continue
            if "address" in function:
                function["address"] = canonical_address(function["address"])
            for field in ("comments", "instructions"):
                values = function.get(field)
                if not isinstance(values, list):
                    continue
                for item in values:
                    if isinstance(item, dict) and "address" in item:
                        item["address"] = canonical_address(item["address"])
                values.sort(
                    key=lambda item: (
                        _address_key(item.get("address", "0x0"))
                        if isinstance(item, dict)
                        else 0,
                        str(item.get("text", "")) if isinstance(item, dict) else "",
                    )
                )
                if not values:
                    function.pop(field, None)
        functions.sort(key=lambda item: _address_key(item.get("address", "0x0")))

    xrefs = out.get("xrefs")
    if isinstance(xrefs, list):
        for xref in xrefs:
            if isinstance(xref, dict):
                if "src" in xref:
                    xref["src"] = canonical_address(xref["src"])
                if "dst" in xref:
                    xref["dst"] = canonical_address(xref["dst"])
        xrefs.sort(
            key=lambda item: (
                _address_key(item.get("src", "0x0")),
                _address_key(item.get("dst", "0x0")),
                str(item.get("kind", "")),
            )
        )

    types = out.get("types")
    if isinstance(types, list):
        types.sort(key=lambda item: str(item.get("name", "")) if isinstance(item, dict) else "")

    return out


def validate_document(doc: Any, schema: str | os.PathLike[str] | None = None) -> None:
    """Valida un documento contra el esquema y comprueba su versión."""
    validate(doc, schema)
    if not isinstance(doc, dict):  # pragma: no cover - el esquema ya lo impide
        raise SchemaError("el documento debe ser un objeto JSON")
    if doc.get("schema_version") != SCHEMA_VERSION:  # pragma: no cover - idem
        raise SchemaError(f"se esperaba schema_version={SCHEMA_VERSION!r}")


def loads(text: str, *, check: bool = True) -> dict[str, Any]:
    """Convierte texto JSON en documento y, opcionalmente, lo valida."""
    # Algunos editores de Windows añaden un BOM al guardar UTF-8. JSON lo
    # permite al inicio, pero `json.loads` no lo ignora por sí solo.
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DocumentError(f"JSON inválido: {exc}") from exc
    if not isinstance(doc, dict):
        raise DocumentError("el documento debe ser un objeto JSON")
    if check:
        validate_document(doc)
    return doc


def load(path: str | os.PathLike[str], *, check: bool = True) -> dict[str, Any]:
    """Lee un documento desde disco y, opcionalmente, lo valida."""
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise DocumentError(f"no se puede leer {target}: {exc}") from exc
    return loads(text, check=check)


def dumps(doc: Any, *, check: bool = True, canonical: bool = True) -> str:
    """Serializa de forma determinista, con salto de línea final."""
    prepared = canonicalize(doc) if canonical else _copy(doc)
    if check:
        validate_document(prepared)
    return json.dumps(
        prepared,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def save(doc: Any, path: str | os.PathLike[str], *, check: bool = True) -> Path:
    """Escribe un documento con UTF-8 y saltos de línea ``\\n``."""
    target = Path(path)
    text = dumps(doc, check=check)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def _require_kind(doc: Mapping[str, Any], expected: str) -> None:
    kind = doc.get("kind")
    if kind != expected:
        raise DocumentError(f"se esperaba kind={expected!r}, no {kind!r}")


def _function_index(doc: Mapping[str, Any]) -> dict[str, MutableMapping[str, Any]]:
    functions = doc.get("functions")
    if not isinstance(functions, list):
        raise DocumentError("el documento no contiene el array 'functions'")
    index: dict[str, MutableMapping[str, Any]] = {}
    for function in functions:
        if not isinstance(function, dict):  # pragma: no cover - el esquema lo impide
            continue
        index[canonical_address(function["address"])] = function
    return index


def merge_updates(
    base: Mapping[str, Any],
    updates: Mapping[str, Any],
    *,
    check: bool = True,
) -> dict[str, Any]:
    """Fusiona un documento ``updates`` sobre una exportación.

    Aplica nombres, firmas y comentarios. Un comentario con la misma dirección
    que otro reemplaza al anterior. Todo o nada: si alguna función del parche no
    existe en la exportación, no se devuelve nada y se explica el motivo.
    """
    if check:
        validate_document(base)
        validate_document(updates)
    _require_kind(base, "export")
    _require_kind(updates, "updates")

    merged = canonicalize(base)
    index = _function_index(merged)
    missing: list[str] = []
    for update in updates["functions"]:
        if not isinstance(update, dict):  # pragma: no cover - el esquema lo impide
            continue
        address = canonical_address(update["address"])
        function = index.get(address)
        if function is None:
            missing.append(address)
            continue
        if "name" in update:
            function["name"] = update["name"]
        if "signature" in update:
            function["signature"] = update["signature"]
        if "comments" in update:
            comments = function.setdefault("comments", [])
            replace: dict[str, dict[str, Any]] = {}
            for comment in update["comments"]:
                comment_address = canonical_address(comment["address"])
                replace[comment_address] = {
                    "address": comment_address,
                    "text": comment["text"],
                }
            kept = [
                item
                for item in comments
                if canonical_address(item["address"]) not in replace
            ]
            kept.extend(replace.values())
            function["comments"] = kept

    if missing:
        unique = sorted(set(missing), key=_address_key)
        raise DocumentError(
            "el parche menciona funciones que no existen en la exportación: "
            + ", ".join(unique)
        )
    return canonicalize(merged)


def make_updates(
    export: Mapping[str, Any],
    *,
    addresses: Iterable[Any] | None = None,
    include_names: bool = True,
    include_signatures: bool = True,
    include_comments: bool = True,
    include_fallback_names: bool = False,
    tool: str = "decompforge-python",
    version: str = "0.1.0",
    generated_at: str | None = None,
    check: bool = True,
) -> dict[str, Any]:
    """Construye un parche ``updates`` a partir de una exportación.

    Es útil para editar el JSON a mano, para conservar el trabajo antes de
    reanalizar o para comparar dos exportaciones. Si se indican ``addresses``
    solo se incluyen esas funciones.
    """
    if check:
        validate_document(export)
    _require_kind(export, "export")

    selected: set[str] | None = None
    if addresses is not None:
        selected = {canonical_address(address) for address in addresses}

    functions: list[dict[str, Any]] = []
    for function in export["functions"]:
        address = canonical_address(function["address"])
        if selected is not None and address not in selected:
            continue
        update: dict[str, Any] = {"address": address}
        if include_names:
            name = function["name"]
            if include_fallback_names or not FALLBACK_NAME.fullmatch(name):
                update["name"] = name
        if include_signatures and "signature" in function:
            update["signature"] = function["signature"]
        if include_comments and function.get("comments"):
            update["comments"] = [
                {
                    "address": canonical_address(comment["address"]),
                    "text": comment["text"],
                }
                for comment in function["comments"]
            ]
        if len(update) > 1:
            functions.append(update)

    source: dict[str, Any] = {"tool": tool, "version": version}
    if generated_at is not None:
        source["generated_at"] = generated_at
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "updates",
        "source": source,
        "functions": functions,
    }
    if check:
        validate_document(document)
    return canonicalize(document)


__all__ = [
    "canonicalize",
    "dumps",
    "load",
    "loads",
    "make_updates",
    "merge_updates",
    "save",
    "validate_document",
]
