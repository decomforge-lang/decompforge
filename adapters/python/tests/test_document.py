"""Pruebas del cliente Python `re-1.0`.

Se ejecutan sin el binario de Rust: usan los ejemplos de ``adapters/examples``
y documentos construidos en memoria. La CLI se prueba con subprocess para
comprobar códigos de salida y escritura determinista.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from decompforge_re import (
    DocumentError,
    SchemaError,
    canonical_address,
    canonicalize,
    dumps,
    load,
    make_updates,
    merge_updates,
    save,
    schema_path,
    validate_document,
)
from decompforge_re.document import loads

HERE = Path(__file__).resolve()
PYTHON_DIR = HERE.parents[1]
EXAMPLES = HERE.parents[2] / "examples"
EXPORT = EXAMPLES / "export-re-1.0.json"
UPDATES = EXAMPLES / "updates-re-1.0.json"


class SchemaTests(unittest.TestCase):
    def test_schema_path_exists(self) -> None:
        self.assertTrue(schema_path().is_file(), f"no existe {schema_path()}")

    def test_examples_are_valid(self) -> None:
        validate_document(load(EXPORT, check=False))
        validate_document(load(UPDATES, check=False))

    def test_canonical_address_width(self) -> None:
        self.assertEqual(canonical_address(0x1000), "0x00001000")
        self.assertEqual(canonical_address("0x1000"), "0x00001000")
        self.assertEqual(canonical_address("0xFFFFFFFF"), "0xffffffff")
        self.assertEqual(canonical_address(0x1_0000_0000), "0x0000000100000000")
        self.assertEqual(canonical_address("0x0000000100000000"), "0x0000000100000000")

    def test_invalid_address(self) -> None:
        with self.assertRaises(SchemaError):
            canonical_address("no-es-una-direccion")
        with self.assertRaises(SchemaError):
            canonical_address(-1)

    def test_schema_rejects_unknown_field(self) -> None:
        doc = load(EXPORT, check=False)
        doc["functions"][0]["campo_inventado"] = True
        with self.assertRaises(SchemaError):
            validate_document(doc)

    def test_schema_rejects_uppercase_address(self) -> None:
        doc = load(EXPORT, check=False)
        doc["functions"][0]["address"] = "0x0010000A"
        with self.assertRaises(SchemaError):
            validate_document(doc)

    def test_schema_rejects_wrong_kind(self) -> None:
        doc = load(EXPORT, check=False)
        doc["kind"] = "otra-cosa"
        with self.assertRaises(SchemaError):
            validate_document(doc)

    def test_invalid_json_is_document_error(self) -> None:
        with self.assertRaises(DocumentError):
            loads("{no es json")

    def test_utf8_bom_is_ignored(self) -> None:
        doc = load(EXPORT, check=False)
        text = "\ufeff" + dumps(doc, check=False)
        parsed = loads(text)
        validate_document(parsed)
        self.assertEqual(len(parsed["functions"]), len(doc["functions"]))


class CanonicalizeTests(unittest.TestCase):
    def test_canonicalize_sorts_and_normalizes(self) -> None:
        doc = load(EXPORT, check=False)
        doc["functions"].reverse()
        doc["functions"][0]["address"] = "0x100040"
        doc["xrefs"].reverse()
        result = canonicalize(doc)
        addresses = [f["address"] for f in result["functions"]]
        self.assertEqual(addresses, ["0x00100000", "0x00100040"])
        self.assertEqual(result["project"]["entry"], "0x00100000")
        self.assertEqual(result["functions"][1]["comments"][0]["address"], "0x00100040")

    def test_dumps_is_deterministic(self) -> None:
        doc = load(EXPORT, check=False)
        first = dumps(doc)
        second = dumps(doc)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))

    def test_saved_file_is_lf(self) -> None:
        doc = load(EXPORT, check=False)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "export.json"
            save(doc, out)
            raw = out.read_bytes()
            self.assertNotIn(b"\r\n", raw)
            self.assertTrue(raw.endswith(b"\n"))
            self.assertEqual(raw.decode("utf-8"), dumps(doc))


class MergeTests(unittest.TestCase):
    def test_merge_applies_name_signature_and_comments(self) -> None:
        base = load(EXPORT, check=False)
        updates = load(UPDATES, check=False)
        merged = merge_updates(base, updates)
        function = next(f for f in merged["functions"] if f["address"] == "0x00100040")
        self.assertEqual(function["name"], "player_update")
        self.assertEqual(function["signature"], "void player_update(Player *player)")
        comments = {c["address"]: c["text"] for c in function["comments"]}
        self.assertIn("guarda la posición", comments.values())
        self.assertEqual(comments["0x00100040"], "actualiza el jugador")
        # El documento base no se modifica.
        original = next(f for f in base["functions"] if f["address"] == "0x00100040")
        self.assertEqual(original["name"], "game_update_player")

    def test_merge_replaces_comment_at_same_address(self) -> None:
        base = load(EXPORT, check=False)
        updates = {
            "schema_version": "re-1.0",
            "kind": "updates",
            "functions": [
                {
                    "address": "0x00100040",
                    "comments": [
                        {"address": "0x00100040", "text": "comentario nuevo"}
                    ],
                }
            ],
        }
        merged = merge_updates(base, updates)
        function = next(f for f in merged["functions"] if f["address"] == "0x00100040")
        texts = [c["text"] for c in function["comments"]]
        self.assertIn("comentario nuevo", texts)
        self.assertNotIn("actualiza el estado del jugador", texts)

    def test_merge_rejects_missing_function(self) -> None:
        base = load(EXPORT, check=False)
        updates = load(UPDATES, check=False)
        updates["functions"][0]["address"] = "0x00200000"
        with self.assertRaises(DocumentError) as ctx:
            merge_updates(base, updates)
        self.assertIn("0x00200000", str(ctx.exception))

    def test_merge_rejects_wrong_kind(self) -> None:
        base = load(EXPORT, check=False)
        with self.assertRaises(DocumentError):
            merge_updates(base, base)


class MakeUpdatesTests(unittest.TestCase):
    def test_roundtrip_is_lossless(self) -> None:
        base = load(EXPORT, check=False)
        updates = make_updates(base)
        validate_document(updates)
        self.assertEqual(len(updates["functions"]), len(base["functions"]))
        merged = merge_updates(base, updates)
        self.assertEqual(dumps(base), dumps(merged))

    def test_subset_and_flags(self) -> None:
        base = load(EXPORT, check=False)
        updates = make_updates(
            base,
            addresses=["0x00100040"],
            include_signatures=False,
            include_comments=False,
        )
        self.assertEqual(len(updates["functions"]), 1)
        item = updates["functions"][0]
        self.assertEqual(item["address"], "0x00100040")
        self.assertIn("name", item)
        self.assertNotIn("signature", item)
        self.assertNotIn("comments", item)

    def test_generated_at_is_optional_and_informative(self) -> None:
        base = load(EXPORT, check=False)
        updates = make_updates(base, generated_at="2026-11-01T00:00:00Z")
        self.assertEqual(updates["source"]["generated_at"], "2026-11-01T00:00:00Z")

    def test_fallback_names_are_skipped_unless_requested(self) -> None:
        base = load(EXPORT, check=False)
        function = base["functions"][1]
        function["name"] = "sub_00100040"
        function.pop("signature", None)
        function.pop("comments", None)
        updates = make_updates(base)
        addresses = [item["address"] for item in updates["functions"]]
        self.assertNotIn("0x00100040", addresses)
        with_fallback = make_updates(base, include_fallback_names=True)
        addresses = [item["address"] for item in with_fallback["functions"]]
        self.assertIn("0x00100040", addresses)

    def test_unknown_address_is_rejected(self) -> None:
        base = load(EXPORT, check=False)
        with self.assertRaises(SchemaError):
            make_updates(base, addresses=["0xZZ"])


class CliTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        # `-c` en vez de `-m` para que funcione también con el Python embebido
        # de Windows, cuyo fichero `._pth` ignora PYTHONPATH.
        bootstrap = (
            "import sys; sys.path.insert(0, sys.argv[1]);"
            " from decompforge_re.cli import main;"
            " raise SystemExit(main(sys.argv[2:]))"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(PYTHON_DIR)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, "-c", bootstrap, str(PYTHON_DIR), *args],
            cwd=str(PYTHON_DIR),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def test_validate(self) -> None:
        result = self._run("validate", str(EXPORT))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cumple re-1.0", result.stdout)

    def test_merge_to_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "merged.json"
            result = self._run("merge", str(EXPORT), str(UPDATES), "-o", str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            merged = load(out, check=False)
            validate_document(merged)
            self.assertIn("fusionado", result.stdout)

    def test_make_updates_to_stdout(self) -> None:
        result = self._run("make-updates", str(EXPORT))
        self.assertEqual(result.returncode, 0, result.stderr)
        updates = json.loads(result.stdout)
        validate_document(updates)
        self.assertEqual(updates["kind"], "updates")

    def test_invalid_document_returns_code_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text('{"schema_version": "re-1.0"}', encoding="utf-8")
            result = self._run("validate", str(bad))
            self.assertEqual(result.returncode, 2)
            self.assertIn("documento inválido", result.stderr)


if __name__ == "__main__":
    unittest.main()
