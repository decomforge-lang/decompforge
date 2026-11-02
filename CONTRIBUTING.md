# Guía de contribución

## Reglas de oro (del Documento Maestro)

- **La IA propone, el sistema verifica.** Ningún cambio generado por IA se acepta
  sin una comprobación automática contra el binario original o un emulador.
- **Nada de contenido de terceros** en el repositorio (ver `ACCEPTABLE_USE.md`).
- **Documenta cada decisión técnica** en `docs/adr/` (plantilla en `docs/adr/ADR-000-plantilla.md`).
- **Reproducibilidad:** versiones fijadas, `Cargo.lock` versionado, resultados deterministas.

## Flujo

1. Una fase por sesión de trabajo; commit al terminar cada fase.
2. Cada módulo lleva pruebas unitarias y de integración.
3. Antes de enviar un cambio:

```
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

En Windows: `./scripts/check.ps1`; en Linux/macOS: `make check`.

4. Si tocas el núcleo, mide la cobertura (mínimo 80 % de líneas):

```
cargo llvm-cov --package decompforge-core --all-targets --fail-under-lines 80
```

En Windows con el toolchain GNU no funciona (`profiler_builtins` no se
distribuye): usa `./scripts/coverage.ps1`, que localiza Visual Studio Build Tools
y ejecuta la misma medición con el toolchain MSVC.

5. Si tocas los adaptadores o los esquemas `re-1.0`:

```
cd adapters/python
python -m unittest discover -s tests -t . -v
```

En Windows, `./scripts/check-ghidra.ps1` compila los scripts Java contra los JAR
de una instalación real de Ghidra y, si hay `gcc`, ejecuta el ciclo completo
exportar → validar → aplicar → reexportar en modo headless. Requiere
`GHIDRA_HOME` (o `-GhidraHome`) y un JDK que cumpla el mínimo de Ghidra
(`application.java.min`).

Requiere Python ≥ 3.9 y `jsonschema`. El esquema se busca en
`DECOMPFORGE_RE_SCHEMA`, en la copia empaquetada o en `schemas/`; si instalas el
paquete fuera del repositorio, define esa variable. Los ejemplos de
`adapters/examples/` deben seguir siendo sintéticos: nunca incluyas binarios,
tipos ni cadenas de un juego real.

6. Anota lo hecho en `docs/BITACORA.md` y, si tomas una decisión de
   arquitectura, añade un ADR en `docs/adr/` (plantilla en
   `docs/adr/ADR-000-plantilla.md`).

## Criterios de calidad

Cobertura ≥ 80 % en el núcleo, cero advertencias de Clippy, documentación
pública sin huecos (`#![warn(missing_docs)]` en el núcleo) y entradas
malformadas que nunca deben provocar un *panic*.
