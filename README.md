# DecompForge

Plataforma asistida por IA para **decompilar, verificar y portar videojuegos** a
plataformas nativas. Consolas objetivo: PS2, PS3, PS4 y Nintendo Switch.

> **Principio rector:** la IA propone; el sistema verifica. Ningún cambio generado
> por IA se acepta sin una comprobación automática contra el binario original.

La especificación completa está en
[`docs/original/DecompForge_Documento_Maestro.docx`](docs/original/DecompForge_Documento_Maestro.docx).

## Estado

| Fase | Contenido | Estado |
| --- | --- | --- |
| 0 | Descubrimiento y diseño | ✅ [`docs/FASE0-descubrimiento-y-diseno.md`](docs/FASE0-descubrimiento-y-diseno.md) |
| 1 | Núcleo y modelo de proyecto | ✅ Cargadores, SQLite, CLI, Capstone, detección recursiva de funciones, *ownership* y CFG |
| 2 | Integración con herramientas de RE | ✅ Esquema `re-1.0`, `export --format re-json`, `apply`, cliente Python y scripts de Ghidra ([`adapters/`](adapters/)); los scripts de Ghidra aún no se han compilado con una instalación real |
| 3-11 | NameForge, MatchLoop, StaticRecomp, HAL, TwinRun, UI... | ⬜ Pendiente |

Detalle de lo hecho y decisiones: [`docs/BITACORA.md`](docs/BITACORA.md).

## Requisitos

- [Rust](https://rustup.rs) ≥ 1.75 (`rustup update`).
- Un compilador de C: SQLite y Capstone se compilan incluidos. En Windows sirven
  *Build Tools for Visual Studio* con "Desarrollo para el escritorio con C++" o
  MinGW-w64/GCC (toolchain `x86_64-pc-windows-gnu`); en Linux, `build-essential`.
- Opcional para los adaptadores y la validación de esquemas: Python ≥ 3.9 con
  `pip install jsonschema`.
- Opcional para Ghidra: Ghidra 11.x (los scripts están en `adapters/ghidra/`;
  no requieren compilar una extensión).

## Uso rápido

```powershell
cargo build --release
# Proyecto de ejemplo con un binario SINTÉTICO (sin contenido de terceros):
cargo run -p decompforge-cli -- init demo --sample --dir target/demo
cargo run -p decompforge-cli -- info --project target/demo/demo.dfproj
cargo run -p decompforge-cli -- export --format json --project target/demo/demo.dfproj
```

Con tu propio binario (ya descifrado por ti, con medios legítimos):

```powershell
decompforge init mijuego --platform ps2
decompforge load juego.elf --project mijuego.dfproj   # carga + análisis
decompforge analyze juego.elf --project mijuego.dfproj
decompforge info --project mijuego.dfproj
```

`load` ejecuta automáticamente la detección de funciones con Capstone (usa
`--no-analyze` para importar solo secciones y símbolos). `analyze` vuelve a
analizar el mismo binario: su SHA-256 debe coincidir con el cargado y se
conservan los nombres y estados ya existentes.

Para una ROM plana: `decompforge load rom.bin --arch arm --endian little --base 0x08000000`.

### Intercambio con Ghidra u otra herramienta (Fase 2)

```powershell
# Exportación re-1.0 (funciones, instrucciones, comentarios, xrefs y tipos)
decompforge export --format re-json --project mijuego.dfproj --output export.json

# Validar y generar un parche editable con el cliente Python
python -m decompforge_re validate export.json
python -m decompforge_re make-updates export.json -o updates.json

# Aplicar nombres, firmas y comentarios (todo o nada)
decompforge apply updates.json --project mijuego.dfproj
```

El flujo completo, la correspondencia de campos y las limitaciones están en
[`adapters/README.md`](adapters/README.md). Los scripts de Ghidra exportan e
importan el mismo documento; ver [`adapters/ghidra/README.md`](adapters/ghidra/README.md).

Códigos de salida: `0` ok · `1` error · `2` comando aún no implementado · `3` formato protegido (rechazado) · `4` formato reconocido sin cargador.

## Formatos soportados (Fase 1)

| Formato | Estado |
| --- | --- |
| ELF 32/64, LE/BE (MIPS, PPC, ARM, ARM64, x86, x86-64, SPU) | ✅ secciones o, si no hay, segmentos `PT_LOAD` |
| DOL (GameCube/Wii) | ✅ detección por validación de cabecera |
| PE/COFF (Windows, Xbox) | ✅ |
| NSO0 (Switch) | ✅ cabecera, mapa de memoria y descompresión LZ4 por bloques |
| ROM plana | ✅ con `--arch --endian --base` |
| XEX | ⏳ reconocido, sin cargador |
| ISO 9660, PFS0 | ⏳ reconocidos; son contenedores, no ejecutables |
| SELF (PS3/PS4) | 🚫 **rechazado por diseño**: cifrado/firmado. No se descifra ([ADR-007](docs/adr/ADR-007-rechazar-contenedores-protegidos.md)) |

Detección de funciones: MIPS, PowerPC, ARM, ARM64 y x86/x86-64
([ADR-010](docs/adr/ADR-010-capstone-y-deteccion-de-funciones.md)). Cada
instrucción pertenece como mucho a una función (*ownership*); el análisis
también produce bloques básicos y aristas de CFG (`fallthrough`, `branch`,
`jump`, `call`, `tail_call`) que se guardan en el proyecto y se regeneran en cada
`analyze`. En MIPS los *delay slots* de ramas, saltos, llamadas y retornos se
incluyen en su función y en el bloque de la instrucción que transfiere el control
([ADR-014](docs/adr/ADR-014-cfg-ownership-y-delay-slots.md)). El ELF de
Cell **SPU** se puede cargar e inspeccionar con `load --no-analyze`, pero
Capstone no lo desensambla: `analyze` devuelve un error explícito (código 4).

Un NSO con segmentos LZ4 se analiza sobre una imagen materializada (archivo +
segmentos descomprimidos); los `file_offset` de sus secciones se refieren a esa
imagen ([ADR-013](docs/adr/ADR-013-imagen-materializada-nso.md)).

## Desarrollo

```powershell
./scripts/check.ps1        # fmt + clippy (-D warnings) + tests + docs + adaptadores   (o: make check)
./scripts/coverage.ps1     # cobertura del nucleo (RNF-06), Windows con MSVC   (o: make coverage)
./scripts/check-ghidra.ps1 # compila los scripts de Ghidra y prueba el ciclo re-1.0 completo
make adapters              # pruebas del cliente Python (requiere jsonschema)
cargo doc --workspace --no-deps --open          # API pública del núcleo
```

El CI de GitHub Actions (`.github/workflows/ci.yml`) ejecuta formato, Clippy,
documentación y pruebas en **Windows, Linux y macOS**, mide la cobertura del
núcleo (mínimo 80 % de líneas), comprueba que el export JSON `1.0` es idéntico
byte a byte y válido contra su esquema, y ejecuta el ciclo `re-1.0`
exportar → validar → parche → aplicar → reexportar
([ADR-011](docs/adr/ADR-011-integracion-continua.md),
[ADR-012](docs/adr/ADR-012-esquema-re-y-adaptadores.md)).
La cobertura se mide con `cargo-llvm-cov` (`rustup component add llvm-tools`
y `cargo install cargo-llvm-cov --locked`). En Windows con toolchain GNU no está
disponible (`profiler_builtins` no se distribuye); `scripts/coverage.ps1` carga
el entorno de Visual Studio Build Tools y usa el toolchain MSVC sin cambiar el
toolchain por defecto.

Estructura (ver Documento Maestro §5.4): `core/` (Rust), `cli/` (Rust),
`schemas/` (JSON Schema de los formatos `1.0` y `re-1.0`), `adapters/`
(cliente Python y scripts de Ghidra), `docs/` (fase 0, ADR, bitácora); el resto
(`analysis/ ai/ verify/ platform/ toolchains/ ui/`) son carpetas reservadas para
fases posteriores.

## Legal

DecompForge **no** incluye ni distribuye juegos, firmware, claves ni assets, y
**no** elude protecciones. Lee [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md). Esto no es
asesoramiento jurídico. Licencia del software: MIT.
