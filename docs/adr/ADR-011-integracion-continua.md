# ADR-011: Integración continua, documentación y cobertura

Estado: aceptado
Fecha: 2026-10-31

## Contexto
La Fase 1 termina con 47 pruebas (48 con el ejemplo de la API) y cero
advertencias en un solo equipo (Windows con toolchain GNU). El Documento Maestro
exige portabilidad a Windows, Linux y macOS (RNF-05), cobertura ≥ 80 % en el
núcleo (RNF-06), documentación de la API pública (RNF-06) y resultados
reproducibles (RNF-02). Hasta ahora nada de eso se comprobaba de forma automática
fuera de `scripts/check.ps1`.

## Decisión
1. **GitHub Actions** como CI, con el flujo en `.github/workflows/ci.yml`.
2. **Matriz de pruebas** `ubuntu-latest`, `windows-latest` y `macos-15-intel` con
   Rust estable. Windows usa el toolchain MSVC por defecto del *runner*, lo que
   además comprueba que el proyecto no depende de MinGW. El desarrollo local en
   Windows sigue usando GNU.
3. **Un solo trabajo de lint** (Ubuntu): `cargo fmt --check`,
   `cargo clippy --workspace --all-targets -- -D warnings` y
   `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`. El núcleo activa
   `#![warn(missing_docs)]`, así que un elemento público sin documentar también
   falla el CI. De este modo los enlaces intra-documentación rotos y los huecos
   de la API no llegan a `main`.
4. **Cobertura con `cargo-llvm-cov`** sobre `decompforge-core` (el núcleo y el
   análisis), con `--fail-under-lines 80`. La CLI no entra en el umbral: es una
   capa fina de entrada/salida ya cubierta por pruebas de extremo a extremo.
   El informe LCOV se publica como artefacto.
5. **Trabajo de esquema y determinismo**: crea un proyecto con el binario
   sintético, exporta dos veces, exige JSON idéntico byte a byte y lo valida
   contra `schemas/decompforge-exchange-1.0.schema.json`.
6. **Caché de compilación** con `Swatinem/rust-cache`; no se cachean binarios,
   proyectos `.dfproj` ni contenido de usuario.

## Alternativas
- **Solo Linux en CI**: más barato, pero no detectaría roturas específicas de
  Windows o macOS, que son objetivos del producto.
- **CircleCI / GitLab CI**: válidos, pero el repositorio se publicará en GitHub
  y Actions no requiere credenciales adicionales.
- **Umbral de cobertura sobre todo el workspace**: la CLI y `main` bajan el
  porcentaje sin aportar señal sobre la calidad del núcleo.
- **`cargo-tarpaulin`**: solo Linux y con menos fidelidad en código genérico;
  `llvm-cov` usa la instrumentación oficial de LLVM.
- **MSRV 1.75 en CI desde el primer día**: deseable, pero `cargo` 1.75 no tiene
  resolución consciente de `rust-version`; se añadirá cuando se fije y pruebe la
  versión mínima real con el `Cargo.lock` versionado.

## Consecuencias
(+) Cada *push* y *pull request* verifica formato, advertencias, pruebas en tres
sistemas, documentación, cobertura y reproducibilidad del export.
(+) El umbral de cobertura es una condición de merge, no una intención.
(+) Los artefactos permiten revisar qué líneas faltan por cubrir.

(-) La matriz de tres sistemas multiplica el tiempo de CI; la concurrencia
cancela ejecuciones antiguas de la misma rama.
(-) La cobertura se mide solo en Linux; diferencias de código por `cfg` en otros
sistemas no se reflejan en el porcentaje. Además, el toolchain
`x86_64-pc-windows-gnu` no distribuye `profiler_builtins`, así que la medición
local en ese entorno no es posible; el CI es la referencia.
(-) El CI no sustituye la prueba con binarios reales del usuario: los runners no
contienen juegos ni firmware (por diseño).
