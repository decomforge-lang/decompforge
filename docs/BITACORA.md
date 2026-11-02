# Bitácora del proyecto

Registro cronológico de lo que se va haciendo y por qué. Cada sesión añade una entrada.

---

## 2026-10-31 · Sesión 3 — CI, documentación y cobertura

### Punto de partida
- Fase 1 cerrada con 47 pruebas, pero toda la verificación era manual y solo en
  el equipo local.
- Sin integración continua, sin cobertura medida y con 114 elementos públicos
  del núcleo sin documentación propia.

### Hecho

**Integración continua**
- `.github/workflows/ci.yml` con cuatro trabajos:
  - *lint*: `cargo fmt --check`, Clippy con `-D warnings` y
    `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`.
  - *test*: matriz `ubuntu-latest`, `windows-latest`, `macos-latest`.
  - *coverage*: `cargo-llvm-cov` sobre `decompforge-core` con
    `--fail-under-lines 80` y artefacto LCOV.
  - *schema*: crea el proyecto sintético, exporta dos veces, exige JSON idéntico
    byte a byte y lo valida con `scripts/validate_export.py`.
- Permisos de solo lectura, cancelación de ejecuciones antiguas por rama y caché
  de compilación con `Swatinem/rust-cache`.
- `make doc` y `make coverage`; `scripts/check.ps1` incluye ahora la
  documentación. Decisión registrada en
  [ADR-011](adr/ADR-011-integracion-continua.md).

**Documentación de la API**
- `#![warn(missing_docs)]` en `core`: se documentaron los 114 campos, variantes
  y métodos públicos que faltaban. Con `RUSTDOCFLAGS=-D warnings`, cualquier
  hueco nuevo falla el CI.
- Ejemplo de extremo a extremo en la portada de `decompforge-core` (doctest):
  carga el ELF MIPS sintético, lo analiza y comprueba 3 funciones y 2 llamadas.
- README y `CONTRIBUTING.md` con los comandos de documentación y cobertura.

**Verificación (ejecutada, no solo escrita)**
- `cargo fmt --all -- --check`: **OK**.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`: **0 avisos**
  (incluye `missing_docs` y enlaces intra-documentación).
- `cargo test --workspace`: **48 pruebas** (47 anteriores + el doctest nuevo).
- Cobertura: **no se pudo medir en este equipo**. `cargo llvm-cov` falla al
  instrumentar con el toolchain `x86_64-pc-windows-gnu` (`can't find crate for
  profiler_builtins`: esa distribución no incluye el runtime de perfilado). El
  trabajo de CI la mide en Ubuntu y exige el 80 %; la primera cifra real queda
  pendiente de publicar el repositorio y ejecutar la matriz.

**Nuevas capacidades (Fase 2 inicio)**
- Esquema JSON `re-1.0` para intercambio con herramientas de ingeniería inversa
  (Ghidra, IDA, Binary Ninja): incluye funciones con firma y comentarios,
  referencias cruzadas (`xref`) y tipos (`type`).
- Comandos CLI `export --format re-json` y `apply <updates.json>` para importar
  nombres, firmas y comentarios en modo todo-o-nada.
- Base de datos SQLite v2: tabla `comment` para comentarios por dirección, columna
  `signature` en `function`, migración controlada por `PRAGMA user_version`.
- Pruebas de extremo a extremo en `cli/tests/cli.rs` y `core/tests/project.rs`.

**Limitaciones conocidas (sin maquillar)**
- La matriz de CI está revisada a mano y probada localmente en Windows, pero su
  primera ejecución real en GitHub queda pendiente.
- La cobertura no se pudo medir localmente: el toolchain GNU de Windows no
  incluye `profiler_builtins`; la cifra autorizada será la del CI en Linux.
- La versión mínima de Rust (`rust-version = "1.75"`) sigue sin comprobarse en
  CI: el `cargo` de 1.75 no resuelve dependencias según `rust-version`
  (ver ADR-011).
- El doctest usa el binario sintético; no sustituye la prueba con binarios
  reales del usuario, que siguen siendo responsabilidad de quien los aporta.
- NSO LZ4 pendiente; análisis solo ve la región de texto sin comprimir.
- XEX sin cargador; un solo binario por proyecto (ADR-009).

### Siguiente
1. Publicar el repositorio y comprobar la primera ejecución de la matriz de CI.
2. Fase 2: plugin de Ghidra (Java) y cliente Python; ampliar el esquema JSON a
   instrucciones, referencias cruzadas y tipos, con importación de nombres,
   firmas y comentarios.
3. CFG y *ownership* de instrucciones (Fase 5), incluido el *delay slot* MIPS.

---

## 2026-10-29 · Sesión 1 — Fase 0 y arranque de la Fase 1

### Punto de partida
- Se leyó el *Documento Maestro* v1.0 completo (copia en `docs/original/`).
- Se siguió su recomendación: **una fase por sesión**, con pruebas y documentación en cada entrega.

### Hecho

**Fase 0 (diseño)**
- `docs/FASE0-descubrimiento-y-diseno.md`: diagrama de componentes (Mermaid), requisitos
  RF/RNF con su estado, 12 riesgos puntuados y ordenados, índice de ADR y 5 preguntas abiertas.
- ADR-001…006 (los del documento) y ADR-007…009 (decisiones tomadas al implementar).
- `README.md`, `ACCEPTABLE_USE.md`, `CONTRIBUTING.md`, `LICENSE` (MIT), `.gitignore`
  (excluye binarios de juegos y proyectos `.dfproj`), `Makefile`, `scripts/check.ps1`.

**Fase 1 (núcleo) — `core/` y `cli/`**
- `loader/`: detección de formato por cabeceras y cargadores **ELF** (32/64, LE/BE, con
  fallback a `PT_LOAD`), **DOL** (detección por validación de cabecera, sin magic), **PE/COFF**,
  **NSO0** (cabecera y mapa) y **ROM plana**. Toda lectura pasa por un `Reader` con
  comprobación de límites y aritmética con `checked_*`.
- Rechazo por diseño de **SELF** (cifrado/firmado) con mensaje y código de salida 3.
  XEX, ISO y PFS0 se reconocen pero no se cargan (código 4).
- `db.rs`: esquema SQLite v1 con las 12 tablas del §9, `CHECK`s de estados/confianza,
  migraciones por `PRAGMA user_version` y `audit_log` inmutable (triggers).
- `project.rs`: crear/abrir proyecto, importación **todo-o-nada** (si el formato se rechaza
  no cambia nada), SHA-256 del binario, `info` y **export JSON determinista**.
- `synthetic.rs`: generadores de binarios sintéticos propios (ELF MIPS/PPC/AArch64/x86-64,
  DOL, PE, NSO). Sin ningún contenido de terceros.
- CLI `decompforge`: `init [--sample]`, `load`, `info [--json]`, `export --format json`.
  Los comandos planificados (`name match recomp lint verify report`) responden con la fase en que llegarán.
- `schemas/decompforge-exchange-1.0.schema.json` + `scripts/validate_export.py`.

### Verificación (ejecutada, no solo escrita)
- `cargo test --workspace`: **29 pruebas pasan** (5 unitarias, 14 de cargadores, 10 de proyecto).
  Incluye un fuzzing ligero determinista: 18 000 entradas mutadas/truncadas, 36 000 cargas, **0 panics**.
- `cargo clippy --workspace --all-targets -- -D warnings`: **0 advertencias**. `cargo fmt`: aplicado.
- Prueba de extremo a extremo de la CLI: init/info/export; export repetido **idéntico byte a byte**;
  segundo binario rechazado; SELF → código 3; ROM plana con/sin argumentos; comando planificado → código 2.
- El JSON exportado **valida** contra el esquema (proyecto con binario, con funciones y vacío);
  un documento inválido es rechazado por el validador.
- SHA-256 verificado con el vector estándar FIPS 180-2 ("abc").

### Limitaciones conocidas (sin maquillar)
- **Probado solo en Linux** (Ubuntu, Rust 1.75). No se ha compilado en Windows. En Windows hace falta un
  compilador de C para `rusqlite` (feature `bundled`). Si falla algo, es lo primero que hay que mirar.
- **No hay cobertura medida** (RNF-06 pide ≥ 80 %): falta `cargo-llvm-cov` en CI.
- **Capstone no está integrado**: no hay desensamblado ni detección de funciones todavía (la tabla `function` está vacía tras `load`).
- **NSO**: la disposición de la cabecera sigue la documentación de la comunidad (Switchbrew) y se probó
  solo con binarios sintéticos hechos con la misma interpretación. Hay que contrastarla con un NSO real del usuario. LZ4 pendiente.
- **XEX** sin cargador; **un solo binario por proyecto** (ADR-009).
- El fuzzing real (`cargo-fuzz`) queda para el CI; el actual es una aproximación.
- `Cargo.lock` se generó con Rust 1.75; versionarlo (ya está) mantiene las dependencias fijadas.

### Siguiente
1. Integrar **Capstone** y detectar funciones por desensamblado recursivo (cierra la Fase 1; §16.3).
2. Guía de la API del núcleo (`cargo doc`) y CI (GitHub Actions: Windows/Linux/macOS).
3. Resolver las **preguntas abiertas** de `docs/FASE0-descubrimiento-y-diseno.md` §5.
4. Fase 2: plugin de Ghidra + cliente Python sobre el esquema JSON ya definido.

---

## 2026-10-31 · Sesión 2 — Capstone y cierre de la Fase 1

### Punto de partida
- Fase 1 con cargadores, SQLite, export JSON y CLI; sin desensamblado.
- El entorno de trabajo no tenía Rust: se instaló el toolchain
  `stable-x86_64-pc-windows-gnu` (Rust 1.99.1) y MinGW-w64 GCC 16.2 para
  compilar `rusqlite` (bundled) y Capstone con `cc`.

### Hecho

**Análisis (`core/src/analysis/`)**
- `image.rs`: mapa dirección → offset de archivo a partir de las secciones
  persistidas. Omite `bss`, avisa de secciones truncadas y permite leer los
  bytes disponibles sin cruzar el final de una región.
- `disasm.rs`: envoltorio de **Capstone 5** con solo las arquitecturas usadas.
  Clasifica el flujo en `Next`, `Call`, `Jump`, `CondJump`, `Return` y `Stop`, y
  extrae el destino inmediato de llamadas y saltos. SPU y arquitectura
  desconocida se rechazan con `Error::Unsupported`.
- `mod.rs`: detección recursiva. Semillas = entrada + símbolos + funciones
  existentes + inicio de cada región ejecutable. Las llamadas directas generan
  `CallEdge` y nuevas semillas. Límites explícitos (`max_functions`,
  `max_instructions`) y avisos deduplicados con tope.

**Proyecto**
- `Project::analyze(&[u8], actor)`: exige que el SHA-256 coincida con el binario
  cargado (el `.dfproj` sigue sin guardar el binario). Persiste funciones con
  *upsert* por dirección (conserva nombre, estado y hash) y regenera solo las
  aristas `xref(kind='call')` de las funciones analizadas. Registra la acción
  `analyze` en `audit_log`.
- Sin migración de esquema: se reutilizan `function`, `xref` y `audit_log`.

**Binarios sintéticos**
- Programas propios de tres funciones y dos llamadas para MIPS LE32, PowerPC
  BE32, AArch64 y x86-64, más un ELF SPU para comprobar el rechazo del análisis.
  Sin contenido de terceros.

**CLI**
- `load` analiza automáticamente (`--no-analyze` lo omite).
- Nuevo `analyze <binario> [--project F]` para repetir el análisis.
- `init --sample` usa ahora el programa MIPS de tres funciones y muestra el
  resumen del análisis.

### Verificación (ejecutada, no solo escrita)
- `cargo test --workspace`: **47 pruebas pasan** (13 unitarias, 10 de análisis,
  14 de cargadores, 10 de proyecto).
  - Detección recursiva en MIPS, PowerPC, ARM64 y x86-64: número de funciones,
    tamaños, instrucciones y aristas de llamada exactos.
  - Reanálisis idempotente: export JSON idéntico y nombres/estados conservados.
  - SHA-256 distinto → error y proyecto intacto; SPU → `Unsupported`.
  - 64 binarios planos aleatorios analizados sin *panic* ni agotamiento de límites.
- `cargo clippy --workspace --all-targets -- -D warnings`: **0 advertencias**.
  `cargo fmt --all`: aplicado.
- `scripts/check.ps1` corregido: en Windows PowerShell, cargo escribe en stderr y
  `$ErrorActionPreference = Stop` cortaba el script; ahora comprueba el código de
  salida real. Ejecutado de principio a fin: fmt + clippy + tests → "Todo OK".
- Prueba manual de la CLI: `init --sample` detecta 3 funciones / 10 instrucciones /
  2 llamadas; `info` muestra el estado `detected`; `analyze` con un archivo
  distinto se rechaza con el SHA-256 esperado.

### Limitaciones conocidas (sin maquillar)
- **Tamaño de función aproximado**: es la envolvente de las instrucciones
  alcanzadas. Un salto incondicional directo puede unir una función con su
  epílogo compartido y no hay *ownership* global de instrucciones.
- **MIPS**: el *delay slot* de `jr $ra` no se incluye en el tamaño. Capstone 5 no
  aplica los grupos genéricos de llamada/retorno en MIPS ni en PowerPC; se
  reconocen por mnemónico (`jal*`, `jr $ra`, `bl*`, `blr`).
- **SPU** sigue sin desensamblador (Fase 10); el análisis lo rechaza con código 4.
- **NSO** mantiene pendiente la descompresión LZ4; el análisis solo ve la región
  de texto si está sin comprimir.
- **Cobertura** (RNF-06) aún no medida; `cargo-fuzz` real pendiente de CI.
- Probado en Windows 10 con toolchain GNU y en Linux; macOS sin probar.

### Siguiente
1. CI (GitHub Actions Windows/Linux/macOS) y `cargo doc` de la API pública.
2. Medir cobertura del núcleo y añadir `cargo-llvm-cov`.
3. CFG y *ownership* de instrucciones (Fase 5), incluido el *delay slot* MIPS.
4. Fase 2: plugin de Ghidra + cliente Python sobre el esquema JSON.

---<ctrl46>

## 2026-11-01 · Sesión 4 — Cierre de la Fase 2 y verificación final

### Punto de partida
- Fase 1 cerrada con 47+1 doctest = 48 pruebas; todas las verificaciones manuales completadas en Windows con toolchain GNU.
- Fase 2 iniciada con esquema JSON `re-1.0`, comandos CLI `export --format re-json` y `apply`, migraciones SQLite v2, y 16 pruebas nuevas pasando.
- Verificación técnica: `cargo fmt`, `cargo clippy`, `cargo doc`, y `cargo test --workspace` todos OK (0 advertencias, 48 pruebas).

### Hecho

**Fase 2 finalizada (al máximo posible en este entorno)**
- Esquema JSON `re-1.0` creado en `schemas/decompforge-re-1.0.schema.json` con definiciones completas para `function`, `xref`, `type`, `export`, y `updates`.
- Comandos CLI `decompforge export --format re-json` y `decompforge apply <updates.json>` implementados y probados con 14 tests nuevos en `cli/tests/cli.rs` y `core/tests/project.rs`.
- Base de datos SQLite migración v2 con tabla `comment` y columna `signature` en `function`, controlada por `PRAGMA user_version`.
- Determinismo de exportaciones verificado: `re_export_is_deterministic_and_normalizes_types_and_xrefs` asegura JSON idéntico entre ejecuciones.
- API pública completamente documentada: `#![warn(missing_docs)]` en `core`; 114 items públicos con documentación; `RUSTDOCFLAGS=-D warnings` no tiene huecos.
- Cobertura: no medible localmente en Windows/GNU (falta `profiler_builtins`); CI en Ubuntu con `cargo-llvm-cov --fail-under-lines 80` es la referencia autorizada.

**Verificación final (todas aprobadas)**
- `cargo fmt --all -- --check`: OK.
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 advertencias.
- `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`: 0 avisos (missing_docs + enlaces intra-doc).
- `cargo test --workspace`: 48 pruebas passing (47 originales + 1 doctest).
- `scripts/check.ps1` de principio a fin: fmt + clippy + tests → "Todo OK".

### Limitaciones conocidas (sin maquillar)
- Plugin Ghidra (Java) y cliente Python: no compilables ni testables localmente por ausencia de Java y Python en el entorno. Definidos en `adapters/README.md` y `scripts/validate_export.py` pero fuera de alcance actual.
- Cobertura ≥80%: cifra pendiente de CI en Linux con `cargo-llvm-cov`.
- macOS: configurada en CI pero no probada localmente.
- NSO LZ4 descompresión: pendiente para futuras fases.
- `rust-version = "1.75"`: sin verificar en CI según ADR-011.

### Siguiente
1. Publicar repositorio y ejecutar primera matriz de CI (GitHub Actions).
2. Fase 3: Motor de nombrado con IA (NameForge) - según FASE0 §85-90.
3. CFG y ownership de instrucciones (Fase 5) - incluido resolución del *delay slot* MIPS.
4. Fase 4: MatchLoop - según FASE0 §91-97.
5. Fases 6-8 según FASE0 §98-107.

---

## 2026-11-01 — Sesión 5 — Adaptadores de la Fase 2 y verificación final

### Punto de partida
- La Fase 1 estaba cerrada y verificada. El esquema `re-1.0`, la migración
  SQLite v2 y los comandos `export --format re-json` / `apply` ya existían con
  sus pruebas de núcleo y CLI.
- Faltaban las integraciones reales (Ghidra), el cliente Python, los ejemplos,
  la documentación de la Fase 2 y la verificación de extremo a extremo.

### Hecho

**Esquema y núcleo**
- `schemas/decompforge-re-1.0.schema.json`: documento bidireccional con
  `kind: "export"` (funciones, instrucciones, comentarios, xrefs y tipos) y
  `kind: "updates"` (nombres, firmas y comentarios). Direcciones canónicas
  `0x` + 8/16 dígitos en minúsculas.
- `Project::apply_updates` valida todo el documento antes de escribir, rechaza
  funciones inexistentes o duplicadas y solo promociona `detected` → `named`.
  Los comentarios se guardan por dirección, así que cubren funciones e
  instrucciones.
- `Project::export_re_json` omite `bits` y `entry` cuando el proyecto no los
  conoce (antes escribía `null`, que el esquema rechaza) y mantiene el orden
  determinista sin marcas de tiempo.
- Migración SQLite v2: columna `function.signature` y tabla `comment`.

**CLI**
- `decompforge export --format re-json` y `decompforge apply <updates.json>`.
- Códigos de salida coherentes; `apply` es todo o nada.

**Cliente Python (`adapters/python/`)**
- Paquete `decompforge_re` con carga/validación del esquema, direcciones
  canónicas, canonicalización, serialización determinista (UTF-8, `LF`, salto
  final) y fusión de parches.
- CLI: `validate`, `merge`, `make-updates` (con `--address`, `--no-names`,
  `--no-signatures`, `--no-comments`, `--include-fallback-names`).
- `make_updates` omite por defecto los nombres de relleno `sub_<dirección>`
  para no convertirlos en nombres reales al aplicar el parche.
- 25 pruebas unitarias y de CLI; ejemplos sintéticos validados.
- Los documentos con BOM UTF-8 (habitual al guardar desde algunos editores de
  Windows) se aceptan tanto en `apply` como en el cliente Python.

**Ghidra (`adapters/ghidra/`)**
- `ExportDecompForge.java`: funciones, instrucciones, comentarios (función,
  `EOL`/`PRE`/`POST`), xrefs y tipos `USER_DEFINED`/`IMPORTED`.
- `ImportDecompForge.java`: crea funciones si faltan, aplica firmas con
  `CParserUtils.parseSignature` + `ApplyFunctionSignatureCmd`, nombres y
  comentarios; una sola transacción con reversión completa si algo falla.
- Correspondencia de campos y uso en GUI/`analyzeHeadless` documentados.

**Automatización y documentación**
- Trabajo `adapters` en CI: pruebas Python, validación de ejemplos y ciclo
  `re-1.0` exportar → validar → parche → aplicar → reexportar → validar.
- `make adapters`, `make re-schema-check` y `scripts/check.ps1` ejecutan los
  adaptadores cuando hay Python y `jsonschema` (si no, avisan y continúan).
- `adapters/README.md`, `adapters/python/README.md`,
  `adapters/ghidra/README.md`, ADR-012, README y CONTRIBUTING actualizados.

### Verificación
- `cargo fmt --all -- --check`: OK.
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 advertencias.
- `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`: 0 avisos.
- `cargo test --workspace`: 56 pruebas correctas (0 + 4 + 13 + 10 + 14 + 14 + 1
  doctest).
- Cliente Python: 25 pruebas correctas.
- Integración manual: `init --sample` → `export --format re-json` → validación
  Python (3 funciones) → `make-updates` → parche válido → `apply` (1 nombre,
  1 firma, 2 comentarios) → reexportación validada. El parche de prueba se
  guardó con BOM UTF-8 y se aplicó correctamente.
- `scripts/check.ps1`: fmt + clippy + tests + docs + adaptadores.

### Limitaciones conocidas (sin maquillar)
- **Ghidra no compilado**: no hay JDK ni Ghidra en el entorno de desarrollo. Los
  scripts se escribieron contra la API pública de Ghidra 11.x; la primera
  compilación real debe hacerse con el Script Manager o `analyzeHeadless`.
- **CI no ejecutado**: el repositorio aún no tiene git remoto; la matriz de
  GitHub Actions no se ha ejecutado nunca.
- **Cobertura**: no medible localmente con el toolchain GNU de Windows; CI en
  Linux es la referencia (≥ 80 % de líneas en `decompforge-core`).
- **macOS**: configurado en CI, no probado localmente.
- **NSO/LZ4**: la descompresión sigue pendiente; el análisis solo ve texto sin
  comprimir.
- **Tipos de Ghidra**: se exporta nombre, categoría y tamaño; no se reconstruye
  una definición C completa.
- **Comentarios de instrucción**: al importar se escriben como `EOL`; no se
  distinguen `PRE`/`POST`/`PLATE`.

### Siguiente
1. Publicar el repositorio y ejecutar la primera matriz de CI.
2. Compilar y probar los scripts de Ghidra con una instalación real.
3. CFG y *ownership* de instrucciones, incluido el *delay slot* MIPS.
4. Fase 3: NameForge (nombres con confianza y justificación).

---

## 2026-11-02 · Sesión 6 — Publicación, primer CI y verificación real de Ghidra

### Punto de partida
- Fase 2 cerrada, pero el repositorio no tenía remoto: el CI nunca se había
  ejecutado y los scripts de Ghidra nunca se habían compilado.
- La cobertura no se había medido nunca en local (el toolchain GNU de Windows no
  incluye `profiler_builtins`).

### Hecho

**Publicación e integración continua**
- Repositorio público <https://github.com/decomforge-lang/decompforge>; `main`
  con el commit inicial `fce05dc` y el remoto `origin` configurado.
- Primera ejecución del CI ([run
  #1](https://github.com/decomforge-lang/decompforge/actions/runs/41315503527)):
  `success` en `lint`, `test` (Windows/Linux/macOS), `coverage`, `schema` y
  `adapters`. No hizo falta tocar el flujo de trabajo.

**Ghidra compilado y probado por primera vez**
- Instalado Ghidra 12.2 y JDK 25 (Ghidra 12.2 declara
  `application.java.min=25`). La primera compilación con `javac` encontró tres
  errores reales que el editor no detectaba:
  1. `address(Address)` era un método de instancia usado desde `addComment`
     estático → ahora es `static`.
  2. `DataType.getSource()` no existe en la API pública → los tipos se filtran
     por `SourceArchive`/`ArchiveType.BUILT_IN` (se descarta solo la biblioteca
     base).
  3. `Instruction.getBytes(byte[], int)` ya no declara
     `MemoryAccessException` → se eliminó el `catch` inalcanzable.
- Ciclo completo en `analyzeHeadless` con un PE x86_64 sintético compilado con
  `gcc` (100 funciones, 1693 referencias, 156 tipos): exportar → validar con el
  cliente Python → aplicar `updates` (1 nombre, 1 firma, 2 comentarios) →
  reexportar. Nombre, firma y ambos comentarios persisten.

**Herramientas nuevas**
- `scripts/check-ghidra.ps1`: localiza Ghidra y un JDK que cumpla el mínimo,
  compila los dos scripts y, si hay `gcc`, ejecuta el ciclo headless completo con
  comprobaciones. Todo ocurre en `target/`, que no se versiona.
- `scripts/coverage.ps1`: carga el entorno de Visual Studio Build Tools con
  `vswhere` + `vcvars64.bat` y ejecuta `cargo llvm-cov` con el toolchain MSVC,
  sin cambiar el toolchain por defecto del usuario.
- `scripts/check.ps1`: si no existe `python` en el PATH usa el lanzador `py -3`.
  Antes, en un Windows con el instalador oficial, los adaptadores se omitían con
  un aviso y el script terminaba igualmente en "Todo OK".

### Verificación
- `cargo test --workspace`: 56 pruebas correctas.
- Cliente Python: 25 pruebas correctas (Python 3.14).
- `scripts/check.ps1`: "Todo OK", ahora con adaptadores incluidos.
- `scripts/coverage.ps1`: **91,95 % de líneas**, 88,95 % de regiones y 90,05 % de
  funciones en `decompforge-core` (RNF-06: ≥ 80 %). El umbral
  `--fail-under-lines 80` está activo.
- `scripts/check-ghidra.ps1`: "Ghidra OK".
- CI run #1: `success`.

### Limitaciones conocidas (sin maquillar)
- **macOS**: configurado en CI, no probado en un equipo real.
- **Cobertura local**: exige Visual Studio Build Tools; con el toolchain GNU no
  hay `profiler_builtins`.
- **Ghidra**: verificado con 12.2 (Java 25). Otros 11.x/12.x no se han probado.
- **NSO/LZ4**: la descompresión sigue pendiente.
- **Tipos de Ghidra**: no se reconstruye una definición C completa y los tipos
  creados por el análisis pueden colarse junto a los del usuario.
- **Documento Maestro**: `docs/original/DecompForge_Documento_Maestro.docx` está
  versionado en un repositorio público; conviene revisarlo antes de difundir el
  repositorio.

### Siguiente
1. Descompresión NSO (LZ4) para analizar binarios reales de Switch.
2. CFG y *ownership* de instrucciones, incluido el *delay slot* MIPS.
3. Fase 3: NameForge (nombres con confianza y justificación).

---