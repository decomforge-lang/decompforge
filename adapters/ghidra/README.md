# Adaptador Ghidra — `re-1.0`

Dos scripts Java para intercambiar información entre Ghidra y DecompForge:

| Script | Dirección | Qué hace |
| --- | --- | --- |
| `ExportDecompForge.java` | Ghidra → JSON | Exporta funciones, instrucciones, comentarios, referencias cruzadas y tipos definidos por el usuario. No modifica el programa. |
| `ImportDecompForge.java` | JSON → Ghidra | Importa nombres, firmas y comentarios de un documento `updates`. Todo o nada: una transacción. |

Formato: `schemas/decompforge-re-1.0.schema.json`. La CLI de Rust genera el
mismo documento con `decompforge export --format re-json` y aplica los parches
con `decompforge apply`.

## Instalación

Copia los dos `.java` en el directorio de scripts de usuario de Ghidra:

- Linux/macOS: `~/ghidra_scripts/`
- Windows: `%USERPROFILE%\ghidra_scripts\`

También puedes dejarlos donde están y pasar `-scriptPath adapters/ghidra/scripts`
a `analyzeHeadless`, o usar **Window → Script Manager → Script Directories** en
la GUI. Los scripts aparecen en **Tools → DecompForge**.

Requisitos: Ghidra 12.x con su JDK correspondiente (12.2 exige Java 25, según
`Ghidra/application.properties`). Ghidra incluye Gson, así que no hay que
instalar dependencias Java.

## Verificación

`scripts/check-ghidra.ps1` automatiza lo que antes era manual:

1. compila ambos `.java` con `javac` contra los JAR de la instalación (detecta
   cambios de API que el editor no ve);
2. si hay `gcc`, compila un binario C mínimo en `target/ghidra-test`, lo importa
   con `analyzeHeadless`, ejecuta `ExportDecompForge`, valida el JSON con el
   cliente Python, aplica un documento `updates`, reexporta y comprueba que el
   nombre, la firma y los dos comentarios persisten.

```powershell
./scripts/check-ghidra.ps1                      # autodetecta Ghidra y el JDK
./scripts/check-ghidra.ps1 -CompileOnly         # solo compilacion
./scripts/check-ghidra.ps1 -GhidraHome D:\ghidra_12.2_PUBLIC -JavaHome C:\jdk-25
```

El binario y los proyectos de prueba se crean en `target/` y no se versionan.

## Exportar

GUI: abre el programa, **Tools → DecompForge → Exportar re-1.0**, elige el
fichero de salida.

Headless:

```sh
analyzeHeadless /ruta/proyectos Demo -process programa.elf \
  -postScript ExportDecompForge.java /ruta/export.json
```

El JSON se puede validar sin Ghidra:

```sh
python -m decompforge_re validate /ruta/export.json
```

## Importar

Parte de un documento `updates` (por ejemplo, generado con
`decompforge export --format re-json`, editado a mano y validado con el cliente
Python):

```sh
analyzeHeadless /ruta/proyectos Demo -process programa.elf -noanalysis \
  -postScript ImportDecompForge.java /ruta/updates.json
```

GUI: **Tools → DecompForge → Importar re-1.0** y elige el JSON.

El script:

1. comprueba `schema_version` y `kind`;
2. busca cada función por dirección y, si no existe, intenta crearla;
3. aplica la firma con `CParserUtils.parseSignature` y
   `ApplyFunctionSignatureCmd` (tipos y parámetros incluidos);
4. aplica el nombre explícito, que tiene prioridad sobre el de la firma;
5. escribe comentarios de función en la entrada y comentarios de instrucción en
   `EOL`;
6. revierte la transacción completa si algo falla.

## Correspondencia de campos

| JSON | Ghidra |
| --- | --- |
| `project.arch` / `endian` / `bits` | `Program.getLanguage()` y espacio de direcciones |
| `function.address` | `Function.getEntryPoint()` |
| `function.name` | `Function.getName()` / `setName` |
| `function.signature` | `Function.getPrototypeString(false, false)` / `ApplyFunctionSignatureCmd` |
| `function.instructions[]` | instrucciones del cuerpo de la función |
| `function.comments[]` | comentario de función (entrada) y comentarios de instrucción |
| `xrefs[]` | `ReferenceManager` (`call`, `jump`, `cond_jump`, `read`, `write`, `read_write`, `data`, `ref`) |
| `types[]` | tipos del `DataTypeManager` que no pertenecen a la biblioteca base (`ArchiveType.BUILT_IN`) |

## Limitaciones conocidas

- **Versión verificada**: Ghidra 12.2 con Java 25. La API pública de `DataType`
  no expone el `SourceType` original, así que los tipos se filtran por archivo
  de origen (se descarta solo la biblioteca base); los tipos creados por el
  análisis pueden aparecer junto a los del usuario.
- La exportación de tipos incluye nombre, categoría y tamaño; no reconstruye
  una definición C completa (el campo `definition` solo se rellena si Ghidra
  tiene descripción).
- El comentario importado en instrucciones se guarda como `EOL`; no se importan
  comentarios `PRE`/`POST`/`PLATE` por separado.
- Las referencias a pila/registro sin dirección destino se omiten.
- El script de importación crea funciones solo si Ghidra puede determinar un
  cuerpo; si no, informa y revierte.
- No se incluye ningún binario, tipo ni contenido de juego: las pruebas usan
  ejemplos sintéticos del repositorio.
