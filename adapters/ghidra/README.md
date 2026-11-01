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

Requisitos: Ghidra 11.x (probado contra su API pública; ver *Limitaciones*).
Ghidra incluye Gson, así que no hay que instalar dependencias Java.

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
| `types[]` | tipos `USER_DEFINED` o `IMPORTED` del `DataTypeManager` |

## Limitaciones conocidas

- **No compilado en este repositorio**: el entorno de desarrollo no tiene JDK ni
  Ghidra. Los scripts se escribieron contra la API pública de Ghidra 11.x; la
  primera compilación real debe hacerse con `analyzeHeadless` o el Script
  Manager y corregir cualquier cambio de API menor.
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
