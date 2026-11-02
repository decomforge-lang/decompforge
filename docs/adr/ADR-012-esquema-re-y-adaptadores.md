# ADR-012: Esquema de intercambio `re-1.0` y arquitectura de adaptadores

Estado: aceptado
Fecha: 2026-11-01

## Contexto
La Fase 2 del Documento Maestro (§9.4 y §11.4) pide intercambiar información con
herramientas de ingeniería inversa: exportar funciones, instrucciones,
referencias cruzadas y tipos desde Ghidra, e importar nombres, firmas y
comentarios. El esquema de la Fase 1
(`schemas/decompforge-exchange-1.0.schema.json`) es una exportación de solo
lectura del proyecto (secciones, símbolos, funciones) y no cubre parches ni
instrucciones. Además, el núcleo Rust no debe depender de Java ni de Python, y
los adaptadores no deben reimplementar el análisis ni la base de datos.

## Decisión
1. **Esquema propio `re-1.0`** en `schemas/decompforge-re-1.0.schema.json`,
   con `kind: "export"` para una exportación completa y `kind: "updates"` para
   un parche. Se mantiene separado del esquema `1.0` de la Fase 1 para no romper
   consumidores existentes.
2. **Direcciones canónicas**: cadena `0x` seguida de 8 dígitos hexadecimales
   (32 bits) o 16 (64 bits), siempre en minúsculas. Evita ambigüedades entre
   enteros, mayúsculas y anchos al comparar documentos.
3. **El núcleo Rust es la autoridad de escritura.** `Project::apply_updates`
   valida el documento completo, comprueba que cada función exista y aplica los
   cambios en una sola transacción SQLite (todo o nada). Solo promociona el
   estado `detected` a `named`; los estados posteriores se conservan.
4. **Los adaptadores solo transforman JSON.** El cliente Python valida,
   normaliza y fusiona documentos; no enlaza con Rust ni abre SQLite. Los
   scripts de Ghidra leen y escriben JSON y usan la API pública de Ghidra. Así
   cada pieza se puede probar y versionar por separado.
5. **Determinismo (RNF-02)**: el export del núcleo ordena funciones, referencias
   y tipos y omite marcas de tiempo. El cliente Python ordena las listas y las
   claves del objeto, escribe UTF-8 con saltos `LF` y un salto final. Dos
   ejecuciones con la misma entrada producen el mismo texto.
6. **Sin contenido de terceros**: los ejemplos de `adapters/examples/` y las
   pruebas son sintéticos. Los adaptadores nunca incluyen ni descargan juegos,
   firmware, claves o tipos de un juego.
7. **Ghidra como scripts Java**, no como extensión empaquetada en esta fase. Se
   instalan en `ghidra_scripts/` o se pasan con `-scriptPath`; funciona en la GUI
   y en `analyzeHeadless` sin compilar un ZIP de extensión.

## Alternativas
- **Reutilizar el esquema `1.0`**: habría exigido campos opcionales y una
  semántica doble (exportación y parche) en el mismo documento, con riesgo de
  romper la validación de la Fase 1.
- **Un esquema por herramienta (Ghidra, IDA, Binary Ninja)**: multiplica el
  trabajo de validación y de pruebas; un único documento intermedio es más
  fácil de mantener.
- **Escribir directamente en SQLite desde Python**: acopla el adaptador al
  esquema interno, duplica validaciones y permite estados inconsistentes.
- **Extensión Ghidra empaquetada**: mejor integración, pero exige JDK, Gradle y
  una versión concreta de Ghidra en CI; se puede añadir más adelante sin cambiar
  el formato JSON.
- **Nombres de relleno `sub_<dirección>` en los parches**: al aplicarlos se
  convertirían en nombres reales. El cliente Python los omite por defecto y
  permite incluirlos explícitamente.

## Consecuencias
(+) El formato es estable, validable por separado y compartido por Rust, Python
y Ghidra; las pruebas de los tres lo comprueban.
(+) El núcleo conserva la integridad del proyecto: un parche inválido no deja
cambios parciales.
(+) Los adaptadores no necesitan el binario ni el `.dfproj`, solo JSON.

(-) Hay dos esquemas que documentar y mantener (`1.0` y `re-1.0`).
(-) La exportación de tipos desde Ghidra solo incluye nombre, categoría y
tamaño; no reconstruye una definición C completa.
(-) Los scripts de Ghidra no se compilan en este repositorio (no hay JDK ni
Ghidra en el entorno de desarrollo); la primera compilación real debe hacerse
con el Script Manager o `analyzeHeadless`.
(-) El comentario importado en instrucciones se guarda como `EOL`; no se
distinguen `PRE`/`POST`/`PLATE`.

## Actualización (2026-11-02)

La compilación real ya está hecha: Ghidra 12.2 con JDK 25. La primera pasada de
`javac` encontró tres errores que el editor no veía (`address` no estático,
`DataType.getSource()` inexistente y un `catch` de `MemoryAccessException`
inalcanzable). Se corrigieron y `scripts/check-ghidra.ps1` reproduce el ciclo
completo en modo headless, así que el punto anterior queda resuelto: los scripts
se compilan y prueban contra una instalación real en cada cambio que los toque.
