# ADR-009: Decisiones del modelo de proyecto en la Fase 1

Estado: aceptado
Fecha: 2026-10-29

## Contexto
El Documento Maestro (§9) da el esquema como lista de tablas con campos en español/inglés mezclados y un SQL de ejemplo en inglés.

## Decisión
(1) Un archivo = un proyecto (`project.id` fijado a 1 con CHECK). (2) Nombres de tablas y columnas en inglés, como en el SQL de ejemplo; `xref(src,dst,kind)` en lugar de origen/destino. (3) Se añaden a `project` las columnas `format`, `bits`, `entry`, `binary_sha256` y `binary_size` para trazabilidad. (4) `audit_log` es inmutable mediante triggers. (5) La exportación JSON es determinista: sin marcas de tiempo, claves y listas ordenadas. (6) Solo se admite un binario por proyecto.

## Alternativas
Varios binarios por proyecto (p. ej. módulos PRX/overlays): se pospone; requerirá una tabla `binary` y una migración v2.

## Consecuencias
(+) RNF-02 y RNF-08 cubiertos desde el primer día. (-) Los juegos con overlays necesitarán la migración v2.
