# ADR-003: SQLite como formato de proyecto

Estado: aceptado
Fecha: 2026-10-29

## Contexto
El proyecto debe ser transaccional, fácil de compartir y versionar, y funcionar sin conexión.

## Decisión
Un proyecto es un único archivo SQLite (`.dfproj`). La versión del esquema vive en `PRAGMA user_version` y se aplican migraciones al abrir. Para colaboración (Fase 9) se sincronizará con PostgreSQL.

## Alternativas
JSON plano: no escala a 200 000 funciones ni es transaccional.

## Consecuencias
(+) Un archivo, ACID, consultas SQL. (+) Migraciones controladas; un proyecto de una versión más nueva se rechaza. (-) Los `.dfproj` son binarios: para revisar cambios se usa la exportación JSON determinista.
