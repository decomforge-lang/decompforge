# ADR-001: Núcleo en Rust

Estado: aceptado
Fecha: 2026-10-29

## Contexto
El núcleo parsea binarios no confiables (potencialmente malformados o maliciosos) y debe manejar proyectos de cientos de miles de funciones.

## Decisión
El núcleo, los cargadores y el análisis se escriben en Rust (`core/`, `analysis/`).

## Alternativas
C++: más rendimiento marginal en algunos casos, pero mayor riesgo de fallos de memoria al tratar entradas hostiles. Todo en Python: demasiado lento para análisis y elevación.

## Consecuencias
(+) Seguridad de memoria; los cargadores no pueden provocar desbordamientos. (+) Buen ecosistema (rusqlite, serde). (-) Curva de aprendizaje; integración con Ghidra/LLVM requiere FFI o procesos externos. Verificado en Fase 1: 18 000 entradas mutadas (36 000 cargas) sin ningún *panic*.
