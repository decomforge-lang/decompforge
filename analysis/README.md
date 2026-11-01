# analysis/ — Análisis y elevación (Fase 5)

CFG, detección de bibliotecas, elevación a LLVM IR y portability linter.
**Aún sin implementar.** Ver Documento Maestro §7.2, §7.9.

El desensamblado básico y la detección recursiva de funciones de la Fase 1
viven en `core/src/analysis/` (Capstone + `Image` + semillas y límites). Esta
carpeta queda reservada para el análisis de mayor nivel de la Fase 5. Ver
`docs/adr/ADR-010-capstone-y-deteccion-de-funciones.md`.
