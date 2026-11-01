# ADR-005: LLVM IR como representación intermedia

Estado: aceptado
Fecha: 2026-10-29

## Contexto
La recompilación estática (PS3/PS4/Switch) necesita elevar varias arquitecturas (MIPS, PPC, ARM64, x86-64, SPU) y generar código para varios destinos.

## Decisión
Se usa LLVM IR como representación intermedia común (Fase 5).

## Alternativas
IR propia: mucho coste de mantenimiento y sin optimizador.

## Consecuencias
(+) Optimización y generación de código para x86-64 y ARM64 ya resueltas. (-) Dependencia de la API de LLVM (que cambia entre versiones): se fijará la versión y se aislará tras una interfaz.
