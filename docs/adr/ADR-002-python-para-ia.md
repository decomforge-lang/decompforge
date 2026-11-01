# ADR-002: Python para IA y scripts

Estado: aceptado
Fecha: 2026-10-29

## Contexto
Los servicios de IA (NameForge, MatchLoop...) dependen de SDKs de modelos y librerías de análisis que viven principalmente en Python.

## Decisión
Los servicios de IA y la automatización se escriben en Python 3.12 (`ai/`) y hablan con el núcleo mediante el formato de intercambio JSON y la CLI.

## Alternativas
Todo en Rust: menos librerías de IA y más fricción de prototipado.

## Consecuencias
(+) Velocidad de prototipado. (-) Dos lenguajes que mantener; la frontera debe estar bien definida por el esquema JSON (`schemas/`).
