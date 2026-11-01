# ADR-004: Contenedores para compiladores antiguos

Estado: aceptado
Fecha: 2026-10-29

## Contexto
El matching exacto exige el compilador original con opciones fijas; además ejecutar binarios y compiladores ajenos es un riesgo de seguridad.

## Decisión
Cada toolchain se empaqueta en una imagen de contenedor con versiones y hash fijados, sin red y con límites de recursos (`toolchains/`). Solo se automatiza la construcción de compiladores libres; los propietarios los aporta el usuario con su licencia.

## Alternativas
Instalación directa en el host: no reproducible ni aislada.

## Consecuencias
(+) Reproducibilidad (RNF-02) y aislamiento (RNF-03). (-) Requiere Docker; los compiladores propietarios no se pueden distribuir, lo que limita el "funciona a la primera" en algunos juegos de PS2.
