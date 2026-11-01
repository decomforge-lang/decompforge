# ADR-008: CLI con parser de argumentos propio en la Fase 1

Estado: aceptado
Fecha: 2026-10-29

## Contexto
La CLI de la Fase 1 tiene cuatro comandos. Un framework (clap) arrastra muchas dependencias transitivas y eleva la versión mínima de Rust.

## Decisión
Parser de argumentos mínimo y estricto (rechaza opciones desconocidas) en `cli/src/main.rs`.

## Alternativas
clap: más cómodo a largo plazo (autocompletado, ayuda generada).

## Consecuencias
(+) Superficie de dependencias reducida (RNF de seguridad de cadena de suministro). (-) Hay que migrar a clap cuando la CLI crezca (Fase 3+); está marcado en la bitácora.
