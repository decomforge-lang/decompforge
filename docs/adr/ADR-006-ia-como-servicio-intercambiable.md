# ADR-006: IA como servicio intercambiable

Estado: aceptado
Fecha: 2026-10-29

## Contexto
Algunos usuarios quieren modelos en la nube; otros exigen que nada salga de su equipo (RNF-04).

## Decisión
Los servicios de IA usan una interfaz común de modelo con implementaciones en la nube y locales. Modo local por defecto; el usuario decide qué se envía y nunca se envía el binario completo. Toda salida de IA se valida contra un esquema y se verifica automáticamente.

## Alternativas
Depender de un único proveedor: riesgo de privacidad, coste y disponibilidad.

## Consecuencias
(+) Privacidad y flexibilidad de costes. (-) Hay que mantener una batería de evaluación (conjunto de oro) para comparar modelos.
