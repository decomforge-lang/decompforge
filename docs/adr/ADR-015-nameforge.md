# ADR-015: NameForge — nombres con confianza y justificacion

Estado: aceptado
Fecha: 2026-11-02

## Contexto
La Fase 3 (RF-04) pide proponer hasta tres nombres por funcion con confianza
(0-1) y justificacion, aprender las convenciones del proyecto y registrar cada
propuesta aceptada o rechazada. El Documento Maestro (§7.3, §10.1-10.3) fija
que la IA propone y el sistema verifica, que el contexto debe ser rico pero
acotado, y que el proveedor debe ser intercambiable.

## Decisión
1. **Contexto acotado.** `nameforge::build_context` arma un paquete con la
   funcion (hasta 200 instrucciones), hasta 5 llamadores y 5 llamados, 16
   cadenas cercanas, 24 constantes y 5 ejemplos de estilo. Los topes son duros:
   un binario hostil no puede inflar el prompt ni la memoria.
2. **Proveedor intercambiable.** El trait `NameProvider` tiene dos
   implementaciones: `HeuristicProvider` (local, determinista, sin red) y un
   comando externo por `stdin`/`stdout` con el contrato `nameforge-1.0`.
   `NameForgeConfig` elige entre `heuristic` y `command { argv, timeout }`.
   El servicio Python opcional `ai/nameforge` implementa ambos modos con
   `urllib` (sin dependencias) y valida la salida antes de imprimirla.
3. **La IA no cambia nada.** Las propuestas se guardan en `ai_suggestion`
   (kind=`name`, status `pending`). Solo `accept_suggestion` aplica un nombre;
   aceptar sobre una funcion ya nombrada exige `--force`. Rechazar no toca el
   nombre.
4. **Validacion estricta.** `validate_suggestions` descarta nombres invalidos o
   vetados, confianzas fuera de [0,1], justificaciones vacias o con control o
   mayores de 500 caracteres, y duplicados. Devuelve los avisos para auditoria.
5. **Historial.** Aceptar/rechazar marca `status` y `decided_at`. Volver a
   proponer solo borra las propuestas `pending` de las funciones procesadas; las
   aceptadas y rechazadas alimentan la revision.
6. **Estilo configurable.** `StyleConfig` (case, prefix, banned, max_length) se
   carga desde un archivo JSON (`--config`) o se usa por defecto. `infer_case`
   deduce el estilo mayoritario de al menos dos nombres aprobados.
7. **Persistencia v4.** La migracion SQLite v4 amplia `ai_suggestion` con
   `reason`, `seq` y `decided_at`, y añade un indice por funcion y estado.
8. **CLI.** `name <binario> ...` (batch e interactivo), `name list`,
   `name accept <id>`, `name reject <id>` y `name config`.

## Alternativas
- **Proveedor siempre remoto.** Romperia el modo local y el principio de
  privacidad (§10.1). La heuristica es la linea base verificable.
- **Aplicar nombres automaticamente.** Contradice "la IA propone, el sistema
  verifica"; además impide la revision humana.
- **Editar el CFG o los nombres desde la base de datos.** Las propuestas son
  datos derivados; solo la CLI las aplica.
- **Contexto sin topes.** Un binario hostil podria inflar el prompt; los topes
  son parte de la seguridad.

## Consecuencias
(+) Propuestas auditable con justificacion y confianza. (+) Proveedor
intercambiable y modo local sin red. (+) Migracion v4 retrocompatible con v3.
(+) Cobertura del nucleo se mantiene por encima del 80 %.

(-) La heuristica es conservadora y devuelve lista vacia sin evidencia.
(-) El proveedor externo puede fallar o ser lento; el lote se detiene en ese
caso. (-) El estilo se configura por archivo, no se aprende automaticamente.
(-) Solo se ha probado con binarios sinteticos.