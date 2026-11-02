# ADR-010: Capstone y detección recursiva de funciones

Estado: aceptado
Fecha: 2026-10-31

## Contexto
La Fase 1 (§16.3) exige integrar un desensamblador y detectar funciones básicas.
El proyecto no guarda el binario en `.dfproj` (ADR-009), así que el análisis debe
poder repetirse aportando el mismo archivo y comprobando su SHA-256. Las
arquitecturas objetivo son MIPS, PowerPC, ARM, ARM64 y x86/x86-64; Cell SPU
llegará en la Fase 10.

## Decisión
1. **Capstone 5** mediante el crate `capstone` 0.14 (`capstone-sys` 0.18), con
   `default-features = false` y solo `std`, `full`, `arch_mips`,
   `arch_powerpc`, `arch_arm`, `arch_arm64` y `arch_x86`. Menos código C que
   compilar y menos superficie de ataque.
2. El análisis no usa la base de datos directamente: `Image` traduce direcciones
   a bytes del archivo a partir de las secciones persistidas, y `Disassembler`
   clasifica cada instrucción en `Next`, `Call`, `Jump`, `CondJump`, `Return` o
   `Stop`.
3. **Detección recursiva**: las semillas son la entrada, los símbolos y funciones
   ya existentes, y el comienzo de cada región ejecutable. Se sigue el flujo
   lineal, las ramas condicionales y los saltos directos de la función; cada
   llamada directa a una dirección ejecutable se guarda en `xref(kind='call')`
   y se convierte en nueva semilla.
4. **Límites explícitos** (`AnalysisOptions`): 65 536 funciones y 5 000 000 de
   instrucciones por defecto. Al alcanzarlos, el resultado se marca `truncated`
   y se avisa; nunca se intenta analizar sin cota.
5. **Reanálisis seguro**: `Project::analyze` exige el mismo SHA-256 y hace
   *upsert* por `function.address`. Conserva `name`, `state` y `hash`; solo
   actualiza `size`/`updated_at` y regenera las aristas de llamada de cada
   función analizada.
6. **SPU se rechaza** con `Error::Unsupported` (código de salida 4). El cargador
   ELF acepta el archivo para inspección, pero Capstone no lo desensambla.
7. El CLI ejecuta el análisis al terminar `load` (`--no-analyze` lo omite) y
   ofrece `analyze <binario>` para repetirlo.

## Alternativas
- **Desensamblador propio**: más control, pero semanas de trabajo y riesgo alto
  de decodificar mal; Capstone es la opción del documento maestro.
- **iced-x86 + decoders por arquitectura**: excelente en x86, pero fragmenta el
  soporte y multiplica dependencias.
- **Ghidra headless desde el principio**: potente, pero ata la Fase 1 a Java y a
  un proceso externo; se reserva para la Fase 2 como adaptador.
- **Capstone con todas las arquitecturas**: compila y enlaza decodificadores que
  el proyecto no usa; se descartó por tiempo de compilación y superficie.

## Consecuencias
(+) Resultados deterministas y auditables; el mismo binario produce las mismas
funciones y llamadas. (+) No se pierde trabajo humano al reanalizar. (+) El
análisis es robusto ante secciones truncadas o flujos que salen de la región.

(-) El tamaño de función es la envolvente de las instrucciones alcanzadas: un
salto incondicional directo a una función anónima todavía no descubierta puede
unirla con su epílogo compartido. El *ownership* global, los bloques básicos y
los *delay slots* de MIPS se añadieron en [ADR-014](ADR-014-cfg-ownership-y-delay-slots.md).
(-) Capstone 5 no marca `jal`/`jr` en MIPS ni `bl`/`blr` en PowerPC con los
grupos genéricos, así que `disasm.rs` los reconoce por mnemónico.
