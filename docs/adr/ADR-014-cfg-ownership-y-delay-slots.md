# ADR-014: CFG, ownership de instrucciones y *delay slots* de MIPS

Estado: aceptado
Fecha: 2026-11-02

## Contexto
La detección recursiva de la Fase 1 identifica funciones por su punto de entrada y
mide su tamaño como la envolvente de las instrucciones alcanzadas (ADR-010). Ese
modelo tiene tres problemas que la Fase 5 no puede arrastrar:

1. Una misma instrucción puede alcanzarse desde dos funciones; sin un dueño
   explícito no se sabe a cuál pertenece el código compartido.
2. Un salto directo incondicional a una función anónima todavía no descubierta se
   sigue como si fuera parte de la función actual, uniendo dos cuerpos.
3. En MIPS, ramas, saltos, llamadas y retornos ejecutan antes la instrucción
   siguiente (*delay slot*). Al no incluirla, el tamaño quedaba corto y el hueco
   podía atribuirse a otra función.

Además, las fases posteriores (matching, elevación a LLVM IR y verificación)
necesitan bloques básicos y aristas tipadas, no solo una lista de funciones.

## Decisión
1. **Ownership único.** Cada instrucción pertenece como mucho a una función. El
   resultado expone `Analysis::owner(address)` y el proyecto responde con
   `Project::instruction_owner(address)`. Los huecos entre funciones no tienen
   dueño.
2. **Adjudicación atómica.** Durante la exploración de una función las
   instrucciones se guardan en un mapa local y solo se reclaman globalmente al
   terminar. Si se alcanza un límite (`truncated`), no quedan instrucciones
   reclamadas a medias.
3. **Corte por ownership.** El flujo se detiene al entrar en una instrucción que
   ya pertenece a otra función o en una semilla conocida. Un salto directo a otra
   función se modela como arista `tail_call`; una rama condicional hacia otra
   función registra la arista `branch` pero no se sigue.
4. **Bloques básicos.** Son líderes la entrada de la función, los destinos de
   rama, la instrucción siguiente a una llamada o rama condicional y el
   *fallthrough* tras un terminador. El bloque es `[start, end)` y guarda su
   función, su tamaño y su número de instrucciones.
5. **Aristas tipadas.** `EdgeKind` distingue `fallthrough`, `branch`, `jump`,
   `call` y `tail_call`. Los destinos que apuntan al interior de un bloque se
   normalizan a su líder.
6. **Delay slots MIPS.** `Instruction::delay_slot` marca ramas, saltos, llamadas
   y retornos de MIPS (excepto `syscall`, `break`, `eret` y `deret`). El hueco se
   decodifica como parte de la función, cuenta como instrucción, entra en la
   envolvente y pertenece al mismo bloque que la instrucción que transfiere el
   control. Si una rama apunta a un *delay slot*, el hueco se une a su bloque en
   vez de abrir uno nuevo.
7. **Persistencia derivada.** La migración SQLite v3 añade `basic_block` y
   `cfg_edge`. `Project::analyze` borra y regenera ambas tablas en cada análisis:
   son información derivada, nunca trabajo del usuario.
8. **Branch-likely.** Las variantes `beql`, `bnel`, etc. solo ejecutan el hueco
   cuando la rama se toma. Se tratan como ramas normales para no perder código
   alcanzable; es una sobreaproximación deliberada.

## Alternativas
- **Mantener solo la envolvente sin ownership.** Imposible saber qué función
  posee el código compartido; habría que resolverlo en cada fase posterior.
- **Reclamar instrucciones al vuelo.** Un límite o un error a mitad de función
  dejaría instrucciones huérfanas o duplicadas.
- **Un bloque por *delay slot*.** Contradice la semántica de MIPS: el hueco no es
  un punto de entrada independiente, y las aristas de la rama deben salir del
  bloque completo.
- **Modelar branch-likely con hueco condicional.** Exigiría un CFG sensible a
  caminos; se pospone hasta que haya verificación con emulador (Fase 7).
- **Persistir el CFG calculado por el usuario.** El CFG se deriva del binario; si
  se pudiera editar, el reanálisis lo descartaría y la base de datos mentiría.

## Consecuencias
(+) Reproducible y auditable: las mismas entradas producen el mismo CFG. (+) El
tamaño de las funciones MIPS incluye sus *delay slots* y cada instrucción tiene un
único dueño. (+) La CLI y `info` informan de bloques y aristas sin consultar las
tablas a mano. (+) El núcleo queda preparado para el matching y la elevación.

(-) Un salto directo a una función anónima aún no descubierta puede unirla con la
actual; no hay pre-pase de llamadas. (-) Las variantes branch-likely pueden
conservar código de más. (-) Los saltos indirectos y las tablas de salto terminan
el bloque sin aristas de destino (`Jump(None)`). (-) El CFG se regenera entero en
cada `analyze`; cualquier consumidor debe volver a leerlo. (-) Solo se ha probado
con binarios sintéticos, no con ejecutables reales.
