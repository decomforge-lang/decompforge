# adapters/ — Integraciones (Fase 2)

Integraciones con herramientas de ingeniería inversa sobre el documento JSON
`re-1.0` (`schemas/decompforge-re-1.0.schema.json`). Ninguna integración incluye
contenido de terceros ni elude protecciones.

| Adaptador | Estado | Qué aporta |
| --- | --- | --- |
| [`ghidra/`](ghidra/) | Scripts Java | Exporta funciones, instrucciones, comentarios, xrefs y tipos a JSON; importa nombres, firmas y comentarios. |
| [`python/`](python/) | Biblioteca + CLI | Valida, normaliza, fusiona parches y genera `updates` de forma determinista. |
| `ida/`, `binaryninja/`, `decompme/` | Pendiente | Se añadirán en fases posteriores. |

## Flujo de extremo a extremo

```sh
# 1. Proyecto y exportación desde DecompForge
decompforge init demo --sample
decompforge export --format re-json --project demo.dfproj --output export.json

# 2. Validar y preparar un parche
python -m decompforge_re validate export.json
python -m decompforge_re make-updates export.json -o updates.json

# 3. Editar updates.json (nombres, firmas, comentarios) y fusionarlo
python -m decompforge_re merge export.json updates.json -o merged.json

# 4. Aplicarlo al proyecto (todo o nada)
decompforge apply updates.json --project demo.dfproj

# 5. O importarlo en Ghidra con ImportDecompForge.java
#    (ver ghidra/README.md para el comando analyzeHeadless)
```

Los adaptadores no guardan el binario ni el proyecto `.dfproj`: solo
intercambian JSON. El SHA-256 y la base de datos siguen siendo responsabilidad
del núcleo Rust.

## Esquemas

- `schemas/decompforge-re-1.0.schema.json`: intercambio bidireccional de la
  Fase 2 (`kind: "export" | "updates"`).
- `schemas/decompforge-exchange-1.0.schema.json`: exportación de solo lectura
  de la Fase 1 (proyecto, secciones, funciones, símbolos). No se mezcla con
  `re-1.0`.
- `adapters/examples/`: ejemplos sintéticos mínimos usados por las pruebas.

## Pruebas

```sh
cd adapters/python
python -m unittest discover -s tests -t . -v
```

El trabajo de CI `adapters` valida los esquemas, ejecuta estas pruebas y realiza
un ciclo exportar → validar → hacer parche → aplicar con la CLI de Rust.
