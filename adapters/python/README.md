# Adaptador Python — intercambio `re-1.0`

Cliente sin dependencias del núcleo Rust para los documentos JSON que produce
`decompforge export --format re-json` y consume `decompforge apply`.

Sirve para:

- validar documentos contra `schemas/decompforge-re-1.0.schema.json`;
- normalizar direcciones y ordenar listas para que la salida sea determinista;
- fusionar un parche `updates` sobre una exportación;
- generar un parche `updates` desde una exportación (para editar a mano o
  conservar el trabajo antes de reanalizar).

## Requisitos

- Python 3.9 o superior.
- `jsonschema` 4.18 o superior (`pip install jsonschema`).
- El esquema se busca en `DECOMPFORGE_RE_SCHEMA`, en la copia empaquetada o en
  `schemas/` del repositorio. Si el paquete se instala fuera del repositorio,
  define `DECOMPFORGE_RE_SCHEMA`.

## Instalación

```sh
cd adapters/python
python -m pip install -e .
```

También se puede usar sin instalar, añadiendo `adapters/python` a `PYTHONPATH`.

## CLI

```sh
# Validar (código 2 si el documento no cumple el esquema)
python -m decompforge_re validate export.json

# Aplicar un parche y escribir el resultado
python -m decompforge_re merge export.json updates.json -o merged.json

# Generar un parche desde una exportación
python -m decompforge_re make-updates export.json -o updates.json

# Solo algunas funciones; sin firmas ni comentarios
python -m decompforge_re make-updates export.json \
  --address 0x00100040 --no-signatures --no-comments -o updates.json
```

El parche generado se aplica al proyecto con la CLI de Rust:

```sh
decompforge apply updates.json --project demo.dfproj
```

## Biblioteca

```python
from decompforge_re import load, make_updates, merge_updates, save

base = load("export.json")
updates = make_updates(base, addresses=["0x00100040"])
merged = merge_updates(base, updates)
save(merged, "merged.json")
```

### Decisiones

- **Determinismo**: `dumps` ordena las claves del objeto (`sort_keys`) y
  `canonicalize` ordena funciones, instrucciones, comentarios, referencias y
  tipos por dirección/nombre. La salida siempre termina en `\n` y se escribe con
  UTF-8 y saltos `LF`.
- **Todo o nada**: `merge_updates` comprueba primero que todas las funciones del
  parche existan en la exportación. Si falta una, no devuelve nada.
- **Comentarios**: un comentario con la misma dirección que otro reemplaza al
  anterior, igual que `ON CONFLICT` en el núcleo.
- **Nombres de relleno**: `make_updates` omite por defecto los nombres
  `sub_<dirección>` que el núcleo usa cuando una función no tiene nombre. Así no
  se convierten en nombres reales al aplicar el parche. Usa
  `include_fallback_names=True` (o `--include-fallback-names`) si los quieres.
- **Esquema**: la validación es la misma que la del núcleo; no se reimplementa
  a mano.
- **BOM**: se acepta un BOM UTF-8 al inicio del documento (habitual al guardar
  desde algunos editores de Windows). La salida nunca escribe BOM.

## Pruebas

```sh
cd adapters/python
python -m unittest discover -s tests -t . -v
```

Las pruebas cubren ejemplos, direcciones de 32/64 bits, rechazo de documentos
inválidos, determinismo, fusión, generación de parches y la CLI. No necesitan
un binario ni contenido de terceros.

## Limitaciones conocidas

- El cliente no analiza binarios ni habla con SQLite: solo transforma JSON.
- No descarga ni ejecuta Ghidra; el adaptador de Ghidra está en
  `adapters/ghidra/`.
- El esquema `re-1.0` es la versión de intercambio de la Fase 2; el esquema de
  exportación del núcleo (`decompforge-exchange-1.0.schema.json`) es distinto y
  no se valida aquí.
