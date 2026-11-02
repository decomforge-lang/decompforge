# ADR-013: Imagen materializada para NSO con LZ4

Estado: aceptado
Fecha: 2026-11-02

## Contexto

Los ejecutables NSO0 de Nintendo Switch marcan en la cabecera qué segmentos
(`.text`, `.rodata`, `.data`) van comprimidos con LZ4. Cada segmento comprimido
es una secuencia de bloques:

```text
u32 compressed_size;
u32 decompressed_size;
[compressed_size bytes LZ4]
```

Hasta ahora el cargador solo leía la cabecera y el análisis veía los bytes
comprimidos: `Section::file_offset` apuntaba al archivo original y `Image`
traducía direcciones con esos offsets. Para analizar código real hay que
descomprimir, pero el proyecto no guarda el binario (ADR-009) y las secciones
persistidas deben seguir describiendo de dónde salen los bytes.

Restricciones:

- el SHA-256 que se verifica al reanalizar es el del archivo aportado, no el de
  una imagen derivada;
- `Image` debe seguir siendo una vista de solo lectura y no conocer LZ4;
- una cabecera maliciosa no puede provocar *panics* ni agotar la memoria
  (RNF-03);
- el resultado debe ser determinista (RNF-02).

## Decisión

Materializar una **imagen de análisis** para los NSO:

1. `loader::load` calcula, sin descomprimir, el offset de cada sección dentro
   de esa imagen. Los segmentos comprimidos se añaden al final del archivo en
   el orden `.text`, `.rodata`, `.data`; los que no están comprimidos o cuyo
   `compressed_size` no es menor que el tamaño original conservan su offset de
   archivo.
2. `loader::image_data(data, format)` devuelve `Cow::Borrowed` para el resto de
   formatos y `Cow::Owned` para un NSO con segmentos comprimidos. Para NSO sin
   compresión devuelve el propio archivo, sin copia.
3. `Project::analyze` guarda el formato en la consulta de estado y construye
   `Image` sobre `image_data`, no sobre el archivo crudo.
4. La descompresión es por bloques: se valida cada cabecera de bloque, no se
   aceptan más bytes de los declarados y se exige que el total coincida con el
   tamaño de la cabecera NSO. La imagen materializada se limita a 2 GiB y las
   reservas usan `try_reserve`.

Los `file_offset` exportados de un NSO comprimido se refieren a la imagen
materializada. Es una decisión consciente: el proyecto no guarda esa imagen, y
el campo describe de dónde lee el analizador, no una posición utilizable en el
archivo original.

## Alternativas

- **Descomprimir dentro de `Image`**: obliga a que el mapa de memoria conozca
  LZ4, complica `read`/`read_up_to` y mezcla formatos con análisis.
- **Guardar la imagen en el `.dfproj`**: rompe ADR-009 (el proyecto no guarda
  binarios), duplica el tamaño y hace que el SHA-256 deje de describir la
  fuente.
- **Reescribir el archivo temporalmente**: introduce estado fuera del proyecto,
  rutas temporales y problemas de limpieza; además impide analizar dos
  binarios en paralelo con el mismo nombre.
- **Descomprimir en el cargador y devolver bytes**: `LoadedBinary` contiene
  metadatos serializables; añadirle varios cientos de MiB de datos complica la
  API y las pruebas.

## Consecuencias

(+) `Image` y el análisis no cambian: siguen traduciendo dirección → offset.

(+) El SHA-256 sigue siendo el del archivo que aporta el usuario.

(+) Con NSO sin compresión no se copia nada; el coste solo aparece cuando hay
LZ4 de verdad, y el aviso lo dice.

(+) Los errores de LZ4 (bloque truncado, tamaños imposibles, suma distinta)
se convierten en `Error::Malformed`, nunca en *panic*.

(-) En un NSO comprimido el archivo y la imagen conviven en memoria durante el
análisis (archivo + segmentos descomprimidos).

(-) `Section::file_offset` deja de ser un offset del archivo original para NSO
comprimidos; hay que documentarlo en la API y en el JSON exportado.

(-) El límite de 2 GiB es una política del proyecto; un NSO legítimo mayor se
rechazará con un mensaje explícito.

Trabajo derivado: pruebas con NSO sintéticos (uno y varios bloques), corrupción
y truncamiento; documentación de la API y de la bitácora.
