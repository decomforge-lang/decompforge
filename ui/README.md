# ui/ — Interfaz web de DecompForge

Panel web ligero (HTML + JavaScript) que envuelve la CLI `decompforge`.
No requiere Tauri ni toolchains pesados: se sirve con Node 24 y llama al
binario `target/debug/decompforge.exe` (o al de `PATH`).

## Uso

```sh
cd ui
node server.js
# abre http://localhost:8787
```

Variables de entorno opcionales:

- `DECOMPFORGE_BIN` — ruta al binario `decompforge` (por defecto busca en `../target/debug` y en `PATH`).
- `PORT` — puerto HTTP (por defecto 8787).

## Alcance

- Crear/cargar proyectos, analizar binarios, ver `info`.
- Ejecutar NameForge por lotes e interactivo, listar/aceptar/rechazar propuestas.
- Exportar `re-json` y aplicar `updates`.

La logica de negocio sigue viviendo en el nucleo Rust; esta UI solo orquesta
comandos y muestra resultados.