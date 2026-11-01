# Política de uso aceptable

> Este documento es una guía de diseño del proyecto, **no asesoramiento jurídico**.
> Las leyes sobre ingeniería inversa, interoperabilidad y elusión de protecciones
> varían según el país. Consulta con un abogado de propiedad intelectual antes de
> publicar el proyecto o de dar soporte a títulos concretos
> (Documento Maestro, cap. 14).

## Principios

1. **El usuario aporta su propia copia legítima.** DecompForge no incluye ni
   distribuye juegos, firmware, claves, firmas, assets ni código original.
2. **No se implementa elusión de protecciones.** Si un archivo llega cifrado o
   firmado (p. ej. un SELF), la herramienta lo **rechaza** con un mensaje
   explicativo. El descifrado, cuando sea legal, queda fuera del proyecto.
3. **Pruebas solo con binarios sintéticos** creados por el propio proyecto
   (`decompforge_core::synthetic`) o con código de dominio público / licencia
   compatible. Nunca se incluyen juegos comerciales ni fragmentos de ellos.
4. **Los repositorios de proyectos** que usen la herramienta deben contener solo
   código y exigir que cada usuario aporte su propio binario (el `.gitignore` de
   este repositorio ya excluye las extensiones típicas).
5. **Transparencia:** se documenta qué hace y qué no hace la herramienta.

## Prohibido

- Distribuir contenido protegido sin autorización.
- Desarrollar trampas o ataques contra servicios en línea.
- Eludir protecciones de acceso o copia, DRM o firmas de consolas.

## Casos de uso que se favorecen

Preservación y archivo histórico; estudios que portan sus propios títulos;
interoperabilidad; investigación y docencia sobre arquitecturas y compiladores;
corrección de errores en juegos cuyo código fuente se perdió, con permiso o
titularidad.
