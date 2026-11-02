# ai/ - Servicios de IA (Fases 3 y 4)

NameForge implementado en `ai/nameforge/` (Python 3.9+, solo biblioteca
estandar). Modo heuristico por defecto y proveedor OpenAI-compatible por
`urllib` con `--provider openai`.

## Uso como proveedor de la CLI de Rust

```sh
decompforge name <binario> --batch --config nameforge.json
```

con `nameforge.json`:

```json
{
  "style": {"case": "snake_case", "prefix": "", "banned": [], "max_length": 64},
  "provider": {"kind": "command", "argv": ["python", "-m", "nameforge"], "timeout_secs": 60}
}
```

Anade `ai/` a `PYTHONPATH` (o instala el paquete) para que `python -m nameforge`
resuelva el modulo. Tambien se puede invocar directamente:

```sh
PYTHONPATH=ai python -m nameforge < contexto.json
```

TypeForge, MatchLoop y DocForge siguen pendientes (Fases 4-8).

Principio: la IA propone, el sistema verifica (compilador + objdiff / emulador).
Plantillas de prompt: Documento Maestro secciones 10.3 y 10.4.