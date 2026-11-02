"""Proveedor OpenAI-compatible para NameForge (biblioteca estandar)."""

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List


SYSTEM_PROMPT = (
    "Eres NameForge, un asistente que propone nombres para funciones de "
    "ingenieria inversa. Responde SOLO con JSON valido con la forma "
    '{"suggestions": [{"name": str, "confidence": float, "reason": str}]}. '
    "Como mucho 3 propuestas. Cada nombre debe ser un identificador valido y "
    "cada justificacion debe ser breve y auditable. No inventes si no hay "
    "evidencia: devuelve una lista vacia."
)


def _extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def openai_suggest(context: Dict[str, Any], style: Dict[str, Any],
                   config: Dict[str, Any]) -> List[Dict[str, Any]]:
    api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("falta la clave de API (OPENAI_API_KEY o --api-key)")
    base_url = (config.get("base_url")
                or os.environ.get("OPENAI_BASE_URL")
                or "https://api.openai.com/v1")
    model = (config.get("model")
             or os.environ.get("OPENAI_MODEL")
             or "gpt-4o-mini")
    timeout = int(config.get("timeout", 60))

    user_prompt = (
        "Contexto de la funcion (JSON):\n" + json.dumps(context, ensure_ascii=False) + "\n\n"
        "Estilo configurado (JSON):\n" + json.dumps(style, ensure_ascii=False) + "\n\n"
        "Devuelve hasta 3 propuestas de nombre con confianza (0-1) y justificacion."
    )

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    url = base_url.rstrip("/") + "/chat/completions"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"el proveedor respondio {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"no se pudo contactar con el proveedor: {exc.reason}") from exc

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("respuesta del proveedor sin 'choices[0].message.content'") from exc
    parsed = _extract_json(content)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        suggestions = parsed.get("suggestions")
        if isinstance(suggestions, list):
            return suggestions
    raise RuntimeError("la respuesta del proveedor no contiene 'suggestions'")


def validate_suggestions(suggestions: List[Any], style: Dict[str, Any],
                         max_suggestions: int = 3) -> List[Dict[str, Any]]:
    """Valida y normaliza propuestas; equivalente a validate_suggestions de Rust."""
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from nameforge.heuristic import is_valid_identifier

    max_length = int(style.get("max_length", 64))
    banned = {str(b).lower() for b in (style.get("banned") or [])}
    valid: List[Dict[str, Any]] = []
    seen = set()
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        reason = str(item.get("reason", "")).strip()
        try:
            confidence = float(item.get("confidence"))
        except (TypeError, ValueError):
            continue
        if not is_valid_identifier(name, max_length):
            continue
        if name.lower() in banned:
            continue
        if confidence != confidence or confidence < 0.0 or confidence > 1.0:  # NaN check
            continue
        if not reason or any(ord(ch) < 0x20 for ch in reason) or len(reason) > 500:
            continue
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        valid.append({"name": name, "confidence": confidence, "reason": reason})
        if len(valid) >= max_suggestions:
            break
    return valid


def _package_dir() -> str:
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))