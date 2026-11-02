"""Proveedores de IA para NameForge.

Soporta:
- OpenAI (y compatibles: Azure, Ollama, LM Studio, vLLM) via /chat/completions
- Anthropic (Claude) via /v1/messages
- Google Gemini via generateContent

Todos usan solo la biblioteca estandar de Python.
"""

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List

OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"
ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"
GEMINI_DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"

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


def _user_prompt(context, style):
    return (
        "Contexto de la funcion (JSON):\n" + json.dumps(context, ensure_ascii=False) + "\n\n"
        "Estilo configurado (JSON):\n" + json.dumps(style, ensure_ascii=False) + "\n\n"
        "Devuelve hasta 3 propuestas de nombre con confianza (0-1) y justificacion."
    )


def _http_post(url, headers, body, timeout):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"el proveedor respondio {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"no se pudo contactar con el proveedor: {exc.reason}") from exc


# ---------- OpenAI (y compatibles) ----------
def openai_suggest(context, style, config):
    api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("falta la clave de API (OPENAI_API_KEY o --api-key)")
    base_url = (config.get("base_url") or os.environ.get("OPENAI_BASE_URL") or OPENAI_DEFAULT_BASE)
    model = (config.get("model") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini")
    timeout = int(config.get("timeout", 60))
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(context, style)},
        ],
        "temperature": 0.2,
    }
    headers = {"Authorization": "Bearer " + api_key}
    # Soporte para headers extra (Azure, etc.)
    for k, v in (config.get("extra_headers") or {}).items():
        headers[k] = v
    payload = _http_post(base_url.rstrip("/") + "/chat/completions", headers, body, timeout)
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("respuesta sin 'choices[0].message.content'") from exc
    parsed = _extract_json(content)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        s = parsed.get("suggestions")
        if isinstance(s, list):
            return s
    raise RuntimeError("la respuesta no contiene 'suggestions'")


# ---------- Anthropic (Claude) ----------
def anthropic_suggest(context, style, config):
    api_key = config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("falta la clave de API (ANTHROPIC_API_KEY o --api-key)")
    base_url = (config.get("base_url") or os.environ.get("ANTHROPIC_BASE_URL") or ANTHROPIC_DEFAULT_BASE)
    model = (config.get("model") or os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-4-20250514")
    timeout = int(config.get("timeout", 60))
    body = {
        "model": model,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": _user_prompt(context, style)}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": config.get("anthropic_version", "2023-06-01"),
    }
    payload = _http_post(base_url.rstrip("/") + "/v1/messages", headers, body, timeout)
    try:
        content = payload["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("respuesta sin 'content[0].text'") from exc
    parsed = _extract_json(content)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        s = parsed.get("suggestions")
        if isinstance(s, list):
            return s
    raise RuntimeError("la respuesta no contiene 'suggestions'")


# ---------- Google Gemini ----------
def gemini_suggest(context, style, config):
    api_key = config.get("api_key") or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("falta la clave de API (GEMINI_API_KEY o --api-key)")
    base_url = (config.get("base_url") or os.environ.get("GEMINI_BASE_URL") or GEMINI_DEFAULT_BASE)
    model = (config.get("model") or os.environ.get("GEMINI_MODEL") or "gemini-2.0-flash")
    timeout = int(config.get("timeout", 60))
    url = base_url.rstrip("/") + f"/models/{model}:generateContent?key={api_key}"
    body = {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + _user_prompt(context, style)}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024},
    }
    payload = _http_post(url, {}, body, timeout)
    try:
        content = payload["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("respuesta sin 'candidates[0].content.parts[0].text'") from exc
    parsed = _extract_json(content)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        s = parsed.get("suggestions")
        if isinstance(s, list):
            return s
    raise RuntimeError("la respuesta no contiene 'suggestions'")


def validate_suggestions(suggestions, style, max_suggestions=3):
    """Valida y normaliza propuestas; equivalente a validate_suggestions de Rust."""
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from nameforge.heuristic import is_valid_identifier
    except Exception:
        from heuristic import is_valid_identifier

    max_length = int(style.get("max_length", 64))
    banned = {str(b).lower() for b in (style.get("banned") or [])}
    valid = []
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
        if confidence != confidence or confidence < 0.0 or confidence > 1.0:
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


PROVIDERS = {
    "openai": openai_suggest,
    "anthropic": anthropic_suggest,
    "gemini": gemini_suggest,
}


def suggest(context, style, config):
    provider = (config.get("provider") or "openai").lower()
    if provider not in PROVIDERS:
        raise RuntimeError(f"proveedor desconocido: {provider} (usa openai, anthropic o gemini)")
    return PROVIDERS[provider](context, style, config)