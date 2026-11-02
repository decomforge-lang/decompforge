"""Heuristica local determinista para NameForge."""

import re
from typing import Any, Dict, List, Optional

GENERIC = {
    "the", "and", "for", "with", "from", "this", "that", "true", "false",
    "null", "none", "error", "warning", "info", "debug", "http", "https",
    "www", "com", "org", "bin", "data", "text",
}


def split_words(value: str) -> List[str]:
    chars = list(value.strip())
    separated = []
    for i, ch in enumerate(chars):
        if ch.isalnum() and ch.isascii():
            if i > 0:
                prev = chars[i - 1]
                split = ch.isupper() and (
                    prev.islower()
                    or (prev.isupper() and i + 1 < len(chars) and chars[i + 1].islower())
                )
                if split:
                    separated.append(" ")
            separated.append(ch)
        else:
            separated.append(" ")
    words = []
    for part in "".join(separated).split():
        w = part.lower()
        if w and len(w) <= 24:
            words.append(w)
    return words[:4]


def is_valid_identifier(name: str, max_length: int) -> bool:
    if not name or len(name) > max_length:
        return False
    chars = list(name)
    first = chars[0]
    if not ((first.isalpha() and first.isascii()) or first == "_"):
        return False
    return all(((c.isalnum() and c.isascii()) or c == "_") for c in chars[1:])


def is_identifier_like(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    chars = list(value)
    first = chars[0]
    if not (first.isalpha() and first.isascii()) and first != "_":
        return False
    return all(c.isalnum() and c.isascii() or c == "_" for c in chars[1:])


def usable_words(value: str) -> Optional[List[str]]:
    value = value.strip()
    if len(value) < 4:
        return None
    if not all(c.isalnum() and c.isascii() or c in " _-" for c in value):
        return None
    if value.isdigit():
        return None
    words = split_words(value)
    if not words:
        return None
    if all(w in GENERIC for w in words):
        return None
    return words


def capitalize(word: str) -> str:
    if not word:
        return ""
    return word[0].upper() + word[1:]


def make_name(style: Dict[str, Any], words: List[str]) -> Optional[str]:
    all_words: List[str] = []
    prefix = (style.get("prefix") or "").strip()
    if prefix:
        all_words.extend(split_words(prefix))
    for w in words:
        w = w.strip().lower()
        if w and w.isascii() and w.isalnum():
            all_words.append(w)
    if not all_words:
        return None
    max_length = int(style.get("max_length", 64))
    banned = {str(b).lower() for b in (style.get("banned") or [])}
    case = style.get("case", "snake_case")

    while True:
        if case == "snake_case":
            name = "_".join(all_words)
        elif case == "camelCase":
            name = all_words[0] + "".join(capitalize(w) for w in all_words[1:])
        elif case == "PascalCase":
            name = "".join(capitalize(w) for w in all_words)
        else:
            name = "_".join(all_words)
        if len(name) <= max_length:
            if name.lower() in banned:
                return None
            return name
        if len(all_words) == 1:
            return None
        all_words.pop()


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    cut = limit
    while cut > 0 and not value[:cut].encode("utf-8", "replace"):
        cut -= 1
    return value[:cut] + "..."


def heuristic_suggest(context: Dict[str, Any], style: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    strings = context.get("strings") or []

    for identifier_only in (True, False):
        for entry in strings:
            if len(out) >= 3:
                break
            value = str(entry.get("value", ""))
            words = usable_words(value)
            if words is None:
                continue
            identifier_like = is_identifier_like(value)
            if identifier_like != identifier_only:
                continue
            name = make_name(style, words)
            if name is None:
                continue
            conf = 0.55 if identifier_like else 0.35
            out.append({
                "name": name,
                "confidence": conf,
                "reason": f"cadena cercana: {value[:80]}",
            })

    instructions = context.get("instructions") or []
    if len(out) < 3 and len(instructions) <= 6:
        named = [c for c in (context.get("callees") or []) if c.get("named")]
        if len(named) == 1:
            words = split_words(str(named[0].get("name", ""))) + ["wrapper"]
            name = make_name(style, words)
            if name is not None:
                out.append({
                    "name": name,
                    "confidence": 0.30,
                    "reason": f"funcion pequena que solo llama a {named[0].get('name')}",
                })

    # Deduplicar por nombre (sin distinguir mayusculas).
    seen = set()
    unique = []
    for s in out:
        key = str(s["name"]).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(s)
        if len(unique) == 3:
            break
    return unique