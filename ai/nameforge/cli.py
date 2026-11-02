"""Interfaz de linea de comandos del servicio NameForge."""

import argparse
import json
import os
import sys

from .heuristic import heuristic_suggest
from .provider import openai_suggest, validate_suggestions


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="NameForge: propuestas de nombres")
    parser.add_argument(
        "--provider",
        choices=["heuristic", "openai"],
        default=os.environ.get("NAMEFORGE_PROVIDER", "heuristic"),
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--fallback-heuristic", action="store_true")
    args = parser.parse_args(argv)

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: JSON invalido en stdin: {exc}", file=sys.stderr)
        return 1

    context = payload.get("context", {})
    style = payload.get("style", {}) or {}
    max_suggestions = int(payload.get("max_suggestions", 3))

    config = {
        "model": args.model,
        "base_url": args.base_url,
        "api_key": args.api_key,
        "timeout": args.timeout,
    }

    try:
        if args.provider == "heuristic":
            suggestions = heuristic_suggest(context, style)
        else:
            suggestions = openai_suggest(context, style, config)
    except Exception as exc:  # noqa: BLE001 - queremos informar y salir
        if args.fallback_heuristic and args.provider != "heuristic":
            suggestions = heuristic_suggest(context, style)
        else:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    valid = validate_suggestions(suggestions, style, max_suggestions)
    print(json.dumps({"suggestions": valid}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())