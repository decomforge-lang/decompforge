"""Errores del cliente de intercambio."""


class DecompForgeError(ValueError):
    """Error base del cliente `re-1.0`."""


class SchemaError(DecompForgeError):
    """El documento no cumple el esquema JSON."""


class DocumentError(DecompForgeError):
    """El documento es válido como JSON pero no es aplicable al proyecto."""


__all__ = ["DecompForgeError", "DocumentError", "SchemaError"]
