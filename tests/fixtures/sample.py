"""Inert AST fixture; the platform must never import or execute this file."""


def inspect_value(value: str) -> object:
    """Represent a call requiring manual source-to-sink investigation."""
    return eval(value)
