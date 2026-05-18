"""Helpers for Jac ↔ dict interop (typed list coercion)."""


def as_list(value: object) -> list:
    return value if isinstance(value, list) else []
