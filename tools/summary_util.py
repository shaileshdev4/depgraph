"""Executive summary sanitization (standalone — safe for Jac import from .jac files)."""

from __future__ import annotations

import re


def sanitize_executive_summary(text: str) -> str:
    """Strip broken mailto/markdown links for package names in LLM summaries."""
    if not text:
        return ""
    out = str(text)
    out = re.sub(
        r"\[([^\]]+)\]\(mailto:[^)]*\)",
        r"`\1`",
        out,
        flags=re.IGNORECASE,
    )
    out = re.sub(
        r"\[([^\]]+@[^\]]+)\]\([^)]*\)",
        r"`\1`",
        out,
    )
    return out
