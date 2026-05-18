"""Post-process executive summary markdown from LLM output."""

from __future__ import annotations

import re


def sanitize_executive_summary(text: str) -> str:
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
