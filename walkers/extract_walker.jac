"""Extract primitive — classify package usage from import paths."""

import from models.llm_config { code_llm }

"""Analyze file paths that import this package.
Return JSON: {"risk_surface": "high|medium|low", "is_reachable_in_prod": true|false, "summary": "..."}
Production paths: src/, lib/, api/, server/. Test paths: test/, spec/, __tests__/."""
def extract_usage_context(
    package_name: str,
    importing_files: str
) -> dict by llm(
    model=code_llm,
    temperature=0,
    max_tokens=256
);
