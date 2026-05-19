"""Ecosystem identifiers for DepGraph (user-facing) and OSV API names."""

from __future__ import annotations

# User selects these in the UI / walker parameter.
SUPPORTED_ECOSYSTEMS: tuple[str, ...] = ("npm", "pypi", "go", "maven", "auto")

# Maps DepGraph ecosystem key -> OSV.dev ecosystem string (case-sensitive).
OSV_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "maven": "Maven",
}

# Manifest files tried in order when fetching from GitHub (first hit wins).
MANIFEST_CANDIDATES: dict[str, list[tuple[str, str]]] = {
    "npm": [
        ("package-lock.json", "lockfile"),
        ("package.json", "package_json"),
    ],
    "pypi": [
        ("poetry.lock", "poetry_lock"),
        ("Pipfile.lock", "pipfile_lock"),
        ("pyproject.toml", "pyproject_toml"),
        ("requirements.txt", "requirements_txt"),
    ],
    "go": [
        ("go.mod", "go_mod"),
    ],
    "maven": [
        ("gradle.lockfile", "gradle_lockfile"),
        ("pom.xml", "pom_xml"),
    ],
}

# For auto-detect: try ecosystems in this order (most specific lockfiles first).
AUTO_DETECT_ORDER: tuple[str, ...] = ("npm", "pypi", "go", "maven")


def normalize_ecosystem(ecosystem: str) -> str:
    key = str(ecosystem or "npm").strip().lower()
    if key in SUPPORTED_ECOSYSTEMS:
        return key
    return "npm"


def osv_ecosystem_for(depgraph_ecosystem: str) -> str:
    eco = normalize_ecosystem(depgraph_ecosystem)
    if eco == "auto":
        return "npm"
    return OSV_ECOSYSTEM.get(eco, "npm")
