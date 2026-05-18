"""LLM routing — return exactly one neighbor index as JSON, e.g. [3]."""

import from models.llm_config { routing_llm, spawn_llm }

"""Security dependency investigator routing decision.
You are investigating a dependency graph for vulnerabilities.
Current package: {current_package} version {current_version}
Current package CVEs found: {cve_count} (max CVSS: {current_cvss})
Critical CVE found on current package: {has_critical}

Neighbors to choose from:
{neighbor_descriptions}

Return EXACTLY ONE index as JSON array.
Prioritize:
1. Packages with known CVE history (jwt, serialize, eval, xml, yaml, crypto)
2. Network/auth/crypto packages over utility packages
3. Older major versions (0.x, 1.x) over recent ones
4. Packages with many dependents

Example outputs: [3] or [0] or [7]
Never return more than one index."""
def choose_neighbor_indexes(
    current_package: str,
    current_version: str,
    cve_count: int,
    current_cvss: float,
    has_critical: bool,
    neighbor_descriptions: str
) -> list[int] by llm(
    model=routing_llm,
    temperature=0,
    max_tokens=16
);

"""Pick ONE direct dependency index from the numbered candidate list.
Return ONLY a JSON array with a single integer, e.g. [3] or [0].
Prioritize auth, jwt, crypto, parse, network, and serialize packages.
No prose, no markdown."""
def select_spawn_root_index(
    candidate_descriptions: str
) -> list[int] by llm(
    model=spawn_llm,
    temperature=0,
    max_tokens=256
);
