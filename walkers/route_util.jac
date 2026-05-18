"""LLM routing — return exactly one neighbor index as JSON, e.g. [3]."""

import from models.llm_config { routing_llm }

"""Security dependency investigator. Given the current package state and its
neighbors, return a JSON list with EXACTLY ONE integer index — the neighbor
most likely to contain vulnerabilities. Prefer packages with known CVE
history, network/auth/crypto roles over test or build-only utilities.
Examples: [3] or [0] or [7] — never more than one index."""
def choose_neighbor_indexes(
    current_package: str,
    current_cvss: float,
    cve_count: int,
    neighbor_descriptions: str
) -> list[int] by llm(
    model=routing_llm,
    temperature=0,
    max_tokens=64
);

"""Pick which direct dependency indexes get deep subtree investigation.
Return JSON array of indexes, e.g. [2, 7, 4, 38]. Up to 8 indexes.
Prioritize auth, crypto, network, parse, and packages with known CVE history."""
def select_spawn_root_indexes(
    candidate_descriptions: str,
    pick_count: int
) -> list[int] by llm(
    model=routing_llm,
    temperature=0,
    max_tokens=64
);
