"""LLM routing — return exactly one neighbor index as JSON, e.g. [3]."""

import from models.llm_config { routing_llm, spawn_llm }

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
