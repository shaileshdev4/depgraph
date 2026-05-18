"""Executive summary generation for investigation results."""

import from models.llm_config { routing_llm }

def generate_executive_summary(
    repo_url: str,
    findings_text: str,
    packages_scanned: int,
    vulnerable_count: int
) -> str by llm(
    model=routing_llm,
    temperature=0.2,
    max_tokens=256
);
