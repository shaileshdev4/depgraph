# DepGraph tools

Deterministic API helpers (NVD, GitHub, npm). Registered as `by llm(tools=[...])` targets — no LLM in this layer.

- `jac_coerce.py` — tiny Python `as_list()` so Jac can iterate `dict` payloads without `Any` narrowing issues in `jac check`.
