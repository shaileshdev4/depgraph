# DepGraph — Implementation Status

> **Reference:** [DEPGRAPH_BLUEPRINT.md](../DEPGRAPH_BLUEPRINT.md) (workspace root)  
> **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)  
> **Last updated:** May 18, 2026 (post Route wiring + drygate E2E)  
> **Estimated completion:** ~50% of full blueprint — **MVP pipeline works; autonomous Route is partial and compromised**

---

## 0. Hackathon alignment (from blueprint §0)

| Blueprint target | Status |
|------------------|--------|
| Event: JacHacks Spring 2026 | Active |
| Deadline: May 19, 2026 | Pending submission |
| Track: Agentic AI ($600) | Primary goal |
| Required: Jac + Featherless | **Both wired** — Featherless calls succeed; routing quality is weak (see §14) |
| Repo: `shaileshdev4/depgraph` | Live |

---

## 1. Solution pipeline — planned vs implemented

Blueprint §4 flow:

```
INPUT: GitHub repo URL
    ↓
[PIPE] Parse manifest → Build dependency graph
    ↓
[SPAWN] Parallel SubtreeWalkers per direct dependency
    ↓
Per Package: [INVOKE] OSV/NVD  [EXTRACT] usage  [ROUTE] next node
    ↓
[LOOP] Remediation validation
    ↓
[GENERATE] Report + interactive graph
```

| Stage | Blueprint | Current implementation | Status |
|-------|-----------|------------------------|--------|
| Input | GitHub URL or local path | GitHub URL only (`main.jac`) | **Partial** |
| Ingest | Multiple ecosystems | `package-lock.json` via GitHub API only | **Partial** (npm v2/v3) |
| Graph build | Full transitive tree | `graph/builder.jac` — 274 pkgs / 373 edges on drygate | **Done** |
| Spawn | Parallel subtree per direct dep | `dep_graph_agent.jac` — up to **8** subtrees, **sequential** spawn | **Partial** |
| NVD / Invoke | Per-node CVE via tools | `tools/cve_lookup.jac` → OSV primary, NVD fallback | **Done** |
| Extract | AST → `UsageContext` | Schema only | **Not started** |
| Route | LLM picks next neighbor, zero if/else | **Wired but not autonomous** — see §14 | **Partial / compromised** |
| Spawn DeepDive | On critical CVE | Flag in reports only | **Not started** |
| Loop | Remediation | Schema only | **Not started** |
| Generate | Executive report | Event log + findings list | **Partial** |
| Output | Graph canvas + JSON | Single-page text log | **Partial** |

---

## 2. Jac primitives (blueprint §5) — scorecard

| Primitive | Blueprint role | Implemented? | Where / notes |
|-----------|----------------|--------------|---------------|
| **Pipe** | Fetch → parse → graph | **Yes** | `github_api` → `lockfile_parser` → `builder` in `DepGraphAgent` |
| **Extract** | AST → `UsageContext` | **No** | `graph/nodes.jac` only |
| **Invoke** | APIs as LLM tools | **Partial** | Deterministic `requests` in `osv_api.jac`, `nvd_api.jac` — not `by llm(tools=[...])` |
| **Route** | LLM picks next `Package` | **Partial** | `route_util.jac` + `subtree_walker.jac` — see §14 |
| **Spawn** | Parallel subtrees + DeepDive | **Partial** | `SubtreeWalker() spawn pkg_node`; no DeepDive; not parallel |
| **Loop** | Remediation until valid | **No** | — |
| **Generate** | Executive summary | **No** | — |

**Honestly demonstrated today:** Pipe, Invoke-like tooling (deterministic), Spawn (basic), Route (exists but weak).

---

## 3. Graph model (blueprint §7.1)

### Nodes (`graph/nodes.jac`)

| Node | Status | Notes |
|------|--------|-------|
| `InvestigationSession` | **Yes** | Per-run anchor |
| `Package` | **Mostly** | Fields exist; runtime mutation avoided |
| `CVE` | **Partial** | Attached via `Package ++> CVE`; missing some blueprint fields |
| `UsageContext` | **Schema only** | Never attached |
| `RemediationPlan` | **Schema only** | Never attached |

### Edges (`graph/edges.jac`)

| Edge | Used? |
|------|-------|
| `DependsOn` | **Yes** — lockfile edges |
| `HasCVE` / others | Declared; traversal uses `++>` not typed edges |

### Builder (`graph/builder.jac`)

- drygate: **274 packages**, **373 edges** — verified.

---

## 4. Walkers (blueprint §7.3)

| Walker | File | Status |
|--------|------|--------|
| `DepGraphAgent` | `walkers/dep_graph_agent.jac` | **MVP** — ingest, graph, spawn subtrees, findings |
| `SubtreeWalker` | `walkers/subtree_walker.jac` | **Partial** — OSV per visit + Route hop; capped |
| `choose_neighbor_indexes` | `walkers/route_util.jac` | **Partial** — `by llm` returns `list[int]` |
| `DeepDiveWalker` | — | **Not created** |
| `RemediationWalker` | — | **Not created** |
| `ReportWalker` | — | **Not created** |
| `start_investigation` | `main.jac` | **Done** |

### `DepGraphAgent` behavior (current)

1. `InvestigationSession` + fetch lockfile + build graph.
2. **Pre-spawns up to 8 `SubtreeWalker`s** on direct deps (`is_direct`, `depth <= 1`) — **before any LLM routing at orchestrator level**.
3. Merges child `reports`; counts `nvd_lookup` for `packages_scanned`.
4. `investigation_complete` with `findings[]`, `subtrees_spawned`, `packages_scanned`.

### `SubtreeWalker` behavior (current)

1. On each `Package` entry (up to `max_visits=5`, `depth_limit=3`):
   - OSV lookup via `lookup_package_cves` → attach `CVE` nodes → `nvd_result` report.
   - Build indexed neighbor list from `[here-->][?:Package]`.
   - Call `choose_neighbor_indexes(descriptions)` → cap to **first valid index** → `visit` one neighbor.
2. On LLM failure: `indexes: [0]`, `mode: fallback`.

### Event protocol

| Event | Meaning |
|-------|---------|
| `session_started` | Run began |
| `lockfile_fetched` / `graph_built` | Ingest OK |
| `nvd_lookup` / `nvd_result` | Per-package OSV (source field: `osv` / `nvd`) |
| `route_decision` | About to call LLM for next hop |
| `route_chosen` | `mode`: `llm` or `fallback`; `indexes`, `targets` |
| `subtrees_spawned` | How many parallel walkers started |
| `investigation_complete` | `packages_scanned` = OSV lookup count; `subtrees_spawned` = walker count |

---

## 5. Tools & integrations

| Tool | File | Status |
|------|------|--------|
| OSV npm | `tools/osv_api.jac` | **Done** (primary) |
| Unified lookup | `tools/cve_lookup.jac` | **Done** |
| NVD | `tools/nvd_api.jac` | **Done** + cache |
| GitHub lockfile | `tools/github_api.jac` | **Done** |
| Lockfile parser | `tools/lockfile_parser.jac` | **Done** v2/v3 |
| Env | `tools/env_util.jac` | **Done** |
| Coerce | `tools/jac_coerce.py` | **Done** |

### Environment

| Variable | Purpose |
|----------|---------|
| `FEATHERLESS_API_KEY` | **Required** for Route |
| `GITHUB_TOKEN` | Rate limits |
| `NVD_API_KEY` | Optional NVD fallback |

---

## 6. LLM / Featherless

| Item | File | Status |
|------|------|--------|
| `routing_llm`, `code_llm` | `models/llm_config.jac` | **Configured** — `featherless_ai/` prefix, `api_base` |
| Default model | `jac.toml` `[plugins.byllm.model]` | DeepSeek-V3-0324 |
| Route function | `walkers/route_util.jac` | `def choose_neighbor_indexes(...) -> list[int] by llm(model=routing_llm)` |
| Route consumer | `walkers/subtree_walker.jac` | Lines 90–137 |

**Featherless integration is real** (LiteLLM logs show successful completion). **Routing intelligence is not** — see §14.

---

## 7. Frontend (`main.jac` → `to cl:`)

| Feature | Status |
|---------|--------|
| Repo input + Investigate | **Done** |
| Activity log | **Done** — all report events |
| Vulnerable packages panel | **Done** |
| Live WebSocket / graph canvas | **Not built** |

### Client pitfalls (fixed)

- No `as_list()` or Python `.get()` in `to cl:` blocks.
- Parse `result["reports"]` from spawn envelope.

**Dev:** UI `http://localhost:8000/cl/app`, API `http://localhost:8001`.

---

## 8. Repository layout

```
depgraph/
├── main.jac
├── walkers/
│   ├── dep_graph_agent.jac   ✅ orchestrator (architectural compromise)
│   ├── subtree_walker.jac    ✅ OSV + Route hops
│   └── route_util.jac        ✅ by llm index picker (thin prompt)
├── models/llm_config.jac       ✅ Featherless models
├── tools/                      ✅ osv, nvd, github, lockfile, cve_lookup
├── graph/                      ✅ nodes, edges, builder
└── deep_dive / remediation / report walkers  ❌
```

---

## 9. Testing & verification (May 18)

| Test | Result |
|------|--------|
| `jac check main.jac graph tools walkers models` | **Passes** |
| `shaileshdev4/drygate` E2E | **HTTP 200** — 0 CVEs (OSV clean), Route events fire |
| Route on drygate root | LLM returned `[0..13]` once → **capped to first index** |
| Many `route_chosen: fallback` | LLM parse fail or empty → index `0` |

---

## 10. Known limitations (honest)

1. **Not one autonomous agent** — 8 pre-spawned subtrees scan breadth; LLM only routes inside each subtree.
2. **Route prompt is thin** — neighbor names only; no CVSS, no “pick one”, no usage context (§14).
3. **Fallback is dumb** — always `[0]`, not BFS or highest-CVSS (blueprint §16 suggested BFS).
4. **Hard caps** — `max_direct_deps=8`, `max_visits=5`, `depth_limit=3`.
5. **No DeepDive** — critical CVE does not spawn deeper analysis.
6. **No graph viz / live stream** — text log only.
7. **Sequential spawn** — not parallel `Spawn` demo.

---

## 11. Risk mitigation (blueprint §16)

| Risk | Blueprint | Current |
|------|-----------|---------|
| NVD rate limit | Key + cache | **Done** |
| LLM bad routing | BFS fallback | **Index `[0]` fallback** — weaker than BFS |
| Walker too slow | depth/time limits | **Aggressive caps** for demo |
| Demo failure | Deterministic core | OSV path is reliable |

---

## 12. What is next? (prioritized)

### P0 — Make Route credible (2–4 h)

1. **Richer Route prompt** — pass `current_package`, `max_cvss`, `cve_count`, instruction; use `incl_info` or expand `choose_neighbor_indexes` inputs.
2. **CVSS-aware fallback** — if LLM fails, pick neighbor with highest known CVSS (or first unvisited), not always index 0.
3. **Single-root mode (optional flag)** — one `SubtreeWalker` from app root; LLM routes entire investigation (matches blueprint narrative).
4. **Few-shot examples** in `route_util.jac` for `[3]` style outputs.

### P1 — Hackathon polish

5. DeepDiveWalker stub on `critical: true`.
6. ReportWalker + `routing_llm` summary.
7. WebSocket/SSE live log.
8. Demo repo with known CVEs in lockfile.

### P2 — Post-hackathon

9. Remediation Loop, AST Extract, graph canvas, true parallel spawn.

---

## 13. Quick reference commands

```bash
cd "/d/Hackathons/Jac Hacks/depgraph"
source .venv/Scripts/activate
export PYTHONIOENCODING=utf-8
jac check main.jac graph tools walkers models
jac start --dev
# UI: http://localhost:8000/cl/app
```

---

## 14. Why Route is NOT truly autonomous (detailed, honest)

Blueprint definition (§5, §7.3, Ponita/Sanjay criteria):

- **One walker** discovers the graph; at each node the **LLM decides the next hop** from accumulated risk (CVSS, usage, critical findings).
- **`visit [-->] by llm(incl_info={...})`** — zero if/else in routing; path changes based on what was found.
- **Spawn DeepDive** when critical CVE found — investigation deepens autonomously.

What we built instead is a **hybrid**: deterministic breadth at the top + weak LLM hops below. That is **not** the same as blueprint autonomy.

---

### 14.1 Architectural issue (biggest) — `dep_graph_agent.jac`

**File:** `walkers/dep_graph_agent.jac` lines **69–87**

```jac
for pkg_node in [session-->][?:Package] {
    if pkg_node.is_direct and pkg_node.depth <= 1 {
        if spawned >= self.max_direct_deps { break; }
        subtree = SubtreeWalker(...) spawn pkg_node;
        ...
    }
}
```

**Exact issue:** The orchestrator **pre-decides** to investigate up to **8 direct dependencies** before any LLM sees the graph. The LLM never chooses *which direct deps matter* — we take the first 8 in graph iteration order.

**Blueprint expected:** Start from one entry (or session root), Route picks which subtree to enter, Spawn specialists when critical findings appear.

**Compromise:** We traded “autonomous path selection” for “demo coverage” (scan multiple top-level deps quickly).

---

### 14.2 Prompt / context issue — `route_util.jac`

**File:** `walkers/route_util.jac` (entire file, ~10 lines)

```jac
def choose_neighbor_indexes(neighbor_descriptions: str) -> list[int] by llm(
    model=routing_llm,
    temperature=0,
    max_tokens=16
);
```

**Exact issues:**

| Gap | Detail |
|-----|--------|
| **Input is only neighbor list text** | Built in `subtree_walker.jac` lines 73–79 as `0) pkg@ver\n1) ...` — no current package name, no OSV results, no CVSS, no “pick exactly one index”. |
| **No `incl_info`** | Blueprint `visit by llm` used `incl_info={ current_package, current_cvss, accumulated_risk, instruction }`. We dropped all of that when we moved off `visit ... by llm` to a standalone `def`. |
| **`max_tokens=16`** | Very tight; may truncate or produce malformed JSON on larger neighbor lists. |
| **byllm auto-prompt** | `by llm` on `def` generates prompt from function docstring + type hints. Our function has **no per-parameter semantic descriptions** (Jac disallows `[3]` in quoted types — parser breaks). So the model gets minimal guidance. |

**Observed LLM behavior (drygate terminal, May 18):**

```
route_chosen: mode=llm, indexes=[0,1,2,...,13], targets=all 14 direct deps
```

The model did **not** understand “return one index”. It listed every neighbor. We **cap to first index** in `subtree_walker.jac` lines 106–118 — so we **discard** any ranking the model might have intended.

---

### 14.3 Consumer / fallback issue — `subtree_walker.jac`

**File:** `walkers/subtree_walker.jac`

| Lines | Issue |
|-------|--------|
| **67** | `neighbor_list = [here-->][?:Package]` — all outgoing package edges (can be large; not “direct deps only”). |
| **90–104** | `try/except` + empty check → `pick_indexes = [0]`, `mode = fallback`. |
| **106–118** | Cap LLM output to **first valid index only** — necessary hack after model returns full range; **not** blueprint Route. |
| **10–11** | `max_visits=5`, `depth_limit=3` — hard stop; agent cannot explore deep chains. |

**Exact issue on fallback:** When LLM fails (common on single-neighbor nodes in drygate log: `ansi-styles`, `color-convert`, `anymatch`, `asn1`), we always pick **index 0**. That is **not** risk-based and **not** BFS. Blueprint §16 said “if Route returns empty, default to BFS” — we did not implement BFS.

---

### 14.4 Missing feedback loop — no `DeepDiveWalker`, no `risk_signals`

**Files missing:** `walkers/deep_dive_walker.jac`, usage in `subtree_walker.jac`

**Blueprint** (`DEPGRAPH_BLUEPRINT.md` ~337–344): On `cvss >= 9.0`, spawn `DeepDiveWalker` and accumulate `risk_signals` for Route.

**Exact issue:** `subtree_walker.jac` sets `has_critical = True` in reports but **never** changes routing inputs. The LLM on the next hop still only sees neighbor names — it cannot “prioritize the critical subtree” because we never pass that signal.

---

### 14.5 Original `visit by llm` failure (why we changed approach)

**Previous code (removed):** `visit [-->][?:Package] by llm(model=routing_llm, incl_info={...})`

**Failure:** `OutputConversionError: Failed to convert LLM output to 'list'` — DeepSeek returned prose/markdown instead of JSON `[0]`.

**Fix path:** Explicit `def choose_neighbor_indexes -> list[int] by llm` + try/catch + cap.

**Tradeoff:** We fixed **reliability** but lost **`filter_visitable_by`’s built-in docstring** (“return indexes in priority order”) and **`incl_info`** from the visit site unless we re-add it to the `def` call.

Reference implementation: `jaseci/jac/jaclang/jac0core/impl/runtime.impl.jac` `JacByLLM.filter_visitable_by` — expects `list[int]` JSON indexes over `_describe_nodes_list` output.

---

### 14.6 Config files (not the blocker)

| File | Role | Autonomy impact |
|------|------|-----------------|
| `models/llm_config.jac` | `routing_llm` Model + `call_params` | **OK** — API works |
| `jac.toml` | `featherless_ai/...`, `api_base` | **OK** — was broken with `featherless/` prefix; fixed |
| `.env` | `FEATHERLESS_API_KEY` | **OK** if set |

**LLM calls do run.** The problem is **what we send** and **what we do with the response**, not Featherless connectivity.

---

### 14.7 Summary table — file → responsibility → exact gap

| File | Responsibility | Why it blocks “autonomous” |
|------|----------------|---------------------------|
| `dep_graph_agent.jac` | Orchestration | Spawns 8 subtrees upfront; LLM does not choose investigation scope |
| `route_util.jac` | Route LLM call | No risk context, no “one index” instruction, tiny token budget |
| `subtree_walker.jac` | OSV + Route hop | Caps multi-index to first; dumb `[0]` fallback; visit/depth caps |
| `models/llm_config.jac` | Model config | Fine — not the issue |
| `main.jac` | UI | Displays events; does not affect autonomy |
| *missing* `deep_dive_walker.jac` | Critical-path depth | No spawn-on-critical; Route has no exploitability signal |
| *missing* `usage` / Extract | Auth vs build-time | Cannot prioritize “qs in route handler” story |

---

### 14.8 What “autonomous” would require (minimal credible fix)

1. **Orchestrator:** Either single `SubtreeWalker` from session root **or** LLM picks which direct deps get a subtree (not first-8 loop).
2. **`route_util.jac`:** Add parameters: `current_name`, `current_cvss`, `cve_summary`, `instruction`; add `incl_info` few-shots `[[0], [2], [1]]`; raise `max_tokens` to ~64.
3. **`subtree_walker.jac`:** On fallback, pick unvisited neighbor with max CVSS (or BFS queue), not `[0]`.
4. **On critical:** `DeepDiveWalker spawn here` and append to `risk_signals` passed into next Route call.
5. **Optional:** Restore `visit ... by llm` once prompt/schema stable, with same `incl_info` as blueprint.

Until (1)–(3) are done, **do not claim full autonomous Route in the pitch** — say “LLM-assisted traversal with deterministic fallbacks and parallel subtree scans.”

---

*Update this document after each milestone. Section §14 is the source of truth for Route honesty.*
