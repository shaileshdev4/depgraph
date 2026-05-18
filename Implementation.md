# DepGraph — Implementation Status

> **Reference:** [DEPGRAPH_BLUEPRINT.md](../DEPGRAPH_BLUEPRINT.md) (workspace root)  
> **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)  
> **Last updated:** May 18, 2026 (post React UI, live polling, spawn/route/deep-dive/remediation pass)  
> **Estimated completion:** ~**65–70%** of full blueprint — **end-to-end demo works**; several primitives are partial or compromised (see §8, §14)

---

## 0. Hackathon alignment

| Blueprint target | Status |
|------------------|--------|
| Event: JacHacks Spring 2026 | Active |
| Deadline: May 19, 2026 | Pending submission |
| Track: Agentic AI | Primary goal |
| Required: Jac + Featherless | **Wired** — spawn, route, extract, report LLM calls run when keys are set |
| Repo: `shaileshdev4/depgraph` | Live |

---

## 1. Solution pipeline — planned vs implemented

```
INPUT: GitHub repo URL
    ↓
[PIPE] Fetch manifest → parse → build graph (risk-filtered, cap 200)
    ↓
[EXTRACT] GitHub code search + LLM usage context (direct deps)
    ↓
[SPAWN] LLM/risk picks up to 8 subtree roots → SubtreeWalker each (sequential)
    ↓
Per package: [INVOKE] OSV/NVD  [ROUTE] next neighbor  [SPAWN] DeepDive if CVSS≥9
    ↓
[LOOP] RemediationWalker (schema + walker exist; rarely emits — see §6)
    ↓
[GENERATE] Executive summary (LLM) + findings + React graph
```

| Stage | Blueprint | Current | Status |
|-------|-----------|---------|--------|
| Input | GitHub URL or local path | GitHub URL only | **Partial** |
| Ingest | Multi-ecosystem | npm: `package-lock.json` (primary) or `package.json` fallback via GitHub raw/API | **Partial** |
| Graph build | Full transitive tree | `graph/builder.jac` + risk cap **200** packages (`risk_scorer.jac`) | **Done** (truncated on large repos) |
| Extract | AST → `UsageContext` | GitHub search paths + `extract_usage_context` LLM → `UsageContext` node | **Partial** (no AST; path heuristics + LLM) |
| Spawn | Parallel subtrees | LLM pool (Qwen2.5-7B) + risk fallback; **sequential** `spawn` | **Partial** |
| Invoke | CVE tools per node | `cve_lookup.jac` → OSV primary, NVD fallback | **Done** |
| Route | LLM next hop | Enriched prompt + CVSS fallback; requires **exactly one** index | **Partial** (works on juice-shop/CRA; still fails often) |
| DeepDive | On critical CVE | `DeepDiveWalker` spawned from `SubtreeWalker` when CVSS ≥ 9 | **Partial** (runs; not fed back into Route) |
| Loop | Remediation validation | `RemediationWalker` called; **no fixed versions from OSV** | **Mostly broken** |
| Generate | Report + graph | LLM summary + `investigation_complete` + React Flow canvas | **Done** |
| Live output | SSE / stream | In-memory session + **HTTP poll** every 500ms | **Partial** (not SSE) |

---

## 2. Repository file structure (important files only)

```
depgraph/
├── main.jac                          # API walkers + legacy jac-client UI (`to cl:`)
├── Implementation.md                 # This document
├── README.md                         # Setup (ports 8001 / 5173)
├── jac.toml                            # byllm / Featherless plugin config
├── .env / .env.example                 # FEATHERLESS_API_KEY, GITHUB_TOKEN, NVD_API_KEY
├── requirements.txt
│
├── graph/
│   ├── nodes.jac                       # InvestigationSession, Package, CVE, UsageContext, RemediationPlan
│   ├── edges.jac                       # DependsOn (typed; runtime often uses ++>)
│   ├── builder.jac                     # Lockfile → Package nodes + edges in session
│   └── snapshot_util.jac               # graph_snapshot payloads for frontend (severity, spawn roots)
│
├── walkers/
│   ├── dep_graph_agent.jac             # Main orchestrator (ingest → extract → spawn → subtrees → remediate → report)
│   ├── subtree_walker.jac              # OSV per visit, Route hop, DeepDive on critical
│   ├── route_util.jac                  # choose_neighbor_indexes (DeepSeek), select_spawn_root_index (Qwen)
│   ├── deep_dive_walker.jac            # Transitive OSV follow-up from critical package
│   ├── extract_walker.jac              # extract_usage_context (Qwen Coder) — used by agent, not separate walker spawn
│   ├── remediation_walker.jac          # remediation_plan events (needs fixed_version on CVEs)
│   └── report_util.jac                 # generate_executive_summary (DeepSeek)
│
├── models/
│   └── llm_config.jac                  # routing_llm, spawn_llm, code_llm (Featherless)
│
├── tools/
│   ├── github_api.jac                  # Lockfile/package.json fetch; search_github_package_imports
│   ├── lockfile_parser.jac             # npm lock v2/v3 + package.json; risk filter
│   ├── osv_api.jac                     # OSV query (primary); fixed_version always "" today
│   ├── nvd_api.jac                     # NVD fallback + cache
│   ├── cve_lookup.jac                  # Unified OSV → NVD
│   ├── risk_scorer.jac                 # Keyword/depth/direct scoring; top-N filter
│   ├── env_util.jac                    # Dotenv helpers
│   ├── jac_coerce.py                   # as_list / safe dict access from Jac
│   ├── session_store.py                # In-memory session events (poll buffer)
│   └── investigation_runner.py         # begin_async_investigation thread + poll_status
│
└── frontend/                           # Vite + React (primary demo UI)
    ├── vite.config.js                  # Port 5173; proxy /walker → :8001
    ├── package.json
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx                     # Router → Investigate page
        ├── api.js                      # startInvestigationAsync, pollInvestigation, envelope parsing
        ├── index.css
        ├── pages/
        │   └── Investigate.jsx         # Demo chips, poll loop, tabs (findings / summary / log)
        ├── components/
        │   ├── DependencyGraph.jsx     # React Flow + dagre layout, tooltips
        │   ├── graphNodes.jsx          # RootNode + PackageNode custom nodes
        │   ├── CVECard.jsx             # Finding cards (CVSS, deep-dive badge, fixed_version)
        │   ├── ExecutiveSummary.jsx    # Markdown summary
        │   ├── ActivityFeed.jsx        # Event log
        │   ├── StatsBar.jsx            # Scanned / vulnerable / route counts
        │   └── NodeTooltip.jsx         # Hover details on graph nodes
        └── utils/
            ├── eventProcessor.js       # applyEvent, normalizeFindings, stats, log formatting
            └── severity.js             # CVSS → severity colors
```

**Not listed:** `.venv/`, `.jac/` cache, `node_modules/`, compiled jac-client bundles.

---

## 3. Jac primitives (blueprint §5)

| Primitive | Blueprint role | Status | Where / honest notes |
|-----------|----------------|--------|----------------------|
| **Pipe** | Fetch → parse → graph | **Yes** | `github_api` → `lockfile_parser` → `builder` in `DepGraphAgent` |
| **Extract** | Usage / reachability | **Partial** | `extract_walker.jac` + GitHub path search; not true AST |
| **Invoke** | External CVE APIs | **Yes** | Deterministic `requests` in `osv_api` / `nvd_api` (not `by llm(tools=…)`) |
| **Route** | LLM picks next package | **Partial** | Richer prompt in `route_util.jac`; CVSS fallback in `subtree_walker.jac` |
| **Spawn** | Parallel subtrees + DeepDive | **Partial** | LLM spawn roots + risk pool; subtrees **sequential**; DeepDive on critical |
| **Loop** | Remediation until valid | **No (practical)** | Walker exists; OSV never sets `fixed_version` → plans rarely emit |
| **Generate** | Executive summary | **Yes** | `report_util.jac` + `investigation_complete` |

---

## 4. Graph model

### Nodes (`graph/nodes.jac`)

| Node | Runtime use |
|------|-------------|
| `InvestigationSession` | **Yes** — anchor per run |
| `Package` | **Yes** — lockfile graph |
| `CVE` | **Yes** — attached after OSV/NVD lookup |
| `UsageContext` | **Yes** — attached to direct deps after Extract LLM |
| `RemediationPlan` | **Schema only** — plans emitted as dict events, not this node type |

### Edges (`graph/edges.jac`)

| Edge | Status |
|------|--------|
| `DependsOn` | Declared; traversal uses generic `++>` from lockfile edges |

### Builder & snapshot

| Module | Role |
|--------|------|
| `graph/builder.jac` | Materialize `Package` nodes from parsed lockfile |
| `graph/snapshot_util.jac` | `graph_snapshot` / `spawn_roots` JSON for React (severity, `is_spawn_root`, depth) |

**Caps:** Large repos truncated to **200** packages via `filter_top_risk_packages` (not full lockfile on canvas).

---

## 5. Walkers (detailed)

### `DepGraphAgent` (`walkers/dep_graph_agent.jac`)

**Flow:**

1. `session_started` (+ `session_push` if `session_id` set).
2. Fetch manifest (`lockfile_fetched`, `manifest_parsed`, `graph_built`).
3. Emit initial `graph_snapshot` (all nodes, dep edges).
4. For each **direct** dep (`depth <= 1`): GitHub import search → `extract_usage_context` → `usage_context` event → attach `UsageContext`.
5. **Spawn selection:** Top-30 risk pool → iterative `select_spawn_root_index` (Qwen) with per-pick risk fallback → up to `max_direct_deps` (default 8).
6. `spawn_roots` + second `graph_snapshot` (spawn flags).
7. `spawn_chosen` (+ session push).
8. For each spawn target: `SubtreeWalker` **sequentially**; child events `report` + `session_push`.
9. Build `findings[]` from packages with CVEs (includes `deep_dive_triggered`, `fixed_version` from CVE nodes).
10. `RemediationWalker` per vulnerable package (usually no-op — see §6).
11. `report_generating` / `report_generated` / `investigation_complete` (+ session push).

**Compromise:** Investigation breadth is still bounded by **8 spawn roots** and **sequential** subtrees, not blueprint “one agent discovers everything in parallel.”

### `SubtreeWalker` (`walkers/subtree_walker.jac`)

- Per visit: `nvd_lookup` → OSV/NVD → attach `CVE` → `nvd_result`.
- If CVSS ≥ 9: spawn `DeepDiveWalker` on same package.
- Route: `choose_neighbor_indexes` with current package, CVSS, critical flag, neighbor CVSS hints.
- Accepts only **`len(raw_picks) == 1`** as LLM success; multi-index → `fallback_multi` then CVSS pick.
- Fallback: `pick_highest_cvss_neighbor_index` (improved from always `[0]`).
- Caps: `max_visits=5`, `depth_limit=3`.

### `DeepDiveWalker` (`walkers/deep_dive_walker.jac`)

- Spawned from subtree on critical finding.
- Walks transitive deps (depth/visit caps), extra OSV lookups, `deep_dive` / `deep_dive_finding` / `deep_dive_complete` events.
- **Gap:** Findings do not change next Route call (no `risk_signals` / `incl_info` loop).

### `RemediationWalker` (`walkers/remediation_walker.jac`)

- Emits `remediation_plan` (`from`, `to`, `confidence`, `status`) when CVEs have `fixed_version`.
- **Gap:** `osv_api.jac` sets `fixed_version: ""` for every CVE → walker almost always `disengage`s.
- **Gap:** `remediation_plan` not `session_push`ed (only `report`); frontend has no remediation panel.

### `route_util.jac`

| Function | Model | Purpose |
|----------|-------|---------|
| `choose_neighbor_indexes` | DeepSeek-V3 | Subtree next hop (enriched security prompt) |
| `select_spawn_root_index` | Qwen2.5-7B | One spawn root per call (reliable JSON on long lists) |

### `extract_walker.jac`

- `extract_usage_context(package_name, importing_files) -> dict` by LLM (Qwen2.5-Coder-32B).
- Used inline in agent (not spawned as separate walker graph).

### `report_util.jac`

- `generate_executive_summary` via DeepSeek-V3 from findings text.

### API entrypoints (`main.jac`)

| Walker | Purpose |
|--------|---------|
| `start_investigation` | Sync full run; optional `session_id` |
| `start_investigation_async` | Returns `session_created` immediately; background thread calls sync walker |
| `investigation_status` | Poll `{ events, status, next, total }` — **`can run`** (was `can poll`, caused long blocks) |

### Legacy UI (`main.jac` `to cl:`)

- Jac-client landing still compiled (~lines 61+): text log, findings string.
- **Primary demo UI** is `frontend/` (React), not `http://localhost:8000/cl/app`.

---

## 6. Tools & integrations

| File | Status | Notes |
|------|--------|-------|
| `tools/osv_api.jac` | **Done** | Primary CVE source; **does not parse patched versions** |
| `tools/nvd_api.jac` | **Done** | Fallback + cache |
| `tools/cve_lookup.jac` | **Done** | OSV then NVD |
| `tools/github_api.jac` | **Done** | Raw lockfile URL + API fallback; `package.json` fallback; code search for imports |
| `tools/lockfile_parser.jac` | **Done** | npm lock v2/v3 + shallow `package.json` |
| `tools/risk_scorer.jac` | **Done** | Scoring + top-N filter for graph and spawn pool |
| `tools/session_store.py` | **Done** | Thread-safe in-memory events |
| `tools/investigation_runner.py` | **Done** | Async thread; no duplicate append at end |
| `tools/env_util.jac` | **Done** | |
| `tools/jac_coerce.py` | **Done** | |

### Environment

| Variable | Purpose |
|----------|---------|
| `FEATHERLESS_API_KEY` | **Required** for spawn, route, extract, summary |
| `GITHUB_TOKEN` | Recommended (rate limits, code search) |
| `NVD_API_KEY` | Optional NVD fallback |

---

## 7. LLM / Featherless (`models/llm_config.jac`)

| Global | Model | Used for |
|--------|-------|----------|
| `spawn_llm` | `featherless_ai/Qwen/Qwen2.5-7B-Instruct` | Spawn root index (JSON) |
| `routing_llm` | `featherless_ai/deepseek-ai/DeepSeek-V3-0324` | Route + executive summary |
| `code_llm` | `featherless_ai/Qwen/Qwen2.5-Coder-32B-Instruct` | Usage context extract |

Provider prefix **`featherless_ai/`** required for LiteLLM. Calls are real when `.env` is set; quality varies by repo size and prompt.

---

## 8. Frontend (React + Vite)

**URL:** http://localhost:5173  
**API proxy:** `/walker/*` → http://127.0.0.1:8001 (`vite.config.js`)

### Implemented

| Feature | File(s) | Status |
|---------|---------|--------|
| Repo input + demo chips (juice-shop, drygate, CRA) | `Investigate.jsx` | **Done** |
| Async start + **500ms poll** | `api.js`, `Investigate.jsx` | **Done** |
| React Flow dependency graph | `DependencyGraph.jsx`, `graphNodes.jsx` | **Done** |
| Dagre layout, minimap, zoom/fit, visited-only toggle | `DependencyGraph.jsx` | **Done** |
| Node types: root (depth 0), package (severity colors) | `graphNodes.jsx` | **Done** |
| Edge styles: deps (gray), spawn (blue dashed), route (green), critical route (red) | `eventProcessor.js`, `DependencyGraph.jsx` | **Done** |
| Hover tooltip | `NodeTooltip.jsx` | **Done** |
| CVE findings panel | `CVECard.jsx` | **Done** |
| Executive summary (markdown) | `ExecutiveSummary.jsx` | **Done** |
| Activity log | `ActivityFeed.jsx`, `eventProcessor.js` | **Done** |
| Stats bar | `StatsBar.jsx` | **Done** |
| API envelope parsing (`data.reports`) | `api.js` | **Done** |

### Not implemented / partial

| Feature | Status |
|---------|--------|
| Dedicated **remediation** tab or plan cards | **No** — only `fixed_version` on CVE card if present |
| `usage_context` in UI | **No** — backend emits; log formatter doesn’t highlight |
| `WalkerNode` floating agent dot | **No** — investigating state = pulse on package node |
| True **SSE** | **No** — HTTP polling only |
| Graph >200 nodes | **No** — backend truncates; UI shows capped snapshot |
| Offline / sync-only mode button | **No** — always async path |

### Event handling (`eventProcessor.js`)

Handles: `graph_snapshot`, `spawn_roots`, `nvd_lookup`, `nvd_result`, `route_chosen`, `deep_dive`, `investigation_complete`.  
Does **not** mutate graph on: `usage_context`, `remediation_plan`, `spawn_chosen` (log only).

---

## 9. Live session architecture

```
Browser (5173)
  POST /walker/start_investigation_async  →  session_id
  loop: POST /walker/investigation_status { session_id, since }
         ← { events[], status, next }

Jac server (8001)
  start_investigation_async → begin_async_investigation() [Python thread]
    thread → POST /walker/start_investigation { session_id }
      DepGraphAgent → session_push() on key events

session_store.py (in-process memory)
  append_event / get_events
```

**Limitations:**

- Sessions are **in-memory** — lost on server restart.
- Jac dev server appears **single-request blocked** during long investigations (port 8001 timeouts observed if a sync run is in flight).
- Not all events are pushed (e.g. `remediation_plan`, manifest milestones).

---

## 10. Event protocol (reference)

| Event | Source | Frontend graph |
|-------|--------|----------------|
| `session_started` / `session_created` | Agent / async API | No |
| `lockfile_fetched`, `manifest_parsing`, `manifest_parsed`, `graph_built` | Agent | No |
| `graph_snapshot` | Agent | **Yes** — full nodes/edges |
| `usage_context` | Agent | No |
| `spawn_decision`, `spawn_chosen`, `spawn_roots`, `spawn_llm_*` | Agent | Spawn edges from root |
| `nvd_lookup`, `nvd_result` | Subtree | Node color / CVSS |
| `route_decision`, `route_chosen` | Subtree | Green/red route edges |
| `deep_dive`, `deep_dive_finding`, `deep_dive_complete` | DeepDive | Badge on findings |
| `remediation_plan` | Remediation | **Rarely emitted** |
| `report_generating`, `report_generated` | Agent | Summary tab |
| `investigation_complete` | Agent | Findings + stats |
| `error` | Any | Error banner |

---

## 11. Testing & verified demos

| Test | Result |
|------|--------|
| `jac check` on project sources | Passes when run on `main.jac graph tools walkers models` (not whole tree with `.venv`) |
| juice-shop | Spawn LLM + findings (axios, jsonwebtoken, etc.) |
| drygate | Graph 200 nodes; OSV clean or low on many paths |
| create-react-app | Spawn LLM picks; large graph truncated |
| React UI + poll | Works when backend on **8001** and not blocked |

---

## 12. Known limitations (honest)

1. **Not one autonomous agent** — spawn picks up to 8 roots; subtrees run sequentially with hard visit/depth caps.
2. **Graph truncation** — 200 package cap hides most of CRA-sized lockfiles.
3. **Route still fails often** — multi-index LLM output → fallback; `max_tokens=16` on route is tight.
4. **DeepDive doesn’t steer Route** — critical findings don’t change `choose_neighbor_indexes` inputs on next hop.
5. **Remediation non-functional in practice** — no OSV `fixed_version` parsing; no UI for plans.
6. **Extract is shallow** — GitHub search + LLM on paths, not AST/call graph.
7. **No true parallel Spawn** — Jac `spawn` subtrees one after another.
8. **Live session fragile** — in-memory; server blocking; no SSE.
9. **Two UIs** — legacy `to cl:` in `main.jac` vs React (React is the demo path).
10. **Invoke not LLM-mediated** — deterministic HTTP, not tool-calling agent pattern from blueprint.

---

## 13. What is compromised vs blueprint (summary)

| Area | What we shipped | What blueprint wanted |
|------|-----------------|------------------------|
| **Orchestration** | Risk-ranked spawn pool + 8 subtrees | Single walker; LLM-driven scope |
| **Route** | Separate `def by llm`; single-index enforcement | `visit by llm(incl_info=…)` with accumulated risk |
| **Spawn** | Qwen iterative picks (fixed empty-JSON issue) | Parallel spawn of all direct deps |
| **Extract** | Path list + LLM label | Full AST extract |
| **Loop** | Walker shell only | Validated upgrade loop with breaking-change checks |
| **Output** | React Flow + poll | SSE + full graph without cap |

**Pitch-safe wording:** *“LLM-assisted dependency investigation with risk-ranked spawn, OSV-driven traversal, critical-path deep dive, and a live graph UI — with deterministic fallbacks and demo caps.”*  
**Avoid claiming:** fully autonomous Ponita-style routing, working remediation loop, or complete lockfile coverage.

---

## 14. Route & spawn — technical honesty (updated)

### 14.1 Spawn (improved since May 18 AM)

**Files:** `dep_graph_agent.jac`, `route_util.jac`, `models/llm_config.jac`

- **Was:** Batch `select_spawn_root_indexes` → empty JSON on large repos (CRA).
- **Now:** Top-30 risk pool; **one index per LLM call** (`select_spawn_root_index`); Qwen2.5-7B; risk fallback per failed pick; `spawn_llm_partial` events.
- **Still compromised:** Max 8 roots; sequential subtrees; not parallel.

### 14.2 Route (improved but partial)

**Files:** `route_util.jac`, `subtree_walker.jac`

- **Improved:** Prompt includes current package, CVSS, critical flag, neighbor CVSS; fallback = highest-CVSS neighbor.
- **Still:** Only accepts exactly one LLM index; `max_tokens=16`; DeepDive findings not passed into next route call.
- **Modes observed:** `llm`, `fallback`, `fallback_multi`.

### 14.3 Architectural gap (unchanged in spirit)

The orchestrator still **pre-selects investigation targets** (spawn roots) before subtrees explore. The LLM does not decide global investigation strategy—only local next hops and spawn picks from a risk-trimmed pool.

---

## 15. What is next? (prioritized)

### P0 — Demo reliability

1. Parse OSV `affected` / ranges → populate `fixed_version` on CVE nodes.
2. `session_push` for `remediation_plan` + frontend remediation cards.
3. Ensure `jac start --dev --port 8001` doesn’t block poll during long runs (worker/process model).

### P1 — Blueprint fidelity

4. Feed `deep_dive` / `usage_context` into Route `incl_info`.
5. Optional true SSE endpoint.
6. Parallel subtree spawn where runtime allows.

### P2 — Polish

7. `usage_context` panel in UI.
8. Walker agent node on graph during `nvd_lookup`.
9. Remove or gate legacy `to cl:` UI to avoid confusion.

---

## 16. Quick reference commands

```powershell
cd "d:\Hackathons\Jac Hacks\depgraph"
.\.venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING = "utf-8"

# Type-check project sources only
jac check main.jac graph tools walkers models

# Backend (API for React)
jac start --dev --port 8001

# Frontend
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

Legacy Jac UI (if enabled by jac-client): http://localhost:8000/cl/app — **not** the primary graph demo.

---

*Update this file after each milestone. §13–§14 are the source of truth for hackathon pitch honesty.*
