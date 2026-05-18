# DepGraph — Implementation Status

> **Reference:** [DEPGRAPH_BLUEPRINT.md](../DEPGRAPH_BLUEPRINT.md) (workspace root)  
> **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)  
> **Last updated:** May 18, 2026  
> **Estimated completion:** ~40–45% of full blueprint (MVP pipeline + single-page UI working)

---

## 0. Hackathon alignment (from blueprint §0)

| Blueprint target | Status |
|------------------|--------|
| Event: JacHacks Spring 2026 | Active |
| Deadline: May 19, 2026 | Pending submission |
| Track: Agentic AI ($600) | Primary goal |
| Required: Jac + Featherless | Jac core done; Featherless **configured, not wired into walkers yet** |
| Repo: `shaileshdev4/depgraph` | Live; git history cleaned (single contributor) |

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
Per Package: [INVOKE] NVD  [EXTRACT] usage  [ROUTE] next node
    ↓
[LOOP] Remediation validation
    ↓
[GENERATE] Report + interactive graph
```

| Stage | Blueprint | Current implementation | Status |
|-------|-----------|------------------------|--------|
| Input | GitHub URL or local path | GitHub URL only (`main.jac` input) | **Partial** |
| Ingest | `package.json`, `requirements.txt`, `pom.xml`, `Cargo.toml` | `package-lock.json` via GitHub Contents API only | **Partial** (npm lockfile v2/v3) |
| Graph build | Full transitive tree | `graph/builder.jac` — all packages + `DependsOn` edges under `InvestigationSession` | **Done** |
| Spawn | Parallel subtree per direct dep | `DepGraphAgent` spawns `SubtreeWalker` on direct deps (`depth <= 1`), cap **8** (`max_direct_deps`) | **Partial** (sequential spawn, capped) |
| NVD / Invoke | Per-node CVE lookup via tools | `tools/nvd_api.jac` — deterministic REST (not `by llm` + tools) | **Done** (simplified Invoke) |
| Extract | AST → `UsageContext` | Node type defined; **no walker or parser** | **Not started** |
| Route | LLM picks next neighbor, no if/else | **Not implemented** | **Not started** |
| Spawn DeepDive | On critical CVE | Critical flag in reports only; **no `DeepDiveWalker`** | **Not started** |
| Loop | Remediation conflict check | `RemediationPlan` node exists; **no `RemediationWalker`** | **Not started** |
| Generate | Executive report narrative | Event log + findings list in UI; **no `ReportWalker` / LLM narrative** | **Partial** |
| Output | Graph canvas + JSON + remediation | Single-page text log + vulnerable list | **Partial** |

---

## 2. Jac primitives (blueprint §5) — scorecard

| Primitive | Blueprint role | Implemented? | Where / notes |
|-----------|----------------|--------------|---------------|
| **Pipe** | Fetch → parse → normalize → nodes | **Yes** | `fetch_github_lockfile` → `parse_npm_lockfile` → `build_package_graph` in `DepGraphAgent` |
| **Extract** | AST → typed `UsageContext` | **No** | `UsageContext` node only |
| **Invoke** | NVD / GitHub as LLM tools mid-walk | **Partial** | Direct Python `requests` in `nvd_api.jac`, `github_api.jac` (reliable demo; not `by llm(tools=[...])`) |
| **Route** | LLM chooses next `Package` to visit | **No** | SubtreeWalker does not traverse graph |
| **Spawn** | Parallel subtrees + DeepDive | **Partial** | `SubtreeWalker() spawn pkg_node`; reports merged to parent; no DeepDive |
| **Loop** | Remediation until conflict-free | **No** | — |
| **Generate** | Executive summary text | **No** | — |

**Primitives actively demonstrated today:** Pipe, Spawn (basic), Invoke-like tooling (deterministic).

---

## 3. Graph model (blueprint §7.1)

### Nodes (`graph/nodes.jac`)

| Node | Blueprint fields | Implemented | Notes |
|------|------------------|-------------|-------|
| `InvestigationSession` | (orchestration root) | **Yes** | Extra vs blueprint; anchors graph per run |
| `Package` | name, version, ecosystem, is_direct, depth, cvss, critical, usage, status | **Mostly** | Fields exist; **not updated at runtime** (read-only assignment issues avoided) |
| `CVE` | cve_id, cvss, severity, description, fixed_version, … | **Partial** | Missing `affected_versions`, `published_date` |
| `UsageContext` | modules, risk_surface, prod reachability, call_chain | **Schema only** | Never attached |
| `RemediationPlan` | upgrade plan + status | **Schema only** | Never attached |

### Edges (`graph/edges.jac`)

| Edge | Implemented | Used in code? |
|------|-------------|---------------|
| `DependsOn` | **Yes** | **Yes** — lockfile dependency edges |
| `HasCVE` | **Yes** (declared) | **Implicit** — `Package ++> CVE` (no typed edge instance) |
| `HasContext` | **Yes** (declared) | **No** |
| `Resolves` | **Yes** (declared) | **No** |
| `BlockedBy` | **Yes** (declared) | **No** |

### Builder (`graph/builder.jac`)

- Parses lockfile output into `Package` nodes linked from `InvestigationSession`.
- Creates `DependsOn` edges with `required_version`.
- Tested on `shaileshdev4/drygate`: **274 packages**, **373 edges**.

---

## 4. Walkers (blueprint §7.3)

| Walker | Blueprint | File | Status |
|--------|-----------|------|--------|
| `DepGraphAgent` | Orchestrator: ingest, graph, spawn subtrees, report | `walkers/dep_graph_agent.jac` | **MVP done** |
| `SubtreeWalker` | NVD per node, Route visit, spawn DeepDive | `walkers/subtree_walker.jac` | **Partial** — NVD on **entry package only** (no `visit` recursion) |
| `DeepDiveWalker` | Usage context + exploitability | — | **Not created** |
| `RemediationWalker` | Loop until valid plan | — | **Not created** |
| `ReportWalker` | Collect critical paths + LLM report | — | **Not created** |
| `start_investigation` | Public API for UI | `main.jac` | **Done** — wraps `DepGraphAgent`, forwards `reports` |

### `DepGraphAgent` behavior (current)

1. Creates `InvestigationSession` on root.
2. Fetches `package-lock.json` from GitHub default branch.
3. Parses and builds full package graph.
4. Spawns up to **8** `SubtreeWalker` instances on direct dependencies.
5. Merges child `reports` into orchestrator stream.
6. Emits `investigation_complete` with `findings[]` (packages that have attached `CVE` nodes).

### `SubtreeWalker` behavior (current)

1. On `Package` entry: `nvd_lookup` report → `nvd_search_cve` → attach `CVE` nodes → `nvd_result` report.
2. **Does not** `visit` child packages (performance cap for demo; differs from blueprint).

### Event protocol (for UI / future WebSocket)

| Event | Payload highlights |
|-------|-------------------|
| `session_started` | `repo_url`, `ecosystem` |
| `lockfile_fetched` | `owner`, `repo`, `filename` |
| `graph_built` | `package_count`, `edge_count` |
| `nvd_lookup` / `nvd_result` | `package`, `version`, `cve_count`, `max_cvss`, `critical` |
| `subtrees_spawned` | `spawn_count`, `max_direct_deps` |
| `investigation_complete` | `packages_scanned`, `vulnerable_count`, `findings[]` |
| `error` | `message` |

---

## 5. Tools & integrations (blueprint §7.4, §8)

| Tool | Blueprint | File | Status |
|------|-----------|------|--------|
| `osv_query_npm` | OSV per npm version | `tools/osv_api.jac` | **Done** (primary for npm) |
| `lookup_package_cves` | Unified lookup | `tools/cve_lookup.jac` | **Done** — OSV first, empty if clean |
| `nvd_search_cve` | NVD REST | `tools/nvd_api.jac` | **Done** + cache + description filter |
| `nvd_get_cvss` | Per-CVE detail | — | **Not split** (score parsed in search) |
| `github_fetch_file` | Raw file fetch | `tools/github_api.jac` | **Done** (Contents API + base64) |
| `github_search_code` | Code search | — | **Not started** |
| `ast_parse_imports` | Usage extraction | — | **Not started** |
| npm / PyPI registry | Version / changelog | — | **Not started** |
| `check_breaking_changes` | Remediation | — | **Not started** |
| Lockfile parser | (npm specific) | `tools/lockfile_parser.jac` | **Done** v2/v3 |
| Env loading | — | `tools/env_util.jac` | **Done** |
| Python interop | dict/list coercion | `tools/jac_coerce.py` | **Done** |

### Environment (`.env.example`)

| Variable | Purpose |
|----------|---------|
| `FEATHERLESS_API_KEY` | LLM (configured, unused in walkers) |
| `GITHUB_TOKEN` | Higher rate limit / private repos |
| `NVD_API_KEY` | 50 req/30s vs 5 unauthenticated |

---

## 6. LLM / Featherless (blueprint §7.2, §11)

| Item | Status |
|------|--------|
| `models/llm_config.jac` — `code_llm`, `routing_llm` | **Configured** (Qwen2.5-Coder-32B, DeepSeek-V3) |
| `jac.toml` `[plugins.byllm]` default model | DeepSeek-V3-0324 |
| Walkers using `by llm()` | **None yet** |
| Dynamic model per task | **Planned** |

---

## 7. Frontend (blueprint §9)

| Page | Blueprint route | Current | Status |
|------|-----------------|---------|--------|
| Landing / input | `/` | `def:pub app` in `main.jac` @ `/cl/app` | **Partial** — URL input + Investigate; default `drygate`; no ecosystem tabs / demo cards |
| Live investigation | `/investigate/:repo` | — | **Not built** |
| Results & report | `/results/:repo` | — | **Not built** (summary embedded in landing) |
| Walker detail | `/walker/:session_id` | — | **Not built** |

### Landing UI (`main.jac` → `to cl:`) — implemented

- Repo URL input, **Investigate** button, disabled while running.
- **Activity log** — all walker `report` events (orchestrator + NVD).
- **Vulnerable packages** — from `investigation_complete.findings`.
- Client spawn: `root spawn start_investigation(...)`.

### UI / client lessons (May 18)

| Issue | Cause | Fix |
|-------|-------|-----|
| Blank log stuck on “Investigating…” | `as_list()` in browser (server-only) | Removed from client code |
| `row.get is not a function` | Python `.get()` in `to cl:` compiles to JS | Use `row["key"]` and `"key" in row` |
| Port WinError 10013 | Stale `node`/`python` on 8000/8001 | Kill PIDs, restart `jac start --dev` |
| Reports not in UI | Nested spawn + client parsing | Forward reports in `start_investigation`; parse `result.reports` |

### Dev stack

- **UI:** http://localhost:8000/cl/app (Vite HMR)
- **API:** http://localhost:8001 (proxied `/walker/*` in `vite.dev.config.js`)
- **Not implemented:** WebSocket/SSE live stream (blueprint §9 Page 2)

### Components

| Blueprint component | Status |
|--------------------|--------|
| `RepoInput`, `EcosystemSelector`, `DemoRepoCards` | **Not built** |
| `WalkerActivityLog`, `DependencyGraphCanvas`, `LiveStatusBar` | **Not built** |
| `SecurityScoreCard`, `FindingCard`, `RemediationPlanTable` | **Not built** |
| `components/Button.cl.jac` | Scaffold from `jac create` template |

---

## 8. Repository layout — planned vs actual

Blueprint §10 vs current tree:

```
depgraph/
├── main.jac                 ✅ entry + single-page UI + start_investigation
├── jac.toml                 ✅ serve + byllm + client (local npm pins uncommitted)
├── requirements.txt         ✅ jaseci==2.3.17, dotenv, requests
├── README.md                ✅ setup + MVP notes
├── graph/
│   ├── nodes.jac            ✅
│   ├── edges.jac            ✅
│   └── builder.jac          ✅
├── walkers/
│   ├── dep_graph_agent.jac  ✅
│   ├── subtree_walker.jac   ✅ partial
│   ├── deep_dive_walker.jac ❌
│   ├── remediation_walker.jac ❌
│   └── report_walker.jac    ❌
├── tools/
│   ├── nvd_api.jac          ✅
│   ├── github_api.jac       ✅
│   ├── lockfile_parser.jac  ✅
│   ├── env_util.jac         ✅
│   ├── jac_coerce.py        ✅
│   ├── npm_api.jac          ❌
│   ├── pypi_api.jac         ❌
│   └── ast_parser.jac       ❌
├── models/
│   └── llm_config.jac       ✅ (unused in walkers)
├── frontend/                ❌ (UI in main.jac instead)
└── components/
    └── Button.cl.jac        ✅ template only
```

---

## 9. Git history (pushed)

| Commit | Summary |
|--------|---------|
| `3c6f6b1` | Initial commit (LICENSE) |
| `22fd88b` | Python tooling + README |
| `3756238` | Jac fullstack client scaffold |
| `429edb0` | OSP graph + DepGraphAgent stub |
| `9938d1a` | GitHub lockfile + NVD + graph builder + SubtreeWalker |
| `efebe7d` | Investigate button + README jac check |

### Uncommitted local work (as of May 18)

- NVD in-memory cache
- `max_direct_deps = 8`, single-package SubtreeWalker scan
- UI: activity log, vulnerable packages, client parsing fixes
- `README.md` MVP description updates
- Possible `jac.toml` npm dependency drift from `jac install` — **do not commit** unless intentional

---

## 10. Testing & verification

| Test | Result |
|------|--------|
| `jac check main.jac graph tools walkers` | **Passes** (do not `jac check .` — scans `.venv`) |
| `shaileshdev4/drygate` | Lockfile + graph + 8 NVD scans + UI log (e.g. `arg@5.0.2` CVE hits) |
| `expressjs/express` | Fails: no `package-lock.json` on default branch |
| API `POST /walker/start_investigation` | 200, `reports` array populated |
| End-to-end UI | **Working** after client `.get` / `as_list` fixes |

### Known limitations

1. **NVD keyword search** — false positives (e.g. npm `arg` vs unrelated CVEs).
2. **Scan cap** — only 8 direct deps; no full transitive NVD sweep.
3. **No Route** — traversal order is fixed, not LLM-driven.
4. **No usage context** — cannot distinguish build-time vs prod exploitability (key judge story for Sanjay).
5. **Sequential spawns** — not parallel `Spawn` demo in terminal.
6. **No graph visualization** — judges see text, not live canvas.

---

## 11. Risk mitigation (blueprint §16) — status

| Risk | Mitigation in blueprint | Current |
|------|----------------------|---------|
| NVD rate limit | API key + cache | **Key supported**; **cache implemented** |
| GitHub rate limit | Token | **Token supported** |
| LLM bad routing | BFS fallback | N/A — no Route yet |
| Walker too slow | depth/time limits | **`max_direct_deps=8`**, no subtree `visit` |
| Demo failure | Deterministic core | **Core is deterministic** — good for demo |

---

## 12. What is next? (prioritized for deadline)

### P0 — Must-have for credible demo (≈4–6 hours)

1. **Commit & push** current uncommitted MVP (UI fix, cache, scan cap).
2. **Featherless Route (minimal)** — one `by llm` Route on `SubtreeWalker` or small router walker: given current `Package` + CVE summary, pick next neighbor from `[-->][?:Package]` (proves Jac primitive for Ponita).
3. **False-positive filter** — tighten NVD: ecosystem keyword + version range or OSV.dev lookup for npm packages.
4. **Demo repo defaults** — small public repo with lockfile + 1–2 known issues; keep drygate as “full” optional.

### P1 — Strong hackathon polish (≈6–10 hours)

5. **Investigation page** — `/cl/investigate` or split view: activity log + simple graph (even static Cytoscape/D3 from OSP export).
6. **WebSocket/SSE** — stream `report` events during run (blueprint wow moment).
7. **DeepDiveWalker (thin)** — on `critical: true`, `by llm` stub assesses risk text (even without full AST).
8. **ReportWalker** — `Generate` executive summary via `routing_llm` from `findings`.

### P2 — If time remains

9. **RemediationWalker + Loop** — single-package upgrade suggestion.
10. **PyPI / requirements.txt** path.
11. **Parallel spawn** — true concurrent SubtreeWalkers for judge “Spawn” narrative.
12. **Devpost** — video, description from blueprint §13, LinkedIn post §14.

### Suggested order for tonight

```
Commit push → Route + NVD filter → Live progress in UI → Record 3-min demo → Devpost
```

---

## 13. Quick reference commands

```bash
cd "/d/Hackathons/Jac Hacks/depgraph"
source .venv/Scripts/activate
export PYTHONIOENCODING=utf-8
jac check main.jac graph tools walkers
jac start --dev
# UI: http://localhost:8000/cl/app
# API: http://localhost:8001/
```

---

*This document should be updated after each major milestone commit.*
