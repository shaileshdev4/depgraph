# DepGraph

**Autonomous dependency vulnerability investigation agent** for [JacHacks Spring 2026](https://jaseci.org).

DepGraph does not flatten your repo into a CVE spreadsheet. It builds a **risk-scored dependency graph**, spawns LLM-guided subtree walkers, routes through transitive deps, classifies **production vs test usage**, and produces an **exploitability verdict** (CVSS + reachability)—the differentiator vs tools that stop at CVSS alone.

- **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)
- **Demo repo:** [drygate](https://github.com/shaileshdev4/drygate) (lockfile + multi-hop routing)
- **Stack:** [Jaseci](https://github.com/Jaseci-Labs/jaseci) · Jac walkers · Featherless.ai (byllm) · React Flow

---

## Quick start

### Prerequisites

- Python 3.10+
- Node.js 18+
- [Jac CLI](https://docs.jaseci.org) (`pip install jaclang`)
- API keys: `FEATHERLESS_API_KEY` (required), `GITHUB_TOKEN` (recommended for usage search)

### 1. Backend (port 8001)

```powershell
cd depgraph
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Edit .env — set FEATHERLESS_API_KEY and GITHUB_TOKEN

$env:PYTHONIOENCODING = "utf-8"
jac install
jac start --dev --port 8001
```

### 2. Frontend (port 5173)

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** → paste a GitHub URL or click **drygate** → **Investigate**.

| Service | URL |
|---------|-----|
| React UI | http://localhost:5173 |
| Jac API | http://localhost:8001 |
| Legacy CL UI | http://localhost:8000/cl/app (optional) |

---

## What it does

```
GitHub URL
    → fetch package-lock.json (or package.json fallback)
    → build Package graph (risk-filtered, up to 300 nodes)
    → classify usage (production / test / build) via GitHub import search
    → LLM spawn: pick 8 high-risk direct deps as subtree roots
    → for each subtree: OSV lookup → route to next dep → deep dive if CVSS ≥ 9
    → exploitability verdict per finding (CRITICAL / HIGH / MEDIUM / LOW)
    → remediation plans + executive summary
```

### Agent primitives

| Primitive | Role |
|-----------|------|
| **Spawn** | Qwen2.5-7B picks subtree roots from top risk pool |
| **Route** | DeepSeek-V3 picks next transitive dependency to investigate |
| **Invoke** | OSV (primary) + NVD fallback per package |
| **Extract** | Deterministic prod/test/build from import paths + GitHub code search |
| **Deep Dive** | Follow transitive chain when CVSS ≥ 9 |
| **Generate** | Executive summary (markdown, no broken package links) |

### Exploitability verdict (differentiator)

Combines **CVSS** with **usage surface**:

| Verdict | Rule |
|---------|------|
| **CRITICAL** | CVSS ≥ 7 and `production` usage |
| **HIGH** | CVSS ≥ 4 and `production` usage |
| **LOW** | `test`-only usage |
| **MEDIUM** | everything else |

Example: `CVSS 8.1 + production code = CRITICAL EXPLOITABILITY` (not just “CVSS 8.1”).

Transitive deps (e.g. `follow-redirects` via `axios`) inherit production context from importers when they are not directly imported in source.

---

## Demo repositories

| Repo | Why use it |
|------|------------|
| **[drygate](https://github.com/shaileshdev4/drygate)** | **Primary demo** — full lockfile, `route_chosen` events, axios → follow-redirects traversal |
| [juice-shop](https://github.com/juice-shop/juice-shop) | Shallow `package.json`; good for spawn/CVE volume, weak on routing |
| [create-react-app](https://github.com/react/create-react-app) | Large graph; shows risk truncation |

---

## UI overview

Single-page **Investigate** flow:

- **Left (~65%):** Live dependency graph (React Flow) with spawn paths, route edges, deep-dive highlights
- **Right:** Activity log (collapsible) → Findings (CVE cards + exploitability) → Analysis → Remediation → Import context

Activity log shows the agent thinking: `spawn_chosen`, `route_decision`, `route_chosen`, `deep_dive`, `usage_context`, `nvd_result`.

---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `FEATHERLESS_API_KEY` | Yes | Spawn, route, executive summary LLMs |
| `GITHUB_TOKEN` | Recommended | Usage context import search (rate limits without it) |
| `NVD_API_KEY` | Optional | NVD fallback when OSV has no match |

Copy `.env.example` → `.env`. Never commit `.env`.

---

## LLM models (Featherless)

| Task | Model |
|------|-------|
| Spawn root selection | Qwen2.5-7B |
| Route next hop | DeepSeek-V3 |
| Executive summary | Qwen2.5-Coder-32B |

Configured in `models/llm_config.jac`.

---

## Project layout

```
depgraph/
├── main.jac                    # Walker API + legacy jac-client UI
├── graph/                      # Package, CVE, UsageContext nodes; DependsOn edges
├── walkers/
│   ├── dep_graph_agent.jac     # Orchestrator
│   ├── subtree_walker.jac      # OSV + route + deep dive per subtree
│   ├── usage_context_util.jac  # Usage attach, inherit, exploitability helpers
│   ├── route_util.jac          # LLM neighbor / spawn selection
│   ├── deep_dive_walker.jac
│   ├── extract_walker.jac
│   ├── remediation_walker.jac
│   └── report_util.jac
├── tools/
│   ├── github_api.jac          # Manifest fetch + import search
│   ├── osv_api.jac               # OSV + fixed_version extraction
│   ├── lockfile_parser.jac
│   ├── session_store.py          # Live poll buffer
│   └── investigation_runner.py # Async investigation thread
├── models/llm_config.jac
└── frontend/                   # Vite + React (primary UI)
    └── src/
        ├── pages/Investigate.jsx
        ├── components/         # Graph, CVECard, ActivityFeed, …
        └── utils/eventProcessor.js
```

See [Implementation.md](Implementation.md) for detailed status vs blueprint.

---

## Development

Type-check Jac sources (exclude `.venv`):

```powershell
$env:PYTHONIOENCODING = "utf-8"
jac check main.jac graph tools walkers
```

Frontend build:

```powershell
cd frontend
npm run build
```

---

## API (async investigation)

Used by the React UI:

1. `POST /walker/start_investigation_async` → `{ session_id }`
2. Poll `POST /walker/investigation_status` with `{ session_id, since }` until `status: "done"`
3. Final event `investigation_complete` includes `findings`, `executive_summary`, stats

Events are pushed live during the walk (`route_chosen`, `usage_context`, etc.).

---

## Recent changes (May 2026)

- Live session polling with route/spawn events in activity log
- Typed `DependsOn` graph traversal (fixes missing `route_chosen` on lockfile repos)
- Exploitability verdict on findings + CVE cards
- Deterministic usage classification; GitHub import search for spawn + CVE-positive packages
- Usage inheritance for transitive deps (e.g. follow-redirects via axios)
- OSV `fixed_version` parsing for remediation
- Deep-dive findings fed into next route decision; CVSS-aware route fallback
- Executive summary sanitization (no `mailto:` package links)
- Investigate UI redesign: graph HUD, collapsible activity log, drygate as default demo

---

## License

MIT — see [LICENSE](LICENSE).
