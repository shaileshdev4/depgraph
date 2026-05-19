# DepGraph

**Autonomous dependency vulnerability investigation agent** — built for [JacHacks Spring 2026](https://jaseci.org) with [Jac](https://github.com/Jaseci-Labs/jaseci) and [Featherless.ai](https://featherless.ai).

DepGraph does not flatten your repo into a CVE spreadsheet. It builds a **risk-scored dependency graph**, spawns LLM-guided subtree walkers, **routes** through transitive deps, classifies **production vs test usage**, and produces an **exploitability verdict** (CVSS + reachability).

| | Snyk-style scanners | DepGraph |
|---|---------------------|----------|
| Output | CVE list + CVSS | CVE + **where it runs** + **what to upgrade** |
| Traversal | Fixed rules | **LLM Route** picks the next dependency to investigate |
| Reachability | Often manual | **GitHub import search** + transitive inheritance |

- **Repo:** https://github.com/shaileshdev4/depgraph
- **Live app:** https://depgraph.vercel.app/
- **API:** https://depgraph-production.up.railway.app
- **Demo repo:** [drygate](https://github.com/shaileshdev4/drygate) (axios → follow-redirects, production usage)
- **Hackathon write-up:** [DEVPOST.md](DEVPOST.md) (inspiration, architecture, challenges, deployment story)

---

## Quick start

### Prerequisites

- Python 3.10+
- Node.js 18+
- [Jac CLI](https://docs.jaseci.org) (`pip install jaclang`)
- `FEATHERLESS_API_KEY` (required)
- `GITHUB_TOKEN` (strongly recommended — without it, usage context often stays `unknown` due to rate limits)

### Backend (port 8001)

```powershell
cd depgraph
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Set FEATHERLESS_API_KEY and GITHUB_TOKEN in .env

$env:PYTHONIOENCODING = "utf-8"
jac install
jac start --dev --port 8001
```

Restart `jac start --dev` after pulling walker changes so bytecode recompiles.

### Frontend (port 5173)

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** → pick ecosystem → paste a GitHub URL or use a demo → **Investigate**.

| Service | URL |
|---------|-----|
| React UI | http://localhost:5173 |
| Jac API | http://localhost:8001 |

---

## Supported ecosystems

| Ecosystem | Manifest files (priority order) |
|-----------|----------------------------------|
| **npm** | `package-lock.json` → `package.json` |
| **PyPI** | `poetry.lock` → `Pipfile.lock` → `pyproject.toml` → `requirements.txt` |
| **Go** | `go.mod` |
| **Maven** | `gradle.lockfile` → `pom.xml` |
| **Auto** | Probes lockfiles across ecosystems |

Go/Maven graphs are **shallower** than npm lockfiles (direct deps, not full transitive closure).

### Pipeline

```
GitHub URL + ecosystem
  → fetch & parse manifest
  → build risk-filtered graph (≤300 nodes)
  → usage context (import-aware GitHub code search)
  → LLM spawn: 8 high-risk direct deps as subtree roots
  → per subtree: OSV → Route → deep dive if CVSS ≥ 9
  → exploitability + remediation + executive summary
```

Workspace root packages (repo name at depth 0) are excluded from spawn and usage search.

---

## Jac agent primitives

| Primitive | What it does |
|-----------|----------------|
| **Spawn** | LLM picks which direct dependencies get a subtree investigation |
| **Route** | LLM picks the next transitive neighbor (e.g. axios → follow-redirects) |
| **Spawn (parallel)** | Multiple `SubtreeWalker` instances in parallel |
| **Loop** | `RemediationWalker` validates upgrade paths |
| **Extract** | Prod/test/build from import paths + GitHub search |

### Exploitability

| Verdict | Rule |
|---------|------|
| **CRITICAL** | CVSS ≥ 7 and production usage |
| **HIGH** | CVSS ≥ 4 and production usage |
| **LOW** | test-only usage |
| **MEDIUM** | otherwise |

Transitive deps inherit production context from importers (e.g. `follow-redirects` via `axios`).

---

## Demo repositories

| Demo | Ecosystem | Highlights |
|------|-----------|--------------|
| **[drygate](https://github.com/shaileshdev4/drygate)** | npm | axios CVEs, Route to follow-redirects, production import |
| [juice-shop](https://github.com/juice-shop/juice-shop) | npm | Large app, many CVEs |
| [requests](https://github.com/psf/requests) | PyPI | `pyproject.toml`, urllib3 chain |
| [flask](https://github.com/pallets/flask) | PyPI | Python web stack |
| [gin](https://github.com/gin-gonic/gin) | Go | `go.mod` |

---

## UI

- **Graph (left):** live dependency graph — spawn paths, route edges, CVSS coloring
- **Panel (right):** activity log → findings (exploitability) → analysis → remediation → import context

Findings **update live** when late `usage_context` events arrive (production vs unknown).

---

## Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `FEATHERLESS_API_KEY` | Yes | Spawn, route, summary LLMs |
| `GITHUB_TOKEN` | Recommended | Code search for usage context |
| `NVD_API_KEY` | No | NVD fallback when OSV misses |

Copy `.env.example` → `.env`. Do not commit `.env`.

### Deploy (Vercel + Railway)

| | URL |
|---|-----|
| **Frontend (Vercel)** | https://depgraph.vercel.app/ |
| **Backend (Railway)** | https://depgraph-production.up.railway.app |

| Host | Setup |
|------|--------|
| **Railway** | Repo root `depgraph/` — start: `jac start -p $PORT --no_client` — env: `FEATHERLESS_API_KEY`, `GITHUB_TOKEN`, `PYTHONIOENCODING=utf-8` (async runner uses `PORT` for in-container `/walker` calls) |
| **Vercel** | Root directory `frontend` — env: `VITE_API_URL=https://depgraph-production.up.railway.app` (no trailing slash; redeploy after changing) |

Local dev needs no `VITE_API_URL` (Vite proxies `/walker` to port 8001). See `frontend/.env.example`.

### LLM models (`models/llm_config.jac`)

| Task | Model |
|------|-------|
| Spawn | Qwen2.5-7B |
| Route | DeepSeek-V3 |
| Executive summary | Qwen2.5-Coder-32B |

---

## Development

```powershell
$env:PYTHONIOENCODING = "utf-8"
jac check walkers/dep_graph_agent.jac walkers/usage_context_util.jac tools/github_api.jac
python -m tools.test_manifest_parsers
cd frontend; npm run build
```

## API (React UI)

1. `POST /walker/start_investigation_async` — `{ repo_url, ecosystem, max_direct_deps }` → `{ session_id }`
2. Poll `POST /walker/investigation_status` — `{ session_id, since }` until `status: "done"`
3. `investigation_complete` includes `findings`, `executive_summary`, stats

`ecosystem`: `auto` | `npm` | `pypi` | `go` | `maven`

---

## Project layout

```
depgraph/
├── walkers/dep_graph_agent.jac   # Orchestrator
├── walkers/subtree_walker.jac    # OSV + route per subtree
├── walkers/usage_context_util.jac
├── tools/manifest_resolver.py    # Multi-ecosystem parse
├── tools/github_api.jac          # Import-aware code search
├── tools/osv_api.jac
└── frontend/                     # Vite + React (primary UI)
```

See [Implementation.md](Implementation.md) for blueprint status.

---

## License

MIT — see [LICENSE](LICENSE).
