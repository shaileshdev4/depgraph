# DepGraph

**Autonomous dependency vulnerability investigation agent** for [JacHacks Spring 2026](https://jaseci.org).

DepGraph does not flatten your repo into a CVE spreadsheet. It builds a **risk-scored dependency graph**, spawns LLM-guided subtree walkers, routes through transitive deps, classifies **production vs test usage**, and produces an **exploitability verdict** (CVSS + reachability)—the differentiator vs tools that stop at CVSS alone.

- **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)
- **Primary npm demo:** [drygate](https://github.com/shaileshdev4/drygate)
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

**After pulling backend changes, restart `jac start --dev`** so walkers recompile. Stale servers may still show old errors (e.g. npm-only MVP gate).

### 2. Frontend (port 5173)

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** → choose ecosystem → paste a GitHub URL or pick a demo → **Investigate**.

| Service | URL |
|---------|-----|
| React UI | http://localhost:5173 |
| Jac API | http://localhost:8001 |
| Legacy CL UI | http://localhost:8000/cl/app (optional) |

---

## Supported ecosystems

| Ecosystem | Manifest files (tried in order) | OSV |
|-----------|----------------------------------|-----|
| **npm** | `package-lock.json` → `package.json` | ✓ |
| **PyPI** | `poetry.lock` → `Pipfile.lock` → `pyproject.toml` → `requirements.txt` | ✓ |
| **Go** | `go.mod` | ✓ |
| **Maven** | `gradle.lockfile` → `pom.xml` (direct deps) | ✓ |
| **Auto-detect** | Probes lockfiles across ecosystems | ✓ |

Go/Maven graphs are **shallower** than npm lockfiles (direct `require` / `pom` deps, not full transitive trees).

### What it does (per ecosystem)

```
GitHub URL + ecosystem
    → fetch manifest (GitHub raw / Contents API)
    → parse into unified {packages, edges}
    → build Package graph (risk-filtered, up to 300 nodes)
    → classify usage (production / test / build) via import-aware GitHub search
    → LLM spawn: pick 8 high-risk direct deps as subtree roots
    → for each subtree: OSV lookup → route to next dep → deep dive if CVSS ≥ 9
    → exploitability verdict per finding (CRITICAL / HIGH / MEDIUM / LOW)
    → remediation plans + executive summary
```

Workspace root packages (e.g. `drygate` from your own `package.json` name) are **excluded** from spawn and usage-context search—they are not registry dependencies.

---

## Agent primitives

| Primitive | Role |
|-----------|------|
| **Spawn** | Qwen2.5-7B picks subtree roots from top risk pool |
| **Route** | DeepSeek-V3 picks next transitive dependency to investigate |
| **Invoke** | OSV per ecosystem (PyPI, npm, Go, Maven) when version is known |
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

Transitive deps (e.g. `follow-redirects` via `axios`) inherit production context from importers when they are not directly imported in source.

---

## Demo repositories

Pick ecosystem on line 1, demo repo on line 2 in the UI.

| Demo | Ecosystem | Why use it |
|------|-----------|------------|
| **[drygate](https://github.com/shaileshdev4/drygate)** | npm | Full lockfile, axios → follow-redirects routing, production usage |
| [juice-shop](https://github.com/juice-shop/juice-shop) | npm | Shallow `package.json`; spawn/CVE volume |
| **[requests](https://github.com/psf/requests)** | PyPI | `pyproject.toml` + urllib3/certifi OSV chain |
| [flask](https://github.com/pallets/flask) | PyPI | Python web stack |
| [gin](https://github.com/gin-gonic/gin) | Go | `go.mod` direct requires |

---

## UI overview

Single-page **Investigate** flow:

- **Line 1:** Ecosystem chips (Auto-detect, npm, PyPI, Go, Maven)
- **Line 2:** Demo repo shortcuts
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
│   ├── dep_graph_agent.jac     # Orchestrator (multi-ecosystem manifest ingest)
│   ├── subtree_walker.jac      # OSV + route + deep dive per subtree
│   ├── usage_context_util.jac  # Usage attach, inherit, exploitability, workspace skip
│   ├── route_util.jac          # LLM neighbor / spawn selection
│   ├── deep_dive_walker.jac
│   ├── extract_walker.jac      # Per-ecosystem source extensions (.py, .go, …)
│   ├── remediation_walker.jac
│   └── report_util.jac
├── tools/
│   ├── ecosystem_util.py       # OSV ecosystem names + manifest priorities
│   ├── manifest_resolver.py    # GitHub fetch + auto-detect
│   ├── manifest_parsers.py     # npm, PyPI, Go, Maven parsers
│   ├── test_manifest_parsers.py
│   ├── github_api.jac          # Import-aware code search
│   ├── osv_api.jac             # OSV per ecosystem
│   ├── lockfile_parser.jac     # npm (Jac-native, legacy path)
│   ├── session_store.py        # Live poll buffer
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

Type-check Jac sources:

```powershell
$env:PYTHONIOENCODING = "utf-8"
jac check walkers/dep_graph_agent.jac walkers/usage_context_util.jac tools/github_api.jac
```

Parser smoke tests (Python):

```powershell
python -m tools.test_manifest_parsers
```

Frontend build:

```powershell
cd frontend
npm run build
```

---

## API (async investigation)

Used by the React UI:

1. `POST /walker/start_investigation_async` with `{ repo_url, ecosystem, max_direct_deps }` → `{ session_id }`
2. Poll `POST /walker/investigation_status` with `{ session_id, since }` until `status: "done"`
3. Final event `investigation_complete` includes `findings`, `executive_summary`, stats

`ecosystem`: `auto` | `npm` | `pypi` | `go` | `maven`

Events are pushed live during the walk (`route_chosen`, `usage_context`, `lockfile_fetched`, etc.).

---

## Recent changes (May 2026)

- **Multi-ecosystem support:** npm, PyPI, Go, Maven + auto-detect; `pyproject.toml` for modern Python repos
- Workspace root packages excluded from spawn/usage (fixes false “drygate” production hits)
- Import-aware GitHub search (`from "axios"`, `import requests`, …) instead of bare package name
- UI: ecosystem row + demo row; requests/flask/gin demos
- Live session polling, exploitability on CVE cards, graph pan/zoom stability
- OSV `fixed_version` + usage inheritance for transitive deps

---

## License

MIT — see [LICENSE](LICENSE).
