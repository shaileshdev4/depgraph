# DepGraph

Autonomous dependency vulnerability investigation agent for **JacHacks Spring 2026**.

Traverses a dependency graph with Jac walkers (Route, Spawn, Invoke) instead of flat CVE lookup tables.

- **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)
- **Stack:** [Jaseci](https://github.com/Jaseci-Labs/jaseci) · jac-client · byllm · Featherless.ai

## Setup

```powershell
cd depgraph
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` → `.env` and set `FEATHERLESS_API_KEY` (and optional `GITHUB_TOKEN`, `NVD_API_KEY`).

```powershell
$env:PYTHONIOENCODING = "utf-8"
jac install
jac start --dev
```

Open http://localhost:8000/cl/app (Jac CL UI) **or** the React graph UI below.

### React graph UI (demo)

**Vite** (not CRA) — fast dev server, proxies walker API to Jac.

```powershell
# Terminal 1 — backend
jac start --dev

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 — investigation path graph, CVE cards, activity log.

| Model | Task |
|-------|------|
| Qwen2.5-7B | Spawn root selection (JSON) |
| DeepSeek-V3 | Subtree route hops |
| Qwen2.5-Coder-32B | Executive summary |

## What works now (MVP)

- Paste a **public GitHub** repo URL with **`package-lock.json`** on the default branch.
- **Investigate** fetches the lockfile, builds a **Package** graph under an `InvestigationSession`, and spawns **SubtreeWalker** on up to **8 direct dependencies** (demo cap).
- Each subtree walker queries **NVD** (keyword search, in-memory cache) and attaches **CVE** nodes for matches.
- The UI shows an **activity log** (orchestrator + NVD events) and a **vulnerable packages** summary.

## Development

Type-check only project sources (do **not** run `jac check` on the whole folder — it will descend into `.venv`):

```powershell
$env:PYTHONIOENCODING = "utf-8"
jac check main.jac graph tools walkers
```

## Layout

```
depgraph/
├── main.jac              # entry + landing UI
├── graph/                # Package, CVE, edges
├── walkers/              # DepGraphAgent, SubtreeWalker, …
├── tools/                # GitHub, NVD, lockfile parse, Python helpers
├── models/               # Featherless LLM config
└── components/           # jac-client UI
```

## License

MIT — see [LICENSE](LICENSE).
