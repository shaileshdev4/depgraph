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

Open http://localhost:8000/cl/app

## What works now (MVP)

- Paste a **public GitHub** repo URL with **`package-lock.json`** on the default branch.
- **Investigate** fetches the lockfile, builds a **Package** graph under an `InvestigationSession`, and spawns **SubtreeWalker** on each direct dependency (depth ≤ 1).
- Each subtree walker queries **NVD** (keyword search) and attaches **CVE** nodes for matches.
- The UI shows a simple **event log** from the orchestrator (fetch → graph → spawn).

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
