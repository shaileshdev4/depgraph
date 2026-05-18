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

## Layout

```
depgraph/
├── main.jac              # entry + landing UI
├── graph/                # Package, CVE, edges
├── walkers/              # DepGraphAgent, SubtreeWalker, …
├── tools/                # NVD, GitHub, npm (deterministic)
├── models/               # Featherless LLM config
└── components/           # jac-client UI
```

## License

MIT — see [LICENSE](LICENSE).
