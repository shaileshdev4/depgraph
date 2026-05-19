# DepGraph — JacHacks Spring 2026

- **Try it live:** [depgraph.vercel.app](https://depgraph.vercel.app/)
- **API:** [depgraph-production.up.railway.app](https://depgraph-production.up.railway.app)
- **Repo:** [github.com/shaileshdev4/depgraph](https://github.com/shaileshdev4/depgraph)

---

## Inspiration

You ran your security scan this morning. It came back clean.

You're not clean.

95% of vulnerabilities in open source software live in transitive dependencies — packages your packages depend on, three, four, five hops deep. Snyk checks level one. Your code doesn't run on level one.

Log4Shell wasn't in anyone's `package.json`. Event-stream wasn't either. Every security tool said: clean. Millions of systems went down.

We wanted to build something that actually *investigates*.

The industry's answer is a lookup table. We built an investigation agent.

---

## What it does

DepGraph is an autonomous dependency vulnerability investigation agent built natively in [Jac](https://docs.jaseci.org).

Give it a GitHub repository URL. It:

1. **Fetches and parses your lockfile** — npm, PyPI, Go modules, or Maven
2. **Builds a risk-scored dependency graph** — ~200 nodes filtered from thousands using security-aware heuristics
3. **Deploys LLM-driven walker agents** — the LLM selects which packages to investigate using Jac's Route primitive, with zero hardcoded traversal logic
4. **Traces multi-hop transitive chains** — follows vulnerability paths through the dependency tree (e.g., axios → follow-redirects → CVE)
5. **Classifies production exposure** — checks whether vulnerable packages are imported in production code, test code, or build tooling via GitHub code search
6. **Generates an exploitability verdict** — CVSS 8.1 + production auth code = **CRITICAL EXPLOITABILITY**. Same CVE in a test file = **LOW** risk.
7. **Produces validated remediation plans** — specific version upgrades, conflict-checked via the Loop primitive

The result: not just "this CVE exists" but "this CVE is in your production auth code, CVSS 9.8, upgrade to version X — validated, no breaking changes."

**Demo:** Paste [https://github.com/shaileshdev4/drygate](https://github.com/shaileshdev4/drygate) into the [live app](https://depgraph.vercel.app/) and watch the graph + activity log.

---

## How we built it

DepGraph is built entirely in **Jac**, Jaseci's AI-native programming language. The entire backend — graph model, walker agents, LLM routing, API server — is Jac. The frontend is React + Vite consuming the Jac API.

### Jac architecture

The dependency graph is modeled natively in Jac:

- `Package` nodes connected by `DependsOn` edges
- `CVE` nodes attached to vulnerable packages
- `UsageContext` nodes storing production/test classification
- `RemediationPlan` nodes with validated upgrade paths

Six of Jac's seven LLM primitives are used — genuinely, not decoratively:

| Primitive | Where | Why it's essential |
|-----------|-------|-------------------|
| **Pipe** | Lockfile manifest → Package nodes | Sequential ingestion pipeline |
| **Invoke** | OSV API + GitHub search at each node | Real CVE data fetched mid-traversal |
| **Spawn** | 8 parallel SubtreeWalkers | LLM selects investigation roots |
| **Route** | Next dependency hop selection | LLM decides traversal path — zero if/else |
| **Loop** | Remediation validation | Iterate until conflict-free upgrade plan |
| **Generate** | Executive summary | Final report generation |

### Model routing via Featherless.ai

Three different models for three different tasks:

- **Qwen2.5-7B-Instruct** — spawn root selection (reliable JSON output on large lists)
- **DeepSeek-V3-0324** — routing decisions + executive summary (best reasoning)
- **Qwen2.5-Coder-32B-Instruct** — usage context classification (code understanding)

### The Route primitive

The core innovation: `visit [-->] by llm(incl_info={...})` — the LLM selects which neighboring package node to traverse to next based on accumulated risk signals (CVSS, CVE count, critical findings, usage surface). No conditional logic. The language architecture *is* the agent architecture.

### Exploitability verdict

After CVE discovery and production classification:

```
exploitability = CRITICAL  if CVSS >= 7 and surface == "production"
               = HIGH      if CVSS >= 4 and surface == "production"
               = LOW       if surface == "test"
               = MEDIUM    otherwise
```

This single combination — something no existing consumer security tool produces — is DepGraph's core differentiator.

### Deployed for the hackathon

We ship a split production stack so judges and users can try it without cloning:

| Layer | Host | URL |
|-------|------|-----|
| **UI** | Vercel | [https://depgraph.vercel.app/](https://depgraph.vercel.app/) |
| **Jac API** | Railway | [https://depgraph-production.up.railway.app](https://depgraph-production.up.railway.app) |

The Vercel build sets `VITE_API_URL` to the Railway API. The backend runs `jac start -p $PORT --no_client` with async investigations self-calling the same container via `PORT` (Jac on 8080 inside Railway). CORS is enabled so the browser can poll `/walker/investigation_status` across origins.

---

## Challenges we ran into

**1. The Route primitive's output format**

Jac's `visit by llm()` expects a `list[int]` of neighbor indexes. DeepSeek-V3 consistently returned full index ranges (`[0,1,2..13]`) or markdown-wrapped JSON. We solved this by moving to an explicit `def choose_neighbor_indexes() -> list[int] by llm()` with a strict single-index docstring prompt, CVSS-aware fallback, and Qwen2.5-7B for spawn selection where JSON reliability matters most.

**2. Large lockfiles (2MB+)**

create-react-app has 2,120 packages in its lockfile. Building 2,120 Jac nodes caused memory issues and walker timeouts. We implemented risk-scored filtering — scoring every package by depth, name heuristics, version age, and ecosystem attack surface — then capping at 200 nodes. This is actually how production SCA tools work. We turned a technical constraint into a feature.

**3. OSV `fixed_version` parsing**

OSV returns patched versions inside `affected[].ranges[].events[].fixed` — a 3-level nested structure. Our initial implementation set `fixed_version: ""` for every CVE, silently breaking the entire remediation pipeline. Once found and fixed, the Loop primitive immediately started producing validated upgrade plans.

**4. GitHub API rate limits for usage context**

Fetching import context for all 69 packages in a repo hit GitHub's 30 requests/minute search limit. Solution: only fetch context for spawn targets + CVE-positive packages — the ~10 packages that actually matter for the investigation.

---

## Accomplishments that we're proud of

- **The exploitability verdict is real and novel.** We verified it against multiple repositories. jsonwebtoken imported in production auth routes = CRITICAL. The same package imported only in test files = LOW. No existing free tool makes this distinction.

- **The Route primitive genuinely works.** The activity log shows the LLM routing from `axios → follow-redirects` because axios had 15 CVEs and CVSS 8.1, not because we wrote `if cvss > 7: investigate_follow_redirects()`. That's the difference between an agent and a script.

- **Multi-hop transitive chains are visible.** `drygate → axios → follow-redirects` — three hops, the vulnerability path is visually traceable in the graph and in the activity log.

- **Four ecosystems.** npm, PyPI, Go modules, Maven — same agent, same graph model, same exploitability analysis.

- **Shipped and demoable.** [depgraph.vercel.app](https://depgraph.vercel.app/) is live for JacHacks — not just localhost.

---

## What we learned

Jac's Object-Spatial Programming model is the right abstraction for security investigation. A dependency graph is literally a spatial data structure, and a security agent is literally computation that needs to move through it. The match isn't cosmetic — the Route primitive letting an LLM decide graph traversal paths without if/else is genuinely hard to do this cleanly in Python, LangGraph, or any existing framework.

The hardest part of building an agentic system isn't the LLM calls — it's the **data model**. Getting the Jac graph nodes right (`Package → CVE → UsageContext → RemediationPlan` as connected nodes rather than flat dicts) made every walker simpler to write and every piece of information naturally available at the right traversal step.

CVSS alone is a meaningless number without deployment context. The same CVE means completely different things in production auth code vs a test helper. That insight — obvious in retrospect — is absent from most existing security tools. DepGraph encodes it in every verdict.

---

## What's next for DepGraph

- **Call graph analysis** — the remaining gap. Currently we know a package is in production code. The next step is tracing whether the *specific vulnerable function* is actually called (AST analysis of repo source).
- **CI/CD integration** — run DepGraph as a GitHub Action on every PR; block merges when CRITICAL EXPLOITABILITY findings are introduced.
- **Remediation PR generation** — not just a plan, an actual pull request with the version bump.
- **Expanded ecosystem support** — Rust (Cargo), Ruby (Bundler), PHP (Composer).
- **Persistent investigation history** — compare security posture across commits over time (today sessions are in-memory on the API host).
