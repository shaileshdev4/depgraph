import { useCallback, useState } from "react";
import { startInvestigation } from "./api";
import { buildGraph } from "./parseReports";
import GraphCanvas from "./components/GraphCanvas";
import CVEPanel from "./components/CVEPanel";
import "./App.css";

const DEFAULT_REPO = "https://github.com/juice-shop/juice-shop";

const DEMO_REPOS = [
  { label: "juice-shop", url: "https://github.com/juice-shop/juice-shop" },
  { label: "drygate", url: "https://github.com/shaileshdev4/drygate" },
  { label: "CRA", url: "https://github.com/react/create-react-app" },
];

export default function App() {
  const [repoUrl, setRepoUrl] = useState(DEFAULT_REPO);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">(
    "idle"
  );
  const [error, setError] = useState("");
  const [logLines, setLogLines] = useState<string[]>([]);
  const [findings, setFindings] = useState<
    import("./types").Finding[]
  >([]);
  const [summary, setSummary] = useState("");

  const [packages, setPackages] = useState<
    import("./types").PackageNode[]
  >([]);
  const [edges, setEdges] = useState<import("./types").GraphEdge[]>([]);

  const run = useCallback(async () => {
    if (!repoUrl.trim()) {
      setError("Enter a GitHub repository URL");
      return;
    }
    setStatus("running");
    setError("");
    setLogLines(["Investigating…"]);
    setFindings([]);
    setSummary("");
    setPackages([]);
    setEdges([]);
    try {
      const result = await startInvestigation(repoUrl);
      const g = buildGraph(result.reports);
      setPackages(g.nodes);
      setEdges(g.edges);
      setLogLines(result.logLines);
      setFindings(result.findings);
      setSummary(result.summary);
      setStatus("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus("error");
    }
  }, [repoUrl]);

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>DepGraph</h1>
          <p className="tagline">
            Autonomous dependency vulnerability investigation
          </p>
        </div>
        <div className="demo-chips">
          {DEMO_REPOS.map((d) => (
            <button
              key={d.url}
              type="button"
              className="chip"
              disabled={status === "running"}
              onClick={() => setRepoUrl(d.url)}
            >
              {d.label}
            </button>
          ))}
        </div>
      </header>

      <div className="toolbar">
        <input
          type="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={status === "running"}
        />
        <button
          type="button"
          className="primary"
          onClick={run}
          disabled={status === "running"}
        >
          {status === "running" ? "Investigating…" : "Investigate"}
        </button>
      </div>

      {error ? <p className="error">{error}</p> : null}

      <main className="main-grid">
        <section className="graph-section">
          <GraphCanvas packages={packages} edges={edges} />
        </section>
        <CVEPanel findings={findings} summary={summary} />
      </main>

      <section className="log-section">
        <h2>Activity log</h2>
        <pre className="log">{logLines.join("\n")}</pre>
      </section>
    </div>
  );
}
