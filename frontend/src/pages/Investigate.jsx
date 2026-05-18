import { useCallback, useState } from "react";
import { startInvestigation } from "../api";
import DependencyGraph from "../components/DependencyGraph";
import CVECard from "../components/CVECard";
import ActivityFeed from "../components/ActivityFeed";
import ExecutiveSummary from "../components/ExecutiveSummary";
import StatsBar from "../components/StatsBar";
import {
  applyEvent,
  computeStats,
  createInitialGraphState,
  formatLogLine,
  getSummary,
  normalizeFindings,
} from "../utils/eventProcessor";

const DEMOS = [
  { label: "juice-shop", url: "https://github.com/juice-shop/juice-shop" },
  { label: "drygate", url: "https://github.com/shaileshdev4/drygate" },
  { label: "CRA", url: "https://github.com/react/create-react-app" },
];

const REPLAY_MS = 120;

export default function Investigate() {
  const [repoUrl, setRepoUrl] = useState(DEMOS[0].url);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("findings");
  const [graphState, setGraphState] = useState(createInitialGraphState);
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState("");
  const [logEntries, setLogEntries] = useState([]);
  const [stats, setStats] = useState({});
  const [showVisitedOnly, setShowVisitedOnly] = useState(false);

  const run = useCallback(async () => {
    if (!repoUrl.trim()) {
      setError("Enter a GitHub repository URL");
      return;
    }
    if (!repoUrl.includes("github.com")) {
      setError("URL must be a github.com repository link");
      return;
    }

    setRunning(true);
    setError("");
    setFindings([]);
    setSummary("");
    setLogEntries([]);
    setStats({});
    setGraphState(createInitialGraphState());

    try {
      const reports = await startInvestigation(repoUrl);
      let gs = createInitialGraphState();
      const logs = [];

      for (let i = 0; i < reports.length; i++) {
        const row = reports[i];
        gs = applyEvent(gs, row);
        logs.push({
          ts: Date.now() + i,
          event: row.event,
          line: `- ${formatLogLine(row)}`,
        });
        setGraphState({ ...gs, nodes: new Map(gs.nodes) });
        setLogEntries([...logs]);
        setStats(computeStats(reports.slice(0, i + 1), gs));
        await new Promise((r) => setTimeout(r, REPLAY_MS));
      }

      setFindings(normalizeFindings(reports));
      setSummary(getSummary(reports));
      setStats(computeStats(reports, gs));
      setTab("findings");
    } catch (e) {
      const msg = e?.response?.data?.detail || e.message || String(e);
      if (msg.includes("404") || msg.includes("Not Found")) {
        setError("Repository or manifest not found (404)");
      } else if (msg.includes("ECONNREFUSED") || msg.includes("Network")) {
        setError("Cannot reach API — start jac on port 8001");
      } else {
        setError(msg);
      }
    } finally {
      setRunning(false);
    }
  }, [repoUrl]);

  return (
    <div className="min-h-screen bg-canvas flex flex-col p-4 gap-4 max-w-[1600px] mx-auto">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">DepGraph</h1>
          <p className="text-sm text-gray-500">
            Autonomous dependency vulnerability investigation
          </p>
        </div>
        <div className="flex gap-2">
          {DEMOS.map((d) => (
            <button
              key={d.url}
              type="button"
              disabled={running}
              onClick={() => setRepoUrl(d.url)}
              className="text-xs px-3 py-1 rounded-full border border-border bg-card hover:border-blue-500 disabled:opacity-50"
            >
              {d.label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex gap-2">
        <input
          className="flex-1 rounded-lg border border-border bg-card px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          disabled={running}
        />
        <button
          type="button"
          onClick={run}
          disabled={running}
          className="px-5 py-2 rounded-lg bg-green-600 hover:bg-green-500 font-semibold text-sm disabled:opacity-50"
        >
          {running ? "Investigating…" : "Investigate"}
        </button>
      </div>

      {error && (
        <p className="text-sm text-red-400 border border-red-500/40 rounded-lg px-3 py-2 bg-red-950/30">
          {error}
        </p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 flex-1 min-h-[480px]">
        <section className="lg:col-span-3 rounded-xl border border-border bg-card overflow-hidden min-h-[420px]">
          <DependencyGraph
            graphState={graphState}
            loading={running}
            showVisitedOnly={showVisitedOnly}
            onToggleVisited={() => setShowVisitedOnly((v) => !v)}
          />
        </section>

        <aside className="lg:col-span-2 rounded-xl border border-border bg-card flex flex-col min-h-[420px]">
          <div className="flex border-b border-border text-sm">
            {["findings", "summary", "log"].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`flex-1 py-2 capitalize ${
                  tab === t
                    ? "text-white border-b-2 border-blue-500"
                    : "text-gray-500"
                }`}
              >
                {t === "log" ? "Activity Log" : t}
              </button>
            ))}
          </div>
          <div className="flex-1 p-3 overflow-hidden min-h-0">
            {tab === "findings" && (
              <ul className="space-y-2 overflow-y-auto h-full max-h-[360px]">
                {findings.length === 0 ? (
                  <p className="text-sm text-gray-500">No vulnerable packages yet.</p>
                ) : (
                  findings.map((f) => (
                    <CVECard key={`${f.package}@${f.version}`} finding={f} />
                  ))
                )}
              </ul>
            )}
            {tab === "summary" && (
              <div className="h-full max-h-[360px] overflow-y-auto">
                <ExecutiveSummary markdown={summary} />
              </div>
            )}
            {tab === "log" && (
              <div className="h-full max-h-[360px]">
                <ActivityFeed logEntries={logEntries} />
              </div>
            )}
          </div>
        </aside>
      </div>

      <StatsBar stats={stats} running={running} />
    </div>
  );
}
