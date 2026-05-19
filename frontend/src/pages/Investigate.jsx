import { useCallback, useEffect, useRef, useState } from "react";
import { pollInvestigation, startInvestigationAsync } from "../api";
import DependencyGraph from "../components/DependencyGraph";
import CVECard from "../components/CVECard";
import ActivityFeed from "../components/ActivityFeed";
import ExecutiveSummary from "../components/ExecutiveSummary";
import {
  applyEvent,
  computeStats,
  createInitialGraphState,
  formatLogLine,
  getSummary,
  normalizeFindings,
  normalizeRemediations,
  normalizeUsageContexts,
} from "../utils/eventProcessor";

const ECOSYSTEMS = [
  { id: "auto", label: "Auto-detect" },
  { id: "npm", label: "npm" },
  { id: "pypi", label: "PyPI" },
  { id: "go", label: "Go" },
  { id: "maven", label: "Maven" },
];

const DEMOS = [
  {
    label: "drygate",
    url: "https://github.com/shaileshdev4/drygate",
    ecosystem: "npm",
  },
  {
    label: "juice-shop",
    url: "https://github.com/juice-shop/juice-shop",
    ecosystem: "npm",
  },
  {
    label: "requests",
    url: "https://github.com/psf/requests",
    ecosystem: "pypi",
  },
  {
    label: "flask",
    url: "https://github.com/pallets/flask",
    ecosystem: "pypi",
  },
  {
    label: "gin",
    url: "https://github.com/gin-gonic/gin",
    ecosystem: "go",
  },
];

const POLL_MS = 500;
const LOG_TAIL_LIVE = 40;
const LOG_MAX_HEIGHT_RUNNING = 240;
const LOG_MAX_HEIGHT_DONE = 320;
const MONO = "'JetBrains Mono', 'Fira Code', monospace";

const STEPS = [
  "Fetches lockfiles (npm, Poetry, go.mod, Gradle, …) and builds a risk-scored graph",
  "LLM selects the highest-risk packages for investigation",
  "Walker agents traverse the graph, calling OSV for real CVE data",
  "Critical findings trigger deep-dive investigation of transitive dependencies",
];

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function SectionDivider() {
  return (
    <div
      style={{
        height: "1px",
        background:
          "linear-gradient(90deg, transparent, #0d1a26 30%, #0d1a26 70%, transparent)",
        margin: "0 12px",
      }}
    />
  );
}

function SectionHeader({ title, badge }) {
  return (
    <div
      style={{
        padding: "14px 16px 10px",
        fontSize: "11px",
        fontWeight: "700",
        color: "#475569",
        letterSpacing: "0.1em",
        textTransform: "uppercase",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "8px",
      }}
    >
      <span>{title}</span>
      {badge != null && badge !== "" && (
        <span style={{ fontSize: "10px", fontWeight: "600", letterSpacing: "0.04em" }}>
          {badge}
        </span>
      )}
    </div>
  );
}

export default function Investigate() {
  const [hasStarted, setHasStarted] = useState(false);
  const [repoUrl, setRepoUrl] = useState(DEMOS[0].url);
  const [ecosystem, setEcosystem] = useState(DEMOS[0].ecosystem || "auto");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [graphState, setGraphState] = useState(createInitialGraphState);
  const [findings, setFindings] = useState([]);
  const [remediations, setRemediations] = useState([]);
  const [usageContexts, setUsageContexts] = useState([]);
  const [summary, setSummary] = useState("");
  const [logEntries, setLogEntries] = useState([]);
  const [stats, setStats] = useState({});
  const [showVisitedOnly, setShowVisitedOnly] = useState(false);
  const [logExpanded, setLogExpanded] = useState(true);
  const allReportsRef = useRef([]);
  const rightPanelRef = useRef(null);
  const logSectionRef = useRef(null);

  const criticalCount = stats.critical ?? 0;
  const findingsBadge =
    findings.length > 0
      ? criticalCount > 0
        ? `${criticalCount} critical · ${findings.length} total`
        : `${findings.length} total`
      : null;

  const processEvents = useCallback((events, gs, logs) => {
    let nextGs = gs;
    const nextLogs = [...logs];
    for (const row of events) {
      nextGs = applyEvent(nextGs, row);
      allReportsRef.current.push(row);
      nextLogs.push({
        ts: Date.now(),
        event: row.event,
        line: formatLogLine(row),
      });
    }
    return { gs: nextGs, logs: nextLogs };
  }, []);

  const run = useCallback(async () => {
    if (!repoUrl.trim()) {
      setError("Enter a GitHub repository URL");
      return;
    }
    if (!repoUrl.includes("github.com")) {
      setError("URL must be a github.com repository link");
      return;
    }

    setHasStarted(true);
    setRunning(true);
    setError("");
    setFindings([]);
    setRemediations([]);
    setUsageContexts([]);
    setSummary("");
    setLogEntries([]);
    setStats({});
    allReportsRef.current = [];
    let gs = createInitialGraphState();
    let logs = [];
    setGraphState(gs);

    try {
      const sessionId = await startInvestigationAsync(repoUrl, ecosystem);
      let since = 0;
      let status = "running";

      while (status === "running") {
        const snap = await pollInvestigation(sessionId, since);
        if (snap.ok === false && snap.status === "missing") {
          throw new Error("Session not found — restart jac server");
        }

        status = snap.status || "running";
        const events = snap.events || [];

        if (events.length > 0) {
          const processed = processEvents(events, gs, logs);
          gs = processed.gs;
          logs = processed.logs;

          setGraphState({
            ...gs,
            nodes: new Map(gs.nodes),
            hotEdges: new Map(gs.hotEdges),
          });
          setLogEntries([...logs]);
          setStats(computeStats(allReportsRef.current, gs));
          setRemediations(normalizeRemediations(allReportsRef.current));
          setUsageContexts(normalizeUsageContexts(allReportsRef.current));

          const complete = events.find((e) => e.event === "investigation_complete");
          if (complete) {
            setFindings(normalizeFindings([...allReportsRef.current, complete]));
            setSummary(complete.executive_summary || complete.summary || "");
            setStats(computeStats([...allReportsRef.current, complete], gs));
          }
        }

        since = snap.next ?? since + events.length;
        if (status === "done" || status === "error") break;
        await sleep(POLL_MS);
      }

      if (status === "error") {
        const errRow = allReportsRef.current.find((e) => e.event === "error");
        throw new Error(errRow?.message || "Investigation failed");
      }

      const reports = allReportsRef.current;
      if (!reports.some((e) => e.event === "investigation_complete")) {
        setFindings(normalizeFindings(reports));
        setSummary(getSummary(reports));
      }
      setStats(computeStats(reports, gs));
      setRemediations(normalizeRemediations(reports));
      setUsageContexts(normalizeUsageContexts(reports));
    } catch (e) {
      const msg = e?.response?.data?.detail || e.message || String(e);
      if (msg.includes("404") || msg.includes("Not Found")) {
        setError("Repository or manifest not found (404)");
      } else if (msg.includes("ECONNREFUSED") || msg.includes("Network")) {
        setError("Cannot reach API — start jac on port 8001 and npm run dev");
      } else {
        setError(msg);
      }
    } finally {
      setRunning(false);
    }
  }, [repoUrl, ecosystem, processEvents]);

  useEffect(() => {
    if (hasStarted && running && rightPanelRef.current) {
      rightPanelRef.current.scrollTop = 0;
    }
  }, [hasStarted, running]);

  useEffect(() => {
    if (running) setLogExpanded(true);
  }, [running]);

  useEffect(() => {
    if (!running && findings.length > 0) setLogExpanded(false);
  }, [running, findings.length]);

  useEffect(() => {
    if (running && logExpanded && logSectionRef.current) {
      logSectionRef.current.scrollTop = logSectionRef.current.scrollHeight;
    }
  }, [logEntries, running, logExpanded]);

  const displayLogs = running ? logEntries.slice(-LOG_TAIL_LIVE) : logEntries;
  const showLogBody = running || findings.length === 0 || logExpanded;

  if (!hasStarted) {
    return (
      <LandingView
        repoUrl={repoUrl}
        setRepoUrl={setRepoUrl}
        ecosystem={ecosystem}
        setEcosystem={setEcosystem}
        running={running}
        error={error}
        onRun={run}
      />
    );
  }

  return (
    <InvestigationView
      repoUrl={repoUrl}
      setRepoUrl={setRepoUrl}
      ecosystem={ecosystem}
      setEcosystem={setEcosystem}
      running={running}
      error={error}
      setError={setError}
      onRun={run}
      graphState={graphState}
      showVisitedOnly={showVisitedOnly}
      onToggleVisited={() => setShowVisitedOnly((v) => !v)}
      stats={stats}
      displayLogs={displayLogs}
      logExpanded={logExpanded}
      onToggleLog={() => setLogExpanded((v) => !v)}
      showLogBody={showLogBody}
      findings={findings}
      findingsBadge={findingsBadge}
      summary={summary}
      remediations={remediations}
      usageContexts={usageContexts}
      rightPanelRef={rightPanelRef}
      logSectionRef={logSectionRef}
    />
  );
}

const chipRowStyle = {
  display: "flex",
  flexWrap: "nowrap",
  justifyContent: "center",
  alignItems: "center",
  gap: "8px",
  width: "100%",
  overflowX: "auto",
  WebkitOverflowScrolling: "touch",
};

function EcosystemDemoPicker({
  ecosystem,
  setEcosystem,
  repoUrl,
  setRepoUrl,
  running,
  compact = false,
}) {
  return (
    <div
      style={{
        width: "100%",
        marginTop: compact ? 0 : "12px",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}
    >
      <div style={chipRowStyle}>
        {ECOSYSTEMS.map((eco) => (
          <button
            key={eco.id}
            type="button"
            disabled={running}
            onClick={() => setEcosystem(eco.id)}
            style={{
              fontSize: "12px",
              padding: "5px 12px",
              borderRadius: "16px",
              border: `1px solid ${ecosystem === eco.id ? "#22d3ee" : "#1e2d3d"}`,
              background:
                ecosystem === eco.id
                  ? "rgba(34,211,238,0.1)"
                  : "rgba(13,17,23,0.8)",
              color: ecosystem === eco.id ? "#22d3ee" : "#64748b",
              cursor: running ? "not-allowed" : "pointer",
              fontFamily: MONO,
              flexShrink: 0,
              whiteSpace: "nowrap",
            }}
          >
            {eco.label}
          </button>
        ))}
      </div>
      <div style={chipRowStyle}>
        {DEMOS.map((d) => (
          <button
            key={d.url}
            type="button"
            disabled={running}
            onClick={() => {
              setRepoUrl(d.url);
              if (d.ecosystem) setEcosystem(d.ecosystem);
            }}
            style={{
              fontSize: "13px",
              padding: "6px 16px",
              borderRadius: "20px",
              border: `1px solid ${repoUrl === d.url ? "#06b6d4" : "#1e2d3d"}`,
              background:
                repoUrl === d.url ? "rgba(6,182,212,0.1)" : "rgba(13,17,23,0.8)",
              color: repoUrl === d.url ? "#06b6d4" : "#64748b",
              cursor: running ? "not-allowed" : "pointer",
              fontFamily: MONO,
              flexShrink: 0,
              whiteSpace: "nowrap",
            }}
          >
            {d.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function LandingView({
  repoUrl,
  setRepoUrl,
  ecosystem,
  setEcosystem,
  running,
  error,
  onRun,
}) {
  return (
    <div
      style={{
        minHeight: "100vh",
        height: "100vh",
        overflowY: "auto",
        background: "radial-gradient(ellipse at 20% 50%, #060d1f 0%, #020408 60%)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "40px 20px",
        gap: "48px",
        boxSizing: "border-box",
      }}
    >
      <div style={{ textAlign: "center" }}>
        <h1
          style={{
            fontSize: "48px",
            fontWeight: "800",
            color: "#e2e8f0",
            letterSpacing: "-0.04em",
            fontFamily: MONO,
            margin: 0,
          }}
        >
          <span style={{ color: "#06b6d4" }}>Dep</span>Graph
        </h1>
        <p
          style={{
            fontSize: "15px",
            color: "#475569",
            marginTop: "8px",
            letterSpacing: "0.02em",
          }}
        >
          Autonomous dependency vulnerability investigation
        </p>
      </div>

      <div style={{ width: "100%", maxWidth: "600px" }}>
        <input
          style={{
            width: "100%",
            borderRadius: "10px",
            border: "1px solid #1e3451",
            background: "rgba(10,15,26,0.8)",
            padding: "14px 18px",
            fontSize: "14px",
            color: "#e2e8f0",
            outline: "none",
            fontFamily: MONO,
            height: "52px",
            boxSizing: "border-box",
          }}
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !running && onRun()}
          placeholder="https://github.com/owner/repo"
          disabled={running}
          onFocus={(e) => {
            e.target.style.borderColor = "#06b6d4";
            e.target.style.boxShadow = "0 0 0 3px rgba(6,182,212,0.1)";
          }}
          onBlur={(e) => {
            e.target.style.borderColor = "#1e3451";
            e.target.style.boxShadow = "none";
          }}
        />

        <EcosystemDemoPicker
          ecosystem={ecosystem}
          setEcosystem={setEcosystem}
          repoUrl={repoUrl}
          setRepoUrl={setRepoUrl}
          running={running}
        />

        <button
          type="button"
          onClick={onRun}
          disabled={running}
          style={{
            width: "100%",
            height: "52px",
            marginTop: "12px",
            borderRadius: "10px",
            border: "none",
            background: running
              ? "rgba(6,182,212,0.15)"
              : "linear-gradient(135deg, #0891b2, #0e7490)",
            color: running ? "#06b6d4" : "white",
            fontSize: "15px",
            fontWeight: "700",
            cursor: running ? "not-allowed" : "pointer",
            boxShadow: running
              ? "none"
              : "0 0 32px rgba(6,182,212,0.35), 0 4px 20px rgba(0,0,0,0.4)",
            letterSpacing: "0.02em",
            transition: "all 0.2s",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "10px",
          }}
          onMouseEnter={(e) => {
            if (running) return;
            e.currentTarget.style.background = "linear-gradient(135deg, #06b6d4, #0891b2)";
            e.currentTarget.style.boxShadow =
              "0 0 48px rgba(6,182,212,0.5), 0 4px 24px rgba(0,0,0,0.4)";
          }}
          onMouseLeave={(e) => {
            if (running) return;
            e.currentTarget.style.background = "linear-gradient(135deg, #0891b2, #0e7490)";
            e.currentTarget.style.boxShadow =
              "0 0 32px rgba(6,182,212,0.35), 0 4px 20px rgba(0,0,0,0.4)";
          }}
        >
          {running ? (
            <>
              <span
                style={{
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  border: "2px solid #0e7490",
                  borderTopColor: "#06b6d4",
                  animation: "depgraph-spin 0.7s linear infinite",
                  display: "inline-block",
                }}
              />
              Investigating…
            </>
          ) : (
            "Investigate →"
          )}
        </button>

        {error && (
          <p
            style={{
              marginTop: "12px",
              fontSize: "12px",
              color: "#fca5a5",
              textAlign: "center",
            }}
          >
            {error}
          </p>
        )}
      </div>

      <div style={{ width: "100%", maxWidth: "500px" }}>
        {STEPS.map((text, i) => (
          <div
            key={text}
            style={{
              display: "flex",
              gap: "12px",
              alignItems: "flex-start",
              marginBottom: i < STEPS.length - 1 ? "16px" : 0,
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: "#06b6d4",
                fontFamily: MONO,
                fontWeight: 700,
                minWidth: "24px",
                marginTop: "1px",
              }}
            >
              {String(i + 1).padStart(2, "0")}
            </span>
            <span style={{ fontSize: "12px", color: "#475569", lineHeight: 1.6 }}>{text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function InvestigationView({
  repoUrl,
  setRepoUrl,
  ecosystem,
  setEcosystem,
  running,
  error,
  setError,
  onRun,
  graphState,
  showVisitedOnly,
  onToggleVisited,
  stats,
  displayLogs,
  logExpanded,
  onToggleLog,
  showLogBody,
  findings,
  findingsBadge,
  summary,
  remediations,
  usageContexts,
  rightPanelRef,
  logSectionRef,
}) {
  return (
    <div
      style={{
        height: "100vh",
        maxHeight: "100vh",
        background: "radial-gradient(ellipse at 15% 40%, #060d1f 0%, #020408 55%)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <header
        style={{
          flexShrink: 0,
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          padding: "9px 20px 10px",
          background: "rgba(4,8,16,0.95)",
          borderBottom: "1px solid #0d1a26",
          boxSizing: "border-box",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            minHeight: "42px",
          }}
        >
        <div style={{ flexShrink: 0, minWidth: "100px" }}>
          <div
            style={{
              fontSize: "16px",
              fontWeight: 800,
              color: "#e2e8f0",
              fontFamily: MONO,
              letterSpacing: "-0.03em",
              lineHeight: 1.1,
            }}
          >
            <span style={{ color: "#06b6d4" }}>Dep</span>Graph
          </div>
          <div style={{ fontSize: "10px", color: "#334155", marginTop: "1px" }}>
            vulnerability investigation
          </div>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "8px",
            minWidth: 0,
          }}
        >
          <input
            style={{
              flex: 1,
              maxWidth: "500px",
              height: "36px",
              borderRadius: "8px",
              border: "1px solid #1e3451",
              background: "rgba(10,15,26,0.8)",
              padding: "0 12px",
              fontSize: "12px",
              color: "#e2e8f0",
              outline: "none",
              fontFamily: MONO,
              boxSizing: "border-box",
            }}
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !running && onRun()}
            placeholder="https://github.com/owner/repo"
            disabled={running}
          />
          <button
            type="button"
            onClick={onRun}
            disabled={running}
            style={{
              height: "36px",
              padding: "0 16px",
              borderRadius: "8px",
              border: "none",
              background: running
                ? "rgba(6,182,212,0.12)"
                : "linear-gradient(135deg, #0891b2, #0e7490)",
              color: running ? "#06b6d4" : "#fff",
              fontSize: "12px",
              fontWeight: 700,
              cursor: running ? "not-allowed" : "pointer",
              whiteSpace: "nowrap",
              flexShrink: 0,
            }}
          >
            {running ? "…" : "Go"}
          </button>
        </div>

        <div style={{ flexShrink: 0, minWidth: "88px", textAlign: "right" }}>
          {running && (
            <span
              style={{
                fontSize: "10px",
                color: "#06b6d4",
                fontFamily: MONO,
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
              }}
            >
              <span
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: "#06b6d4",
                  animation: "depgraph-pulse 1s ease-in-out infinite",
                }}
              />
              scanning
            </span>
          )}
        </div>
        </div>

        <EcosystemDemoPicker
          ecosystem={ecosystem}
          setEcosystem={setEcosystem}
          repoUrl={repoUrl}
          setRepoUrl={setRepoUrl}
          running={running}
          compact
        />
      </header>

      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "row",
          minHeight: 0,
          overflow: "hidden",
        }}
      >
        <section
          style={{
            flex: "0 0 68.25%",
            minWidth: 0,
            height: "100%",
            borderRight: "1px solid #0d1a26",
            position: "relative",
            overflow: "hidden",
            animation: "depgraph-slide-in-left 0.4s ease-out",
          }}
        >
          <DependencyGraph
            graphState={graphState}
            loading={running}
            showVisitedOnly={showVisitedOnly}
            onToggleVisited={onToggleVisited}
            stats={stats}
            running={running}
          />
        </section>

        <aside
          ref={rightPanelRef}
          style={{
            width: "clamp(361px, 31.75vw, 475px)",
            flexShrink: 0,
            height: "100%",
            overflowY: "auto",
            overflowX: "hidden",
            display: "flex",
            flexDirection: "column",
            background: "rgba(6,10,18,0.6)",
            position: "relative",
            animation: "depgraph-fade-up 0.4s ease-out 0.1s both",
            WebkitOverflowScrolling: "touch",
          }}
        >
          {error && (
            <div
              style={{
                position: "sticky",
                top: 0,
                zIndex: 20,
                margin: "8px 12px 0",
                padding: "8px 12px",
                borderRadius: "8px",
                background: "rgba(127,29,29,0.92)",
                border: "1px solid rgba(239,68,68,0.35)",
                fontSize: "11px",
                color: "#fca5a5",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "8px",
              }}
            >
              <span style={{ flex: 1 }}>{error}</span>
              <button
                type="button"
                onClick={() => setError("")}
                style={{
                  background: "none",
                  border: "none",
                  color: "#ef4444",
                  cursor: "pointer",
                  fontSize: "14px",
                  padding: 0,
                  lineHeight: 1,
                }}
                aria-label="Dismiss"
              >
                ×
              </button>
            </div>
          )}

          <div style={{ borderBottom: "1px solid #0d1a26" }}>
            <div
              style={{
                padding: "12px 16px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "8px",
                fontSize: "11px",
                fontWeight: 700,
                color: "#475569",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                {running && (
                  <span
                    style={{
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: "#06b6d4",
                      animation: "depgraph-pulse 1s ease-in-out infinite",
                      flexShrink: 0,
                    }}
                  />
                )}
                {running ? "Live Investigation" : "Activity Log"}
                {displayLogs.length > 0 && (
                  <span style={{ fontWeight: 500, color: "#334155", letterSpacing: "0.04em", textTransform: "none" }}>
                    · {displayLogs.length}
                    {running ? " recent" : ""}
                  </span>
                )}
              </span>
              {findings.length > 0 && !running && (
                <button
                  type="button"
                  onClick={onToggleLog}
                  style={{
                    background: "none",
                    border: "none",
                    padding: 0,
                    fontSize: "11px",
                    fontWeight: 600,
                    color: "#06b6d4",
                    cursor: "pointer",
                    letterSpacing: "0.02em",
                    textTransform: "none",
                  }}
                >
                  {logExpanded ? "Hide activity log" : "Show activity log"}
                </button>
              )}
            </div>

            {showLogBody && (
            <div
              ref={logSectionRef}
              style={{
                maxHeight: running ? LOG_MAX_HEIGHT_RUNNING : LOG_MAX_HEIGHT_DONE,
                overflowY: "auto",
                overflowX: "hidden",
                padding: "0 12px 12px",
                WebkitOverflowScrolling: "touch",
              }}
            >
              {displayLogs.length > 0 ? (
                <ActivityFeed logEntries={displayLogs} />
              ) : (
                <p style={{ fontSize: "11px", color: "#334155", margin: 0 }}>
                  Waiting for events…
                </p>
              )}
            </div>
            )}
          </div>

          <SectionDivider />

          <SectionHeader title="Findings" badge={findingsBadge} />
          <div style={{ padding: "0 12px 12px", display: "flex", flexDirection: "column", gap: "8px" }}>
            {findings.length === 0 ? (
              <p style={{ fontSize: "12px", color: "#334155", textAlign: "center", padding: "24px 8px" }}>
                {running
                  ? "Scanning dependencies for vulnerabilities…"
                  : "No vulnerable packages discovered in scanned subtrees."}
              </p>
            ) : (
              findings.map((f) => <CVECard key={`${f.package}@${f.version}`} finding={f} />)
            )}
          </div>

          {summary && (
            <>
              <SectionDivider />
              <SectionHeader title="Analysis" />
              <div className="depgraph-analysis" style={{ margin: "0 12px 12px" }}>
                <ExecutiveSummary markdown={summary} />
              </div>
            </>
          )}

          {remediations.length > 0 && (
            <>
              <SectionDivider />
              <SectionHeader title="Remediation Plans" badge={String(remediations.length)} />
              <div style={{ padding: "0 12px 12px" }}>
                <RemediationList remediations={remediations} />
              </div>
            </>
          )}

          {usageContexts.length > 0 &&
            usageContexts.some((c) => c.surface !== "unknown") && (
            <>
              <SectionDivider />
              <SectionHeader title="Import Context" badge={String(usageContexts.length)} />
              <div className="depgraph-context-panel" style={{ padding: "0 12px 12px" }}>
                <ContextList contexts={usageContexts} />
              </div>
            </>
          )}

          <div style={{ height: "40px", flexShrink: 0 }} />
        </aside>
      </div>
    </div>
  );
}

function RemediationList({ remediations }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      {remediations.map((r, i) => (
        <div
          key={`${r.package}-${i}`}
          style={{
            borderRadius: "8px",
            border: `1px solid ${
              r.status === "validated"
                ? "rgba(34,197,94,0.3)"
                : r.status === "conflict"
                  ? "rgba(239,68,68,0.3)"
                  : "#1e2d3d"
            }`,
            background:
              r.status === "validated"
                ? "rgba(34,197,94,0.04)"
                : r.status === "conflict"
                  ? "rgba(239,68,68,0.04)"
                  : "#0a0f1a",
            padding: "10px 12px",
          }}
        >
          <div style={{ fontFamily: MONO, fontSize: "12px", fontWeight: 700, color: "#e2e8f0" }}>
            {r.package}
          </div>
          <div style={{ fontSize: "11px", fontFamily: MONO, color: "#94a3b8", marginTop: "4px" }}>
            <span style={{ color: "#f97316" }}>{r.from}</span>
            {" → "}
            <span style={{ color: "#22c55e" }}>{r.to}</span>
          </div>
          {r.breaking_changes?.length > 0 && (
            <div style={{ fontSize: "10px", color: "#eab308", marginTop: "4px" }}>
              ⚠ {r.breaking_changes.length} breaking change
              {r.breaking_changes.length !== 1 ? "s" : ""}
            </div>
          )}
          <div
            style={{
              marginTop: "6px",
              fontSize: "9px",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color:
                r.status === "validated"
                  ? "#22c55e"
                  : r.status === "conflict"
                    ? "#ef4444"
                    : "#64748b",
            }}
          >
            {r.status || "pending"}
          </div>
        </div>
      ))}
    </div>
  );
}

function ContextList({ contexts }) {
  return (
    <div className="depgraph-context-list">
      {contexts.map((ctx, i) => (
        <div
          key={`${ctx.package}-${i}`}
          className={`depgraph-context-item${ctx.is_prod ? " depgraph-context-item--prod" : ""}`}
        >
          <div className="depgraph-context-item-header">
            <span className="depgraph-context-package">{ctx.package}</span>
            <span
              className={`depgraph-context-surface${ctx.is_prod ? " depgraph-context-surface--prod" : ""}`}
            >
              {ctx.surface || "unknown"}
            </span>
          </div>
          {ctx.importing_file_count > 0 && (
            <div className="depgraph-context-meta">
              {ctx.importing_file_count} import file
              {ctx.importing_file_count !== 1 ? "s" : ""}
            </div>
          )}
          {ctx.importing_files?.length > 0 && (
            <ul className="depgraph-context-files">
              {ctx.importing_files.map((f, j) => (
                <li key={j} title={f}>
                  {f}
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}
