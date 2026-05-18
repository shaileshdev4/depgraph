import { useCountUp } from "../utils/useCountUp";

function HudSep() {
  return (
    <span style={{ color: "#1e2d3d", fontSize: "10px", userSelect: "none" }}>·</span>
  );
}

export default function GraphHUD({ stats = {}, running }) {
  const nodesCount = useCountUp(stats.packagesInGraph ?? 0);
  const scannedCount = useCountUp(stats.scanned ?? 0);
  const vulnCount = useCountUp(stats.vulnerable ?? 0);
  const criticalCount = useCountUp(stats.critical ?? 0);

  const spawnMode = stats.spawnMode ?? "—";
  const spawnColor = spawnMode === "llm" ? "#22c55e" : "#eab308";

  return (
    <div
      style={{
        position: "absolute",
        top: "10px",
        left: "50%",
        transform: "translateX(-50%)",
        zIndex: 10,
        display: "flex",
        gap: "6px",
        background: "rgba(4,8,16,0.85)",
        border: "1px solid #1a2a3a",
        borderRadius: "20px",
        padding: "5px 14px",
        backdropFilter: "blur(12px)",
        alignItems: "center",
        fontSize: "10px",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        whiteSpace: "nowrap",
      }}
    >
      <span style={{ color: "#334155" }}>⬡ {nodesCount} nodes</span>
      <HudSep />
      <span style={{ color: "#475569" }}>⊙ {scannedCount} scanned</span>
      {(stats.vulnerable ?? 0) > 0 && (
        <>
          <HudSep />
          <span style={{ color: "#f97316" }}>◈ {vulnCount} vuln</span>
        </>
      )}
      {(stats.critical ?? 0) > 0 && (
        <>
          <HudSep />
          <span
            style={{
              color: "#ef4444",
              animation: "depgraph-blink 1.5s ease-in-out infinite",
            }}
          >
            ◆ {criticalCount} critical
          </span>
        </>
      )}
      <HudSep />
      <span style={{ color: spawnColor }}>spawn: {spawnMode}</span>
      {running && (
        <>
          <HudSep />
          <span style={{ display: "flex", alignItems: "center", gap: "5px", color: "#06b6d4" }}>
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "#06b6d4",
                boxShadow: "0 0 8px #06b6d4",
                animation: "depgraph-pulse 1s ease-in-out infinite",
              }}
            />
            scanning…
          </span>
        </>
      )}
    </div>
  );
}
