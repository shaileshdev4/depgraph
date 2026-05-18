export default function StatsBar({ stats, running }) {
  const critical = stats.critical ?? 0;
  const vulnerable = stats.vulnerable ?? 0;

  return (
    <div
      style={{
        borderTop: "1px solid #1e2d3d",
        paddingTop: "12px",
        display: "flex",
        flexWrap: "wrap",
        gap: "8px",
        alignItems: "center",
      }}
    >
      <StatCard
        icon="⬡"
        label="In Graph"
        value={
          stats.truncated
            ? `${stats.packagesInGraph ?? "—"} / ${stats.originalCount}`
            : (stats.packagesInGraph ?? "—")
        }
        sub={stats.truncated ? "risk filtered" : stats.filterMethod || null}
        subColor="#475569"
      />
      <StatCard
        icon="⊙"
        label="Scanned"
        value={stats.scanned ?? "—"}
        iconColor="#06b6d4"
      />
      <StatCard
        icon="◈"
        label="Vulnerable"
        value={vulnerable}
        valueColor={vulnerable > 0 ? "#f97316" : "#475569"}
        iconColor={vulnerable > 0 ? "#f97316" : "#334155"}
        glow={vulnerable > 0}
        glowColor="rgba(249,115,22,0.15)"
      />
      <StatCard
        icon="◆"
        label="Critical"
        value={critical}
        valueColor={critical > 0 ? "#ef4444" : "#475569"}
        iconColor={critical > 0 ? "#ef4444" : "#334155"}
        pulse={critical > 0}
        glow={critical > 0}
        glowColor="rgba(239,68,68,0.18)"
      />
      <Divider />
      <StatCard
        icon="⇡"
        label="Spawn"
        value={stats.spawnMode ?? "—"}
        valueColor={
          stats.spawnMode === "llm"
            ? "#22c55e"
            : stats.spawnMode === "fallback"
            ? "#eab308"
            : "#475569"
        }
        iconColor={stats.spawnMode === "llm" ? "#22c55e" : "#334155"}
        sub={
          stats.spawnMode === "llm"
            ? "LLM selected"
            : stats.spawnMode === "fallback"
            ? "risk ranked"
            : null
        }
      />
      <StatCard
        icon="⤳"
        label="Route LLM"
        value={stats.routeLlm ?? 0}
        valueColor={(stats.routeLlm ?? 0) > 0 ? "#22c55e" : "#475569"}
        iconColor={(stats.routeLlm ?? 0) > 0 ? "#22c55e" : "#334155"}
      />
      <StatCard
        icon="⤳"
        label="Route fallback"
        value={stats.routeFallback ?? 0}
        valueColor={(stats.routeFallback ?? 0) > 0 ? "#eab308" : "#475569"}
        iconColor="#334155"
      />

      {running && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            marginLeft: "auto",
            fontSize: "11px",
            color: "#06b6d4",
          }}
        >
          <div
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              background: "#06b6d4",
              animation: "depgraph-pulse 1s ease-in-out infinite",
            }}
          />
          Investigating…
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  sub,
  subColor = "#334155",
  valueColor = "#e2e8f0",
  iconColor = "#334155",
  pulse = false,
  glow = false,
  glowColor = "transparent",
}) {
  return (
    <div
      style={{
        borderRadius: "8px",
        border: "1px solid #1a2332",
        background: glow
          ? `linear-gradient(135deg, #0a0f1a 0%, #0d1220 100%)`
          : "linear-gradient(135deg, #080c14 0%, #0b1018 100%)",
        padding: "7px 12px",
        minWidth: "80px",
        boxShadow: glow ? `0 0 16px ${glowColor}` : "none",
        transition: "box-shadow 0.3s",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "5px", marginBottom: "3px" }}>
        <span
          style={{
            fontSize: "10px",
            color: iconColor,
            animation: pulse ? "depgraph-blink 1.5s ease-in-out infinite" : "none",
          }}
        >
          {icon}
        </span>
        <span style={{ fontSize: "9.5px", color: "#334155", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          {label}
        </span>
      </div>
      <div
        style={{
          fontSize: "18px",
          fontWeight: "700",
          color: valueColor,
          lineHeight: "1",
          fontVariantNumeric: "tabular-nums",
          animation: pulse ? "depgraph-blink 1.5s ease-in-out infinite" : "none",
        }}
      >
        {value}
      </div>
      {sub && (
        <div style={{ fontSize: "9px", color: subColor, marginTop: "2px" }}>
          {sub}
        </div>
      )}
    </div>
  );
}

function Divider() {
  return (
    <div
      style={{
        width: "1px",
        height: "40px",
        background: "linear-gradient(180deg, transparent, #1e2d3d, transparent)",
        flexShrink: 0,
      }}
    />
  );
}