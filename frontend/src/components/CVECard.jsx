import { SEVERITY_COLORS } from "../utils/severity";

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, CLEAN: 4 };

const EXPLOITABILITY_STYLE = {
  CRITICAL: { color: "#ef4444", bg: "rgba(239,68,68,0.12)", border: "rgba(239,68,68,0.45)" },
  HIGH: { color: "#f97316", bg: "rgba(249,115,22,0.12)", border: "rgba(249,115,22,0.4)" },
  MEDIUM: { color: "#eab308", bg: "rgba(234,179,8,0.1)", border: "rgba(234,179,8,0.35)" },
  LOW: { color: "#64748b", bg: "rgba(100,116,139,0.12)", border: "rgba(100,116,139,0.3)" },
};

function exploitabilityVerdict(exploitability, cvss, usageSurface, inheritedFrom) {
  const exp = String(exploitability || "MEDIUM").toUpperCase();
  const surface = String(usageSurface || "unknown").toLowerCase();
  const surfaceLabel =
    surface === "production"
      ? "production code"
      : surface === "test"
      ? "test-only usage"
      : surface === "build"
      ? "build tooling"
      : surface === "mixed"
      ? "mixed prod+test"
      : "usage unknown";
  const via =
    inheritedFrom?.length > 0
      ? ` (reachable via ${inheritedFrom.join(", ")})`
      : "";
  return {
    exp,
    line: `CVSS ${cvss} + ${surfaceLabel}${via} = ${exp} EXPLOITABILITY`,
  };
}

export default function CVECard({ finding }) {
  const sev = finding.severity || "LOW";
  const pal = SEVERITY_COLORS[sev] || SEVERITY_COLORS.LOW;
  const cvss = Number(finding.max_cvss || 0).toFixed(1);
  const verdict = exploitabilityVerdict(
    finding.exploitability,
    cvss,
    finding.usage_surface,
    finding.usage_inherited_from
  );
  const expStyle = EXPLOITABILITY_STYLE[verdict.exp] || EXPLOITABILITY_STYLE.MEDIUM;
  const cveLink = finding.top_cve
    ? `https://nvd.nist.gov/vuln/detail/${finding.top_cve}`
    : null;

  return (
    <li
      style={{
        borderRadius: "10px",
        border: `1px solid #1e2d3d`,
        background: "linear-gradient(135deg, #0a0f1a 0%, #0d1220 100%)",
        overflow: "hidden",
        position: "relative",
        transition: "border-color 0.2s, box-shadow 0.2s",
        animation: "depgraph-card-enter 0.2s ease-out forwards",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = pal.border;
        e.currentTarget.style.boxShadow = pal.glow;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "#1e2d3d";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      <div
        style={{
          height: "6px",
          background: pal.cardAccent,
          borderRadius: "10px 10px 0 0",
          boxShadow: `0 2px 12px ${pal.badge}40`,
        }}
      />

      <div style={{ padding: "12px 14px" }}>
        {/* Header row */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "8px" }}>
          <div style={{ minWidth: 0 }}>
            <div
              style={{
                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                fontSize: "12.5px",
                fontWeight: "700",
                color: "#e2e8f0",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {finding.package}
              <span style={{ color: "#475569", fontWeight: "400" }}>@{finding.version}</span>
            </div>
            <div style={{ fontSize: "10px", color: "#334155", marginTop: "2px", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
              depth {finding.depth ?? "?"} · {finding.is_direct ? "direct" : "transitive"}
            </div>
          </div>

          {/* Severity badge */}
          <span
            style={{
              fontSize: "9.5px",
              fontWeight: "800",
              letterSpacing: "0.08em",
              padding: "2px 8px",
              borderRadius: "4px",
              border: `1px solid ${pal.border}`,
              background: pal.badgeBg,
              color: pal.badge,
              flexShrink: 0,
              textTransform: "uppercase",
            }}
          >
            {sev}
          </span>
        </div>

        {/* CVSS score — large */}
        <div style={{ marginTop: "10px", display: "flex", alignItems: "baseline", gap: "6px" }}>
          <span
            style={{
              fontSize: "36px",
              fontWeight: "800",
              lineHeight: "1",
              color: pal.accent,
              fontVariantNumeric: "tabular-nums",
              textShadow: cvss >= 7 ? `0 0 16px ${pal.accent}60` : "none",
            }}
          >
            {cvss}
          </span>
          <div>
            <div style={{ fontSize: "9px", color: "#475569", letterSpacing: "0.1em", textTransform: "uppercase" }}>CVSS</div>
            <div style={{ fontSize: "9px", color: "#334155" }}>
              {finding.cve_count} CVE{finding.cve_count !== 1 ? "s" : ""} · {finding.source || "osv"}
            </div>
          </div>
        </div>

        {finding.exploitability && (
          <div
            style={{
              marginTop: "10px",
              padding: "8px 10px",
              borderRadius: "6px",
              background: expStyle.bg,
              border: `1px solid ${expStyle.border}`,
            }}
          >
            <div
              style={{
                fontSize: "11px",
                fontWeight: 800,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                color: expStyle.color,
              }}
            >
              {verdict.exp} exploitability
            </div>
            <div style={{ fontSize: "10px", color: "#94a3b8", marginTop: "3px", lineHeight: 1.4 }}>
              {verdict.line}
            </div>
          </div>
        )}

        {/* CVE link */}
        {cveLink && (
          <a
            href={cveLink}
            target="_blank"
            rel="noreferrer"
            style={{
              display: "inline-block",
              marginTop: "8px",
              fontSize: "10.5px",
              color: "#3b82f6",
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              textDecoration: "none",
            }}
            onMouseEnter={(e) => (e.target.style.textDecoration = "underline")}
            onMouseLeave={(e) => (e.target.style.textDecoration = "none")}
          >
            {finding.top_cve} ↗
          </a>
        )}

        {/* Tags row */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "5px", marginTop: "10px" }}>
          {finding.deep_dive_triggered && (
            <Tag color="#ef4444" bg="rgba(239,68,68,0.1)">⬡ Deep Dive</Tag>
          )}
          {finding.usage_surface && finding.usage_surface !== "unknown" && (
            <Tag
              color={finding.usage_surface === "production" ? "#f97316" : "#64748b"}
              bg={
                finding.usage_surface === "production"
                  ? "rgba(249,115,22,0.1)"
                  : "rgba(71,85,105,0.1)"
              }
            >
              {finding.usage_surface === "production" ? "⚠ prod" : `${finding.usage_surface}`}
            </Tag>
          )}
          {finding.is_direct && (
            <Tag color="#06b6d4" bg="rgba(6,182,212,0.08)">direct dep</Tag>
          )}
        </div>

        {/* Fixed version / remediation */}
        {finding.fixed_version && (
          <div
            style={{
              marginTop: "10px",
              padding: "7px 10px",
              borderRadius: "6px",
              background: "rgba(34,197,94,0.06)",
              border: "1px solid rgba(34,197,94,0.2)",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <span style={{ fontSize: "10px", color: "#22c55e" }}>✓</span>
            <div>
              <div style={{ fontSize: "9.5px", color: "#64748b", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                Fix available
              </div>
              <div style={{ fontSize: "11px", fontFamily: "'JetBrains Mono', 'Fira Code', monospace", color: "#22c55e", marginTop: "1px" }}>
                Upgrade to {finding.fixed_version}
              </div>
            </div>
          </div>
        )}

        {/* Remediation plan from backend */}
        {finding.remediation && (
          <div
            style={{
              marginTop: "8px",
              padding: "7px 10px",
              borderRadius: "6px",
              background: "rgba(6,182,212,0.05)",
              border: "1px solid rgba(6,182,212,0.15)",
            }}
          >
            <div style={{ fontSize: "9.5px", color: "#0e7490", letterSpacing: "0.06em", textTransform: "uppercase" }}>
              Remediation plan
            </div>
            <div style={{ fontSize: "11px", fontFamily: "'JetBrains Mono', 'Fira Code', monospace", color: "#67e8f9", marginTop: "2px" }}>
              {finding.remediation.from} → {finding.remediation.to}
            </div>
            {finding.remediation.breaking_changes?.length > 0 && (
              <div style={{ fontSize: "10px", color: "#eab308", marginTop: "2px" }}>
                ⚠ {finding.remediation.breaking_changes.length} breaking change
                {finding.remediation.breaking_changes.length !== 1 ? "s" : ""}
              </div>
            )}
            <div
              style={{
                fontSize: "9px",
                color:
                  finding.remediation.status === "validated"
                    ? "#22c55e"
                    : finding.remediation.status === "conflict"
                    ? "#ef4444"
                    : "#64748b",
                marginTop: "2px",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}
            >
              {finding.remediation.status || "pending"}
            </div>
          </div>
        )}
      </div>
    </li>
  );
}

function Tag({ color, bg, children }) {
  return (
    <span
      style={{
        fontSize: "9px",
        fontWeight: "600",
        color,
        background: bg,
        border: `1px solid ${color}40`,
        borderRadius: "4px",
        padding: "1px 6px",
        letterSpacing: "0.04em",
        textTransform: "uppercase",
      }}
    >
      {children}
    </span>
  );
}