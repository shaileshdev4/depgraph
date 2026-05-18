import { Handle, Position } from "@xyflow/react";
import { SEVERITY_COLORS, severityFromCvss } from "../utils/severity";

export function RootNodeView({ data }) {
  return (
    <div
      style={{
        background: "linear-gradient(135deg, #050d1a 0%, #0a1828 100%)",
        border: "2px solid #06b6d4",
        boxShadow:
          "0 0 24px rgba(6,182,212,0.5), 0 0 48px rgba(6,182,212,0.2), inset 0 1px 0 rgba(6,182,212,0.1)",
        borderRadius: "50%",
        padding: "14px 22px",
        minWidth: "148px",
        textAlign: "center",
        color: "#e2e8f0",
        cursor: "default",
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ opacity: 0, pointerEvents: "none" }}
      />
      <div
        style={{
          fontSize: "13px",
          fontWeight: "700",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          color: "#67e8f9",
          letterSpacing: "-0.01em",
          maxWidth: "120px",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {data.name}
      </div>
      <div
        style={{
          fontSize: "10px",
          color: "#0e7490",
          marginTop: "3px",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        }}
      >
        v{data.version}
      </div>
      <div
        style={{
          fontSize: "8px",
          color: "#06b6d4",
          marginTop: "2px",
          letterSpacing: "0.15em",
          textTransform: "uppercase",
          opacity: 0.8,
        }}
      >
        root
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ opacity: 0.5 }}
      />
    </div>
  );
}

export function PackageNodeView({ data }) {
  const hasCVE = (data.cve_count || 0) > 0;
  const cvss = Number(data.cvss_score || 0);
  const sev =
    cvss > 0 ? severityFromCvss(cvss) : data.severity || "CLEAN";
  let palette = SEVERITY_COLORS[sev] || SEVERITY_COLORS.CLEAN;

  // CVE / CVSS severity always wins over spawn or visited styling
  if (!hasCVE && cvss < 4) {
    if (data.isSpawnRoot && (sev === "CLEAN" || sev === "LOW")) {
      palette = SEVERITY_COLORS.SPAWN;
    } else if (data.visited && sev === "CLEAN" && !data.isSpawnRoot) {
      palette = SEVERITY_COLORS.VISITED;
    }
  }

  const label =
    data.name?.length > 22 ? `${data.name.slice(0, 20)}…` : data.name;

  const boxShadow = data.investigating
    ? `0 0 0 3px rgba(6,182,212,0.7), 0 0 20px rgba(6,182,212,0.5), ${palette.glow}`
    : hasCVE
    ? palette.glow
    : "none";

  const entryAnim =
    sev === "CRITICAL"
      ? "depgraph-node-enter-stagger 0.25s ease-out forwards, depgraph-glow-pulse 2s ease-in-out 0.3s infinite"
      : "depgraph-node-enter-stagger 0.25s ease-out forwards";

  return (
    <div
      style={{
        background: palette.bg,
        border: `1.5px solid ${palette.border}`,
        boxShadow,
        borderRadius: "8px",
        padding: "9px 13px 8px",
        minWidth: "168px",
        maxWidth: "210px",
        color: "#e2e8f0",
        position: "relative",
        transition: "box-shadow 0.25s ease",
        cursor: "default",
        overflow: "hidden",
        animation: entryAnim,
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ opacity: 0.25, background: palette.border }}
      />

      {/* CVE diamond badge */}
      {hasCVE && (
        <div
          style={{
            position: "absolute",
            top: "-7px",
            right: "-7px",
            width: "14px",
            height: "14px",
            background: palette.badge,
            transform: "rotate(45deg)",
            boxShadow: `0 0 8px ${palette.badge}`,
            zIndex: 10,
          }}
        />
      )}

      {data.investigating && (
        <>
          <div
            style={{
              position: "absolute",
              inset: "-5px",
              borderRadius: "11px",
              border: "2px solid #06b6d4",
              animation: "depgraph-pulse 1.2s ease-in-out infinite",
              pointerEvents: "none",
              opacity: 0.8,
            }}
          />
          <div
            style={{
              position: "absolute",
              top: 0,
              left: "-100%",
              width: "60%",
              height: "100%",
              background:
                "linear-gradient(90deg, transparent, rgba(6,182,212,0.3), transparent)",
              animation: "depgraph-scan 1.2s ease-in-out infinite",
              pointerEvents: "none",
              borderRadius: "8px",
            }}
          />
        </>
      )}

      {/* Left accent bar for severity */}
      <div
        style={{
          position: "absolute",
          left: 0,
          top: "6px",
          bottom: "6px",
          width: "3px",
          borderRadius: "0 2px 2px 0",
          background: palette.cardAccent,
          opacity: hasCVE ? 1 : 0.4,
        }}
      />

      {/* Package name */}
      <div
        style={{
          fontSize: "11.5px",
          fontWeight: "600",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          color: hasCVE ? palette.text : "#94a3b8",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          paddingLeft: "6px",
        }}
      >
        {label}
      </div>

      {/* Version */}
      <div
        style={{
          fontSize: "9.5px",
          color: "#475569",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          paddingLeft: "6px",
          marginTop: "1px",
        }}
      >
        @{data.version}
      </div>

      {/* CVSS + CVE count */}
      {cvss > 0 && (
        <div
          style={{
            fontSize: "10.5px",
            color: palette.accent,
            marginTop: "4px",
            paddingLeft: "6px",
            fontWeight: "700",
            display: "flex",
            alignItems: "center",
            gap: "4px",
          }}
        >
          <span>CVSS {cvss.toFixed(1)}</span>
          {hasCVE && (
            <span
              style={{
                fontSize: "9px",
                color: palette.text,
                background: palette.badgeBg,
                border: `1px solid ${palette.border}`,
                borderRadius: "3px",
                padding: "0 4px",
                fontWeight: "600",
              }}
            >
              {data.cve_count} CVE
            </span>
          )}
        </div>
      )}

      {/* Bottom row: depth + spawn label */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginTop: "3px",
          paddingLeft: "6px",
        }}
      >
        <span
          style={{
            fontSize: "9px",
            color: "#2d3748",
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          }}
        >
          d{data.depth}
        </span>
        {data.isSpawnRoot && (
          <span
            style={{
              fontSize: "8px",
              color: "#06b6d4",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              opacity: 0.9,
            }}
          >
            SPAWN
          </span>
        )}
        {data.critical && !data.isSpawnRoot && (
          <span
            style={{
              fontSize: "8px",
              color: "#ef4444",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              animation: "depgraph-blink 1.5s ease-in-out infinite",
            }}
          >
            CRITICAL
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        style={{ opacity: 0.25, background: palette.border }}
      />
    </div>
  );
}

export const graphNodeTypes = {
  root: RootNodeView,
  package: PackageNodeView,
};