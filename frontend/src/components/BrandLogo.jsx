/** DepGraph brand mark — served from /public/depgraph-logo.png */

export const LOGO_SRC = "/depgraph-logo.png";
export const LOGO_ALT = "DepGraph";

const MONO = "'JetBrains Mono', 'Fira Code', monospace";

export default function BrandLogo({
  size = 40,
  showText = true,
  compact = false,
  subtitle = null,
}) {
  const titleSize = compact ? "16px" : "48px";

  return (
    <div
      className="depgraph-brand"
      style={{
        display: "flex",
        flexDirection: compact ? "row" : "column",
        alignItems: "center",
        justifyContent: "center",
        gap: compact ? 10 : 16,
        textAlign: compact ? "left" : "center",
      }}
    >
      <img
        src={LOGO_SRC}
        alt={LOGO_ALT}
        width={size}
        height={size}
        className="depgraph-brand__mark"
        style={{
          width: size,
          height: size,
          objectFit: "contain",
          flexShrink: 0,
          display: "block",
        }}
        draggable={false}
      />
      {showText && (
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontSize: titleSize,
              fontWeight: 800,
              color: "#e2e8f0",
              letterSpacing: "-0.04em",
              fontFamily: MONO,
              lineHeight: 1.1,
              margin: 0,
            }}
          >
            <span style={{ color: "#06b6d4" }}>Dep</span>Graph
          </div>
          {subtitle != null && subtitle !== "" && (
            <div
              style={{
                fontSize: compact ? "10px" : "15px",
                color: compact ? "#334155" : "#475569",
                marginTop: compact ? "1px" : "8px",
                letterSpacing: "0.02em",
                lineHeight: 1.3,
              }}
            >
              {subtitle}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
