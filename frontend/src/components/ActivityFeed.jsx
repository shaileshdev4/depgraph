import { useEffect, useRef } from "react";
import { logColor } from "../utils/eventProcessor";

export default function ActivityFeed({ logEntries }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logEntries]);

  return (
    <div
      style={{
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: "11px",
        lineHeight: 1.65,
        paddingRight: "4px",
      }}
    >
      {logEntries.map((entry, i) => (
        <div
          key={`${entry.ts}-${i}`}
          style={{ ...parseLogStyle(logColor(entry.event)), padding: "2px 0" }}
        >
          <span style={{ color: "#475569", marginRight: "8px" }}>
            {new Date(entry.ts).toLocaleTimeString()}
          </span>
          {entry.line}
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

function parseLogStyle(colorStr) {
  if (!colorStr || typeof colorStr !== "string") return {};
  const style = {};
  const colorMatch = colorStr.match(/color:\s*([^;]+)/);
  const weightMatch = colorStr.match(/font-weight:\s*([^;]+)/);
  if (colorMatch) style.color = colorMatch[1].trim();
  if (weightMatch) style.fontWeight = weightMatch[1].trim();
  return style;
}
