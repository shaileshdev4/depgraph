export function severityFromCvss(cvss) {
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "CLEAN";
}

export const SEVERITY_COLORS = {
  CRITICAL: { bg: "#dc2626", border: "#ef4444", glow: "0 0 12px #dc262655" },
  HIGH: { bg: "#ea580c", border: "#f97316", glow: "0 0 10px #ea580c55" },
  MEDIUM: { bg: "#d97706", border: "#f59e0b", glow: "0 0 8px #d9770655" },
  LOW: { bg: "#2563eb", border: "#3b82f6", glow: "none" },
  CLEAN: { bg: "#1a1a1a", border: "#333333", glow: "none" },
  VISITED: { bg: "#1e3a2f", border: "#22c55e", glow: "none" },
  SPAWN: { bg: "#1e2a3a", border: "#3b82f6", glow: "0 0 10px #3b82f655" },
};
