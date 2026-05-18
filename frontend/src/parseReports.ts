import type {
  Finding,
  GraphEdge,
  InvestigationResult,
  PackageNode,
  ReportEvent,
} from "./types";

function formatLogLine(row: ReportEvent): string {
  const ev = String(row.event ?? "unknown");
  switch (ev) {
    case "nvd_result": {
      const pkg = String(row.package ?? "?");
      const cnt = Number(row.cve_count ?? 0);
      const cvss = Number(row.max_cvss ?? 0);
      return `- ${ev}: ${pkg} (${cnt} CVEs, max CVSS ${cvss})`;
    }
    case "route_chosen": {
      const mode = String(row.mode ?? "?");
      const targets = String(row.targets ?? "?");
      const frm = String(row.from_package ?? "?");
      return `- ${ev}: ${mode} → ${targets} (from ${frm})`;
    }
    case "spawn_chosen": {
      const mode = String(row.mode ?? "?");
      const targets = String(row.targets ?? "?");
      const llm = Number(row.llm_picks ?? 0);
      const risk = Number(row.risk_picks ?? 0);
      if (risk > 0) {
        return `- ${ev}: ${mode} (${llm} LLM + ${risk} risk) → ${targets}`;
      }
      return `- ${ev}: ${mode} → ${targets}`;
    }
    case "spawn_decision": {
      const pool = Number(row.llm_pool_count ?? row.candidate_count ?? 0);
      const cnt = Number(row.candidate_count ?? 0);
      return `- ${ev}: LLM picks from top ${pool} of ${cnt} candidates`;
    }
    case "spawn_llm_partial": {
      return `- ${ev}: ${row.llm_picks} LLM, ${row.risk_picks} risk fallback`;
    }
    case "deep_dive": {
      return `- ${ev}: ${row.package} critical (${row.cve_id})`;
    }
    case "investigation_complete": {
      const vuln = Number(row.vulnerable_count ?? 0);
      const scanned = Number(row.packages_scanned ?? 0);
      return `- ${ev}: ${vuln} vulnerable, ${scanned} OSV lookups`;
    }
    default:
      return `- ${ev}`;
  }
}

export function buildGraphFromReports(reports: ReportEvent[]): {
  nodes: PackageNode[];
  edges: GraphEdge[];
} {
  const nodeMap = new Map<string, PackageNode>();
  const spawned = new Set<string>();
  const edges: GraphEdge[] = [];
  const edgeKeys = new Set<string>();

  const upsert = (
    name: string,
    patch: Partial<PackageNode> = {}
  ): PackageNode => {
    const id = name;
    const existing = nodeMap.get(id);
    const base: PackageNode = existing ?? {
      id,
      label: name,
      version: patch.version ?? "",
      maxCvss: 0,
      cveCount: 0,
      topCve: "",
      spawned: false,
      investigated: false,
    };
    const merged = { ...base, ...patch, id, label: name };
    nodeMap.set(id, merged);
    return merged;
  };

  const addEdge = (from: string, to: string, animated = true) => {
    const key = `${from}->${to}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ id: key, source: from, target: to, animated });
  };

  for (const row of reports) {
    const ev = String(row.event ?? "");
    if (ev === "spawn_chosen") {
      const targets = String(row.targets ?? "")
        .split(/\s+/)
        .filter(Boolean);
      for (const t of targets) {
        spawned.add(t);
        upsert(t, { spawned: true, investigated: true });
      }
    }
    if (ev === "route_chosen") {
      const from = String(row.from_package ?? "");
      const targets = String(row.targets ?? "")
        .split(/\s+/)
        .filter(Boolean);
      if (from) {
        upsert(from, { investigated: true });
        for (const t of targets) {
          upsert(t, { investigated: true });
          addEdge(from, t);
        }
      }
    }
    if (ev === "nvd_lookup" || ev === "nvd_result") {
      const pkg = String(row.package ?? "");
      const ver = String(row.version ?? "");
      if (!pkg) continue;
      upsert(pkg, {
        version: ver || nodeMap.get(pkg)?.version || "",
        investigated: true,
        ...(ev === "nvd_result"
          ? {
              maxCvss: Number(row.max_cvss ?? 0),
              cveCount: Number(row.cve_count ?? 0),
              topCve: "",
            }
          : {}),
      });
    }
    if (ev === "investigation_complete" && Array.isArray(row.findings)) {
      for (const f of row.findings as Finding[]) {
        upsert(f.package, {
          version: f.version,
          maxCvss: f.max_cvss,
          cveCount: f.cve_count,
          topCve: f.top_cve,
          investigated: true,
        });
      }
    }
  }

  return { nodes: [...nodeMap.values()], edges };
}

export function parseInvestigationReports(
  reports: ReportEvent[]
): InvestigationResult {
  const logLines = reports.map(formatLogLine);
  let findings: Finding[] = [];
  let summary = "";

  for (const row of reports) {
    if (row.event === "investigation_complete") {
      if (Array.isArray(row.findings)) {
        findings = row.findings as Finding[];
      }
      summary =
        String(row.executive_summary ?? row.summary ?? "") ||
        summary;
    }
    if (row.event === "report_generated" && row.summary) {
      summary = String(row.summary);
    }
  }

  return { reports, findings, summary, logLines };
}

export { buildGraphFromReports as buildGraph };
