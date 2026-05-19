import { severityFromCvss } from "./severity";

// ── log formatting ───────────────────────────────────────────────────────────

export function formatLogLine(row) {
  const ev = row.event || "unknown";
  switch (ev) {
    case "session_started":
      return `session started · ${row.repo_url}`;
    case "lockfile_fetched":
      return `lockfile fetched: ${row.filename} (${row.manifest_kind})`;
    case "manifest_parsing":
      return `manifest parsing: ${row.filename} (${Math.round(row.bytes / 1024)}KB)`;
    case "manifest_parsed":
      return row.truncated
        ? `manifest parsed: ${row.package_count} packages in graph (risk filter from ${row.original_package_count}, ${row.filter_method})`
        : `manifest parsed: ${row.package_count} packages`;
    case "graph_built":
      return `graph built: ${row.package_count} nodes, ${row.edge_count} edges`;
    case "spawn_decision":
      return `spawn decision: LLM picks from top ${row.llm_pool_count ?? "?"} of ${row.candidate_count} candidates`;
    case "spawn_llm_failed":
      return `spawn LLM failed: ${row.reason}`;
    case "spawn_llm_partial":
      return `spawn partial: ${row.llm_picks} LLM picks, ${row.risk_picks} risk fallback (empty model response)`;
    case "spawn_chosen":
      return `spawn chosen: ${row.mode}${row.llm_picks != null ? ` (${row.llm_picks} LLM + ${row.risk_picks} risk)` : ""} → ${row.targets}`;
    case "nvd_lookup":
      return `nvd lookup: ${row.package}@${row.version}`;
    case "nvd_result":
      return `nvd result: ${row.package} (${row.cve_count} CVEs, max CVSS ${row.max_cvss}, ${row.source})`;
    case "route_decision": {
      const pkg = row.version ? `${row.package}@${row.version}` : row.package;
      return `route decision: ${pkg} → LLM picks 1 of ${row.neighbor_count} deps (cvss ${row.max_cvss ?? "?"})`;
    }
    case "route_chosen": {
      const idx = row.index ?? row.indexes?.[0] ?? "?";
      return `route chosen: ${row.mode} → ${row.targets} (from ${row.from_package}, idx ${idx})`;
    }
    case "deep_dive":
      return `deep dive: ${row.package} critical (${row.cve_id})`;
    case "deep_dive_finding":
      return `deep dive finding: ${row.package} CVSS ${row.cvss_score}`;
    case "deep_dive_complete":
      return `deep dive complete: ${row.findings_count ?? 0} additional findings`;
    case "usage_context": {
      const via =
        row.inherited_from?.length > 0
          ? `via ${row.inherited_from.join(", ")}`
          : `${row.importing_file_count ?? 0} files`;
      return `usage context: ${row.package} → ${row.surface || "unknown"} (${via})`;
    }
    case "remediation_plan":
      return `remediation plan: ${row.package} ${row.from} → ${row.to} [${row.status}]`;
    case "report_generating":
      return `report generating…`;
    case "report_generated":
      return `report generated`;
    case "investigation_complete":
      return `investigation complete: ${row.vulnerable_count} vulnerable, ${row.packages_scanned} OSV lookups (${row.subtrees_spawned} subtrees)`;
    case "error":
      return `error: ${row.message}`;
    default:
      return ev;
  }
}

export function logColor(ev) {
  if (ev === "session_started" || ev === "session_created") return "color: #475569";
  if (ev.startsWith("spawn")) return "color: #06b6d4";
  if (ev.startsWith("route")) return "color: #22c55e";
  if (ev === "deep_dive" || ev === "deep_dive_finding") return "color: #ef4444; font-weight: 600";
  if (ev === "deep_dive_complete") return "color: #f87171";
  if (ev === "nvd_result" || ev === "nvd_lookup") return "color: #94a3b8";
  if (ev === "usage_context") return "color: #a78bfa";
  if (ev === "remediation_plan") return "color: #34d399";
  if (ev === "report_generated" || ev === "report_generating") return "color: #c084fc";
  if (ev === "investigation_complete") return "color: #67e8f9; font-weight: 600";
  if (ev === "error") return "color: #ef4444; font-weight: 700";
  if (ev === "graph_built" || ev === "graph_snapshot") return "color: #1e4d6b";
  return "color: #334155";
}

export function logColorClass(ev) {
  if (ev === "session_started" || ev === "session_created") return "text-slate-500";
  if (ev.startsWith("spawn")) return "text-cyan-400";
  if (ev.startsWith("route")) return "text-green-400";
  if (ev === "deep_dive" || ev === "deep_dive_finding") return "text-red-400 font-semibold";
  if (ev === "deep_dive_complete") return "text-red-300";
  if (ev === "nvd_result" || ev === "nvd_lookup") return "text-slate-300";
  if (ev === "usage_context") return "text-violet-400";
  if (ev === "remediation_plan") return "text-emerald-400";
  if (ev === "report_generated" || ev === "report_generating") return "text-purple-400";
  if (ev === "investigation_complete") return "text-cyan-300 font-semibold";
  if (ev === "error") return "text-red-500 font-bold";
  if (ev === "graph_built") return "text-slate-600";
  if (ev === "graph_snapshot") return "text-slate-700";
  return "text-slate-600";
}

// ── findings normalization ───────────────────────────────────────────────────

export function computeExploitability(cvss, usageSurface) {
  const score = Number(cvss || 0);
  const surface = String(usageSurface || "unknown").toLowerCase();
  if (score >= 7 && surface === "production") return "CRITICAL";
  if (score >= 4 && surface === "production") return "HIGH";
  if (surface === "test") return "LOW";
  return "MEDIUM";
}

function usageSurfaceRank(surface) {
  const s = String(surface || "unknown").toLowerCase();
  if (s === "production") return 4;
  if (s === "mixed") return 3;
  if (s === "build") return 2;
  if (s === "test") return 1;
  return 0;
}

function mergeUsageContext(map, row) {
  if (!row?.package) return;
  const surface = row.surface || row.risk_surface || "unknown";
  const next = {
    surface,
    importing_file_count: row.importing_file_count ?? 0,
    is_prod: row.is_prod ?? surface === "production",
    inherited_from: row.inherited_from || [],
  };
  const existing = map.get(row.package);
  if (!existing || usageSurfaceRank(next.surface) > usageSurfaceRank(existing.surface)) {
    map.set(row.package, next);
  }
}

/** Patch live findings when a usage_context event arrives after CVE cards exist. */
export function applyUsageContextToFindings(findings, row) {
  if (!row?.package || !Array.isArray(findings) || findings.length === 0) {
    return findings;
  }
  const surface = row.surface || row.risk_surface || "unknown";
  return findings.map((f) => {
    if (f.package !== row.package) return f;
    const usage_surface =
      usageSurfaceRank(surface) > usageSurfaceRank(f.usage_surface)
        ? surface
        : f.usage_surface || surface;
    return {
      ...f,
      usage_surface,
      usage_inherited_from:
        row.inherited_from?.length > 0
          ? row.inherited_from
          : f.usage_inherited_from,
      exploitability: computeExploitability(f.max_cvss, usage_surface),
    };
  });
}

export function normalizeFindings(reports) {
  const deepDiveSet = new Set();
  const remediationMap = new Map();
  const usageMap = new Map();

  for (const row of reports) {
    if (row.event === "deep_dive" && row.package) {
      deepDiveSet.add(row.package);
    }
    if (row.event === "remediation_plan" && row.package) {
      remediationMap.set(row.package, {
        from: row.from,
        to: row.to,
        status: row.status,
        confidence: row.confidence,
        breaking_changes: row.breaking_changes || [],
      });
    }
    if (row.event === "usage_context") {
      mergeUsageContext(usageMap, row);
    }
  }

  // Prefer investigation_complete findings
  for (const row of reports) {
    if (row.event === "investigation_complete" && Array.isArray(row.findings)) {
      return row.findings
        .map((f) => {
          const usageCtx = usageMap.get(f.package);
          const usage_surface =
            usageCtx?.surface || f.usage_surface || "unknown";
          return {
            ...f,
            deep_dive_triggered: f.deep_dive_triggered || deepDiveSet.has(f.package),
            severity: f.severity || severityFromCvss(f.max_cvss || 0),
            source: f.source || "osv",
            remediation: remediationMap.get(f.package) || null,
            usage_surface,
            exploitability: computeExploitability(f.max_cvss, usage_surface),
            usage_inherited_from:
              f.usage_inherited_from ||
              (usageCtx?.inherited_from?.length ? usageCtx.inherited_from : null),
          };
        })
        .sort((a, b) => (b.max_cvss || 0) - (a.max_cvss || 0));
    }
  }

  // Fallback: reconstruct from nvd_result events
  const byPkg = new Map();
  for (const row of reports) {
    if (row.event !== "nvd_result") continue;
    const cvss = Number(row.max_cvss || 0);
    const cnt = Number(row.cve_count || 0);
    if (cvss <= 0 && cnt <= 0) continue;
    const pkg = row.package;
    if (!pkg) continue;
    const existing = byPkg.get(pkg);
    if (!existing || cvss > existing.max_cvss) {
      const usage_surface = usageMap.get(pkg)?.surface || "unknown";
      byPkg.set(pkg, {
        package: pkg,
        version: row.version || "",
        cve_count: cnt,
        max_cvss: cvss,
        top_cve: row.top_cve || "",
        severity: severityFromCvss(cvss),
        depth: row.depth ?? 0,
        is_direct: false,
        deep_dive_triggered: deepDiveSet.has(pkg),
        fixed_version: row.fixed_version || "",
        source: row.source || "osv",
        remediation: remediationMap.get(pkg) || null,
        usage_surface,
        exploitability: computeExploitability(cvss, usage_surface),
      });
    }
  }
  return [...byPkg.values()].sort((a, b) => b.max_cvss - a.max_cvss);
}

// ── remediation list ─────────────────────────────────────────────────────────

export function normalizeRemediations(reports) {
  const plans = [];
  for (const row of reports) {
    if (row.event === "remediation_plan") {
      plans.push({
        package: row.package,
        from: row.from,
        to: row.to,
        status: row.status || "pending",
        confidence: row.confidence ?? 0,
        breaking_changes: row.breaking_changes || [],
      });
    }
  }
  return plans;
}

// ── usage context list ────────────────────────────────────────────────────────

export function normalizeUsageContexts(reports) {
  const map = new Map();
  for (const row of reports) {
    if (row.event === "usage_context") {
      const surface = row.surface || row.risk_surface || "unknown";
      const next = {
        package: row.package,
        surface,
        importing_files: row.importing_files || [],
        importing_file_count: row.importing_file_count ?? 0,
        is_prod: row.is_prod ?? false,
        inherited_from: row.inherited_from || [],
      };
      const existing = map.get(row.package);
      if (!existing || usageSurfaceRank(next.surface) > usageSurfaceRank(existing.surface)) {
        map.set(row.package, next);
      }
    }
  }
  return [...map.values()];
}

// ── summary ───────────────────────────────────────────────────────────────────

function sanitizeSummaryMarkdown(text) {
  if (!text) return "";
  let out = String(text).trim();
  const fenced = out.match(/^```(?:markdown|md)?\s*([\s\S]*?)```$/i);
  if (fenced) out = fenced[1].trim();
  return out
    .replace(/\[([^\]]+)\]\(mailto:[^)]*\)/gi, "`$1`")
    .replace(/\[([^\]]+@[^\]]+)\]\([^)]*\)/g, "`$1`");
}

export function getSummary(reports) {
  for (const row of reports) {
    if (row.event === "investigation_complete") {
      return sanitizeSummaryMarkdown(row.executive_summary || row.summary || "");
    }
  }
  for (const row of reports) {
    if (row.event === "report_generated") {
      return sanitizeSummaryMarkdown(row.summary || "");
    }
  }
  return "";
}

// ── graph state ───────────────────────────────────────────────────────────────

export function createInitialGraphState() {
  return {
    nodes: new Map(),
    edges: [],
    routeEdges: [],
    spawnEdges: [],
    hotEdges: new Map(),
    activeNodeId: null,
    walkerNodeId: null,
  };
}

function findRootNodeId(nodes) {
  for (const n of nodes.values()) {
    if (n.depth === 0) return n.id;
  }
  return nodes.size > 0 ? [...nodes.keys()][0] : null;
}

export function applySnapshot(state, snapshot) {
  const next = { ...state, nodes: new Map(state.nodes) };
  for (const n of snapshot.nodes || []) {
    const kind = n.depth === 0 ? "root" : "package";
    const existing = state.nodes.get(n.id);
    const incomingCvss = Number(n.cvss_score || 0);
    const existingCvss = Number(existing?.cvss_score || 0);
    const cvss = Math.max(incomingCvss, existingCvss);
    const cveCount = Math.max(Number(n.cve_count || 0), Number(existing?.cve_count || 0));
    next.nodes.set(n.id, {
      ...n,
      kind,
      visited: existing?.visited ?? false,
      investigating: existing?.investigating ?? false,
      isSpawnRoot: n.is_spawn_root || existing?.isSpawnRoot || false,
      cvss_score: cvss,
      cve_count: cveCount,
      critical: existing?.critical ?? false,
      severity: severityFromCvss(cvss),
      usage_surface: existing?.usage_surface ?? n.usage_surface,
      usage_is_prod: existing?.usage_is_prod ?? n.usage_is_prod,
    });
  }
  const depEdges = (snapshot.edges || []).map((e, i) => ({
    id: `dep-${e.source}-${e.target}-${i}`,
    source: e.source,
    target: e.target,
    type: "depends_on",
  }));
  next.edges = depEdges;
  return next;
}

export function applyEvent(state, row) {
  const next = {
    ...state,
    nodes: new Map(state.nodes),
    routeEdges: [...state.routeEdges],
    spawnEdges: [...state.spawnEdges],
    hotEdges: new Map(state.hotEdges || []),
  };
  const ev = row.event;

  if (ev === "graph_snapshot") {
    return applySnapshot(next, row);
  }

  if (ev === "spawn_roots") {
    const rootId = findRootNodeId(next.nodes);
    for (const id of row.roots || []) {
      const node = next.nodes.get(id);
      if (node) next.nodes.set(id, { ...node, isSpawnRoot: true });
      if (rootId && id !== rootId) {
        const edgeId = `spawn-${rootId}-${id}`;
        if (!next.spawnEdges.find((e) => e.id === edgeId)) {
          next.spawnEdges.push({
            id: edgeId,
            source: rootId,
            target: id,
            type: "spawn_path",
          });
        }
      }
    }
    return next;
  }

  if (ev === "nvd_lookup") {
    const id = `${row.package}@${row.version}`;
    const node = next.nodes.get(id);
    if (node) {
      next.nodes.set(id, { ...node, investigating: true });
      next.walkerNodeId = id;
    }
    return next;
  }

  if (ev === "nvd_result") {
    const id = `${row.package}@${row.version}`;
    const node = next.nodes.get(id);
    const cvss = Number(row.max_cvss || 0);
    if (node) {
      next.nodes.set(id, {
        ...node,
        visited: true,
        investigating: false,
        cvss_score: cvss,
        cve_count: row.cve_count || 0,
        severity: severityFromCvss(cvss),
        critical: !!row.critical,
      });
    }
    if (next.walkerNodeId === id) next.walkerNodeId = null;
    return next;
  }

  if (ev === "route_chosen") {
    const from = row.from_package;
    const targets = String(row.targets || "")
      .split(/\s+/)
      .filter(Boolean);
    for (const t of targets) {
      const fromNode = [...next.nodes.values()].find((n) => n.name === from);
      const toNode = [...next.nodes.values()].find((n) => n.name === t);
      if (fromNode && toNode) {
        const isCritical =
          fromNode.critical ||
          fromNode.severity === "CRITICAL" ||
          Number(fromNode.cvss_score || 0) >= 9;
        const edgeId = `route-${fromNode.id}-${toNode.id}`;
        if (!next.routeEdges.find((e) => e.id === edgeId)) {
          next.routeEdges.push({
            id: edgeId,
            source: fromNode.id,
            target: toNode.id,
            type: isCritical ? "critical_path" : "route_path",
          });
        }
        next.hotEdges.set(edgeId, Date.now());
        next.nodes.set(toNode.id, {
          ...toNode,
          visited: true,
          investigating: true,
        });
      }
    }
    return next;
  }

  if (ev === "deep_dive") {
    const id = `${row.package}@${row.version}`;
    const node = next.nodes.get(id);
    if (node) {
      next.nodes.set(id, {
        ...node,
        critical: true,
        investigating: true,
        severity: "CRITICAL",
      });
    }
    return next;
  }

  if (ev === "usage_context") {
    const pkg = row.package;
    const node = [...next.nodes.values()].find((n) => n.name === pkg);
    if (node) {
      next.nodes.set(node.id, {
        ...node,
        usage_surface: row.surface || row.risk_surface || "unknown",
        usage_is_prod: row.is_prod ?? false,
      });
    }
    return next;
  }

  if (ev === "investigation_complete") {
    next.walkerNodeId = null;
    for (const [id, node] of next.nodes) {
      if (node.investigating) {
        next.nodes.set(id, { ...node, investigating: false });
      }
    }
    return next;
  }

  return next;
}

// ── stats ─────────────────────────────────────────────────────────────────────

export function computeStats(reports, graphState) {
  const complete = reports.find((r) => r.event === "investigation_complete");
  const spawnChosen = [...reports].reverse().find((r) => r.event === "spawn_chosen");
  const graphBuilt = reports.find((r) => r.event === "graph_built");
  const manifestParsed = reports.find((r) => r.event === "manifest_parsed");

  let routeLlm = 0;
  let routeFallback = 0;
  let criticalCount = 0;

  for (const r of reports) {
    if (r.event === "route_chosen") {
      if (r.mode === "llm") routeLlm++;
      else routeFallback++;
    }
    if (r.event === "nvd_result" && r.critical) criticalCount++;
  }

  // More accurate critical count from findings
  if (complete?.findings) {
    criticalCount = complete.findings.filter(
      (f) => Number(f.max_cvss || 0) >= 9.0
    ).length;
  }

  return {
    packagesInGraph:
      complete?.packages_in_graph ??
      graphBuilt?.package_count ??
      graphState.nodes.size,
    scanned: complete?.packages_scanned ?? 0,
    vulnerable: complete?.vulnerable_count ?? 0,
    critical: criticalCount,
    spawnMode: spawnChosen?.mode ?? "—",
    routeLlm,
    routeFallback,
    truncated: manifestParsed?.truncated ?? false,
    originalCount: manifestParsed?.original_package_count,
    filterMethod: manifestParsed?.filter_method,
  };
}

export function computeStatsFromSnapshot(snap, graphState, reports = []) {
  return computeStats(reports, graphState);
}