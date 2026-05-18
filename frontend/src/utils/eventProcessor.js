import { severityFromCvss } from "./severity";

export function formatLogLine(row) {
  const ev = row.event || "unknown";
  switch (ev) {
    case "nvd_result":
      return `${ev}: ${row.package} (${row.cve_count} CVEs, CVSS ${row.max_cvss})`;
    case "route_chosen":
      return `${ev}: ${row.mode} → ${row.targets} (from ${row.from_package})`;
    case "spawn_chosen":
      return `${ev}: ${row.mode} → ${row.targets}`;
    case "spawn_decision":
      return `${ev}: top ${row.llm_pool_count} of ${row.candidate_count}`;
    case "deep_dive":
      return `${ev}: ${row.package} critical (${row.cve_id})`;
    case "remediation_plan":
      return `${ev}: ${row.package} ${row.from} → ${row.to}`;
    default:
      return ev;
  }
}

export function logColor(ev) {
  if (ev.startsWith("spawn")) return "text-blue-400";
  if (ev.startsWith("route")) return "text-green-400";
  if (ev === "deep_dive" || ev === "deep_dive_finding") return "text-red-400 font-semibold";
  if (ev === "nvd_result" || ev === "nvd_lookup") return "text-gray-200";
  if (ev === "report_generated" || ev === "report_generating") return "text-purple-400";
  if (ev === "error") return "text-red-500";
  return "text-gray-500";
}

export function normalizeFindings(reports) {
  const deepDive = new Set();
  for (const row of reports) {
    if (row.event === "deep_dive" && row.package) {
      deepDive.add(row.package);
    }
  }
  for (const row of reports) {
    if (row.event === "investigation_complete" && Array.isArray(row.findings)) {
      return row.findings.map((f) => ({
        ...f,
        deep_dive_triggered:
          f.deep_dive_triggered || deepDive.has(f.package),
        severity: f.severity || severityFromCvss(f.max_cvss || 0),
        source: f.source || "osv",
      }));
    }
  }
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
      byPkg.set(pkg, {
        package: pkg,
        version: row.version || "",
        cve_count: cnt,
        max_cvss: cvss,
        top_cve: row.top_cve || "",
        severity: severityFromCvss(cvss),
        depth: row.depth ?? 0,
        is_direct: false,
        deep_dive_triggered: false,
        fixed_version: "",
        source: row.source || "osv",
      });
    }
  }
  return [...byPkg.values()].sort((a, b) => b.max_cvss - a.max_cvss);
}

export function getSummary(reports) {
  for (const row of reports) {
    if (row.event === "investigation_complete") {
      return row.executive_summary || row.summary || "";
    }
  }
  for (const row of reports) {
    if (row.event === "report_generated") return row.summary || "";
  }
  return "";
}

export function createInitialGraphState() {
  return {
    nodes: new Map(),
    edges: [],
    routeEdges: [],
    spawnEdges: [],
    activeNodeId: null,
    walkerNodeId: null,
    showVisitedOnly: false,
  };
}

export function applySnapshot(state, snapshot) {
  const next = { ...state, nodes: new Map(state.nodes) };
  for (const n of snapshot.nodes || []) {
    next.nodes.set(n.id, {
      ...n,
      visited: false,
      investigating: false,
      isSpawnRoot: n.is_spawn_root || false,
      severity: n.severity || severityFromCvss(n.cvss_score || 0),
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
  };
  const ev = row.event;

  if (ev === "graph_snapshot") {
    return applySnapshot(next, row);
  }

  if (ev === "spawn_roots") {
    for (const id of row.roots || []) {
      const node = next.nodes.get(id);
      if (node) next.nodes.set(id, { ...node, isSpawnRoot: true });
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
    next.walkerNodeId = null;
    return next;
  }

  if (ev === "route_chosen") {
    const from = row.from_package;
    const targets = String(row.targets || "").split(/\s+/).filter(Boolean);
    for (const t of targets) {
      const fromNode = [...next.nodes.values()].find((n) => n.name === from);
      const toNode = [...next.nodes.values()].find((n) => n.name === t);
      if (fromNode && toNode) {
        next.routeEdges.push({
          id: `route-${fromNode.id}-${toNode.id}`,
          source: fromNode.id,
          target: toNode.id,
          type: "route_path",
        });
        next.nodes.set(toNode.id, { ...toNode, visited: true });
      }
    }
    return next;
  }

  if (ev === "deep_dive") {
    const id = `${row.package}@${row.version}`;
    const node = next.nodes.get(id);
    if (node) {
      next.nodes.set(id, { ...node, critical: true, investigating: true });
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

export function computeStats(reports, graphState) {
  const complete = reports.find((r) => r.event === "investigation_complete");
  let routeLlm = 0;
  let routeFallback = 0;
  for (const r of reports) {
    if (r.event === "route_chosen") {
      if (r.mode === "llm") routeLlm += 1;
      else routeFallback += 1;
    }
  }
  return {
    packagesInGraph: complete?.packages_in_graph ?? graphState.nodes.size,
    scanned: complete?.packages_scanned ?? 0,
    vulnerable: complete?.vulnerable_count ?? 0,
    critical: complete?.critical_count ?? 0,
    spawnMode: complete?.spawn_mode ?? "—",
    routeLlm: complete?.route_llm_count ?? routeLlm,
    routeFallback: complete?.route_fallback_count ?? routeFallback,
    truncated: complete?.truncated,
    originalCount: complete?.original_package_count,
  };
}
