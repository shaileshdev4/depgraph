import dagre from "dagre";
import type { Node, Edge } from "@xyflow/react";
import type { GraphEdge, PackageNode } from "./types";

export function cvssColor(cvss: number): string {
  if (cvss >= 9) return "#f85149";
  if (cvss >= 7) return "#f0883e";
  if (cvss >= 4) return "#d29922";
  if (cvss > 0) return "#58a6ff";
  return "#30363d";
}

export function toFlowElements(
  packages: PackageNode[],
  graphEdges: GraphEdge[]
): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", nodesep: 48, ranksep: 64 });

  for (const p of packages) {
    g.setNode(p.id, { width: 180, height: 56 });
  }
  for (const e of graphEdges) {
    g.setEdge(e.source, e.target);
  }
  dagre.layout(g);

  const nodes: Node[] = packages.map((p) => {
    const pos = g.node(p.id);
    const border = cvssColor(p.maxCvss);
    return {
      id: p.id,
      position: { x: (pos?.x ?? 0) - 90, y: (pos?.y ?? 0) - 28 },
      data: {
        label: p.label,
        version: p.version,
        maxCvss: p.maxCvss,
        cveCount: p.cveCount,
        topCve: p.topCve,
        spawned: p.spawned,
      },
      style: {
        background: p.maxCvss >= 9 ? "#3d1214" : "#161b22",
        border: `2px solid ${border}`,
        borderRadius: 10,
        padding: "8px 12px",
        color: "#e6edf3",
        fontSize: 12,
        width: 180,
        boxShadow: p.spawned ? `0 0 12px ${border}55` : undefined,
      },
    };
  });

  const edges: Edge[] = graphEdges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    animated: e.animated ?? true,
    style: { stroke: "#58a6ff", strokeWidth: 2 },
  }));

  return { nodes, edges };
}
