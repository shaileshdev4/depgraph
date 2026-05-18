import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import { Handle, Position } from "@xyflow/react";
import { SEVERITY_COLORS } from "../utils/severity";

function PackageNodeView({ data }) {
  const sev = data.severity || "CLEAN";
  let palette = SEVERITY_COLORS[sev] || SEVERITY_COLORS.CLEAN;
  if (data.isSpawnRoot) palette = SEVERITY_COLORS.SPAWN;
  if (data.visited && sev === "CLEAN") palette = SEVERITY_COLORS.VISITED;
  const label =
    data.name.length > 20 ? `${data.name.slice(0, 18)}…` : data.name;

  return (
    <div
      className={`rounded-lg border px-2 py-1.5 text-[11px] min-w-[140px] ${
        data.investigating ? "animate-pulse ring-2 ring-cyan-400" : ""
      }`}
      style={{
        background: palette.bg,
        borderColor: palette.border,
        boxShadow: palette.glow,
        color: "#f3f4f6",
      }}
    >
      <Handle type="target" position={Position.Top} className="!opacity-30" />
      <div className="font-semibold">{label}</div>
      <div className="text-gray-400 text-[10px]">@{data.version}</div>
      {data.cvss_score > 0 && (
        <div className="text-orange-200 text-[10px]">
          CVSS {Number(data.cvss_score).toFixed(1)}
          {data.cve_count > 0 ? ` · ${data.cve_count} CVE` : ""}
        </div>
      )}
      <div className="text-[9px] text-gray-500 text-right">d{data.depth}</div>
      <Handle type="source" position={Position.Bottom} className="!opacity-30" />
    </div>
  );
}

const nodeTypes = { package: PackageNodeView };

function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", nodesep: 55, ranksep: 70 });
  nodes.forEach((n) => g.setNode(n.id, { width: 160, height: 58 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return {
      ...n,
      position: { x: (p?.x ?? 0) - 80, y: (p?.y ?? 0) - 29 },
    };
  });
}

export default function DependencyGraph({
  graphState,
  loading,
  showVisitedOnly,
  onToggleVisited,
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [rf, setRf] = useState(null);

  const graphNodes = useMemo(() => {
    const list = [...graphState.nodes.values()];
    if (!showVisitedOnly) return list;
    return list.filter((n) => n.visited || n.isSpawnRoot);
  }, [graphState, showVisitedOnly]);

  useEffect(() => {
    const flowNodes = graphNodes.map((n) => ({
      id: n.id,
      type: "package",
      data: n,
      position: { x: 0, y: 0 },
    }));
    const depEdges = graphState.edges.map((e) => ({
      ...e,
      animated: false,
      style: { stroke: "#555", strokeWidth: 1 },
      markerEnd: { type: "arrowclosed", color: "#555" },
    }));
    const routeEdges = graphState.routeEdges.map((e) => ({
      ...e,
      animated: true,
      style: { stroke: "#22c55e", strokeWidth: 2.5 },
      markerEnd: { type: "arrowclosed", color: "#22c55e" },
    }));
    const laid = layoutGraph(flowNodes, [...depEdges, ...routeEdges]);
    setNodes(laid);
    setEdges([...depEdges, ...routeEdges]);
    setTimeout(() => rf?.fitView({ padding: 0.2 }), 80);
  }, [graphNodes, graphState.edges, graphState.routeEdges, setNodes, setEdges, rf]);

  const onInit = useCallback((instance) => setRf(instance), []);

  if (loading && graphState.nodes.size === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500 animate-pulse">
        Building dependency graph…
      </div>
    );
  }

  if (graphState.nodes.size === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500 px-6 text-center">
        Run an investigation to render the full risk-filtered dependency graph.
      </div>
    );
  }

  return (
    <div className="relative h-full w-full">
      <div className="absolute top-2 left-2 z-10 flex gap-2">
        <button
          type="button"
          className="text-xs px-2 py-1 rounded bg-card border border-border"
          onClick={() => rf?.zoomIn()}
        >
          +
        </button>
        <button
          type="button"
          className="text-xs px-2 py-1 rounded bg-card border border-border"
          onClick={() => rf?.zoomOut()}
        >
          −
        </button>
        <button
          type="button"
          className="text-xs px-2 py-1 rounded bg-card border border-border"
          onClick={() => rf?.fitView({ padding: 0.2 })}
        >
          Fit
        </button>
        <button
          type="button"
          className="text-xs px-2 py-1 rounded bg-card border border-border"
          onClick={onToggleVisited}
        >
          {showVisitedOnly ? "All nodes" : "Visited only"}
        </button>
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onInit={onInit}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.05}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#222" gap={18} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            const s = n.data?.severity || "CLEAN";
            return SEVERITY_COLORS[s]?.border || "#333";
          }}
          maskColor="rgba(10,10,10,0.85)"
        />
      </ReactFlow>
    </div>
  );
}
