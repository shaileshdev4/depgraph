import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  useEdgesState,
  useNodesState,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import { graphNodeTypes } from "./graphNodes";
import GraphHUD from "./GraphHUD";
import NodeTooltip from "./NodeTooltip";
import { SEVERITY_COLORS, severityFromCvss } from "../utils/severity";

// ── layout ──────────────────────────────────────────────────────────────────

function layoutGraph(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: "TB",
    nodesep: 90,
    ranksep: 120,
    marginx: 40,
    marginy: 40,
  });

  nodes.forEach((n) => {
    const h = n.type === "root" ? 80 : 76;
    const w = n.type === "root" ? 164 : 210;
    g.setNode(n.id, { width: w, height: h });
  });

  edges.forEach((e) => {
    try {
      g.setEdge(e.source, e.target);
    } catch (_) {}
  });

  dagre.layout(g);

  return nodes.map((n) => {
    const p = g.node(n.id);
    const w = n.type === "root" ? 164 : 210;
    const h = n.type === "root" ? 80 : 76;
    return {
      ...n,
      position: {
        x: (p?.x ?? 0) - w / 2,
        y: (p?.y ?? 0) - h / 2,
      },
    };
  });
}

// ── edge styles ──────────────────────────────────────────────────────────────

function edgeProps(type) {
  switch (type) {
    case "spawn_path":
      return {
        animated: true,
        style: { stroke: "#06b6d4", strokeWidth: 2, strokeDasharray: "8 4" },
        markerEnd: { type: "arrowclosed", color: "#06b6d4", width: 16, height: 16 },
      };
    case "critical_path":
      return {
        animated: true,
        style: { stroke: "#ef4444", strokeWidth: 2.5 },
        markerEnd: { type: "arrowclosed", color: "#ef4444", width: 18, height: 18 },
      };
    case "route_path":
      return {
        animated: true,
        style: { stroke: "#22c55e", strokeWidth: 2 },
        markerEnd: { type: "arrowclosed", color: "#22c55e", width: 16, height: 16 },
      };
    default:
      return {
        animated: false,
        style: { stroke: "#1e2d3d", strokeWidth: 1 },
        markerEnd: { type: "arrowclosed", color: "#1e2d3d", width: 12, height: 12 },
      };
  }
}

// ── component ────────────────────────────────────────────────────────────────

function styledRouteEdge(e, hotEdges, now) {
  const traversedAt = hotEdges?.get(e.id);
  const age = traversedAt ? now - traversedAt : Infinity;
  const isCritical = e.type === "critical_path";

  if (age < 800) {
    const stroke = isCritical ? "#ff2d55" : "#00ff88";
    return {
      ...e,
      type: "default",
      animated: true,
      style: {
        stroke,
        strokeWidth: 4,
        filter: `drop-shadow(0 0 6px ${stroke})`,
      },
      markerEnd: {
        type: "arrowclosed",
        color: stroke,
        width: 20,
        height: 20,
      },
    };
  }
  if (age < 2500) {
    const opacity = 1 - ((age - 800) / 1700) * 0.6;
    const stroke = isCritical ? "#ef4444" : "#22c55e";
    return {
      ...e,
      type: "default",
      animated: true,
      style: {
        stroke,
        strokeWidth: 2.5,
        opacity,
      },
      markerEnd: { type: "arrowclosed", color: stroke },
    };
  }
  return { ...e, type: "default", ...edgeProps(e.type) };
}

function buildFlowEdges(graphState, nodeIds, hotEdges, now) {
  const validEdge = (e) => nodeIds.has(e.source) && nodeIds.has(e.target);
  const depEdges = graphState.edges
    .filter(validEdge)
    .map((e) => ({ ...e, type: "default", ...edgeProps("depends_on") }));
  const spawnEdges = graphState.spawnEdges
    .filter(validEdge)
    .map((e) => ({ ...e, type: "default", ...edgeProps(e.type) }));
  const routeEdges = graphState.routeEdges
    .filter(validEdge)
    .map((e) => styledRouteEdge(e, hotEdges, now));
  return [...depEdges, ...spawnEdges, ...routeEdges];
}

export default function DependencyGraph({
  graphState,
  loading,
  showVisitedOnly,
  onToggleVisited,
  stats = {},
  running = false,
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [rf, setRf] = useState(null);
  const [hoverNode, setHoverNode] = useState(null);
  const [tipPos, setTipPos] = useState({ x: 0, y: 0 });
  const [hotEdgeAge, setHotEdgeAge] = useState(0);
  const containerRef = useRef(null);
  const lastStructureSig = useRef("");
  const didFitView = useRef(false);

  useEffect(() => {
    if (graphState.nodes.size === 0) {
      didFitView.current = false;
      lastStructureSig.current = "";
    }
  }, [graphState.nodes.size]);

  useEffect(() => {
    if (!running || !graphState.hotEdges?.size) return undefined;
    const interval = setInterval(() => setHotEdgeAge(Date.now()), 200);
    return () => clearInterval(interval);
  }, [running, graphState.hotEdges]);

  const visibleNodes = useMemo(() => {
    const list = [...graphState.nodes.values()];
    if (!showVisitedOnly) return list;
    return list.filter(
      (n) => n.visited || n.isSpawnRoot || n.kind === "root" || n.investigating
    );
  }, [graphState.nodes, showVisitedOnly]);

  const structureSig = useMemo(() => {
    const ids = visibleNodes
      .map((n) => n.id)
      .sort()
      .join("|");
    const dep = graphState.edges.map((e) => e.id).join(",");
    const spawn = graphState.spawnEdges.map((e) => e.id).join(",");
    const route = graphState.routeEdges.map((e) => e.id).join(",");
    return `${ids}::${dep}::${spawn}::${route}::${showVisitedOnly}`;
  }, [
    visibleNodes,
    graphState.edges,
    graphState.spawnEdges,
    graphState.routeEdges,
    showVisitedOnly,
  ]);

  const nodeDataSig = useMemo(
    () =>
      visibleNodes
        .map(
          (n) =>
            `${n.id}:${n.severity}:${n.cvss_score}:${n.visited}:${n.investigating}:${n.cve_count}:${n.isSpawnRoot}`
        )
        .join("|"),
    [visibleNodes]
  );

  useEffect(() => {
    const flowNodes = visibleNodes.map((n) => ({
      id: n.id,
      type: n.kind === "root" ? "root" : "package",
      data: n,
      position: { x: 0, y: 0 },
    }));

    const nodeIds = new Set(flowNodes.map((n) => n.id));
    const now = hotEdgeAge || Date.now();
    const allEdges = buildFlowEdges(graphState, nodeIds, graphState.hotEdges, now);

    if (flowNodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const structureChanged = structureSig !== lastStructureSig.current;

    if (structureChanged) {
      const laid = layoutGraph(flowNodes, allEdges);
      setNodes(laid);
      setEdges(allEdges);
      lastStructureSig.current = structureSig;
      if (!didFitView.current) {
        setTimeout(() => {
          rf?.fitView({ padding: 0.18, duration: 400 });
          didFitView.current = true;
        }, 120);
      }
      return;
    }

    setNodes((prev) => {
      const posById = new Map(prev.map((n) => [n.id, n.position]));
      return flowNodes.map((n) => ({
        ...n,
        position: posById.get(n.id) ?? n.position,
      }));
    });
    setEdges(allEdges);
  }, [
    structureSig,
    nodeDataSig,
    hotEdgeAge,
    visibleNodes,
    graphState,
    setNodes,
    setEdges,
    rf,
  ]);

  const onInit = useCallback((instance) => setRf(instance), []);

  const onNodeMouseEnter = useCallback((event, node) => {
    setHoverNode(node.data);
    const rect = containerRef.current?.getBoundingClientRect();
    if (rect) {
      setTipPos({
        x: event.clientX - rect.left + 14,
        y: event.clientY - rect.top - 10,
      });
    }
  }, []);

  const onNodeMouseLeave = useCallback(() => setHoverNode(null), []);

  // ── legend ────────────────────────────────────────────────────────────────

  const Legend = () => (
    <div
      style={{
        position: "absolute",
        top: "48px",
        right: "12px",
        zIndex: 10,
        background: "rgba(5,9,18,0.9)",
        border: "1px solid #1e2d3d",
        borderRadius: "8px",
        padding: "8px 12px",
        display: "flex",
        flexDirection: "column",
        gap: "4px",
        backdropFilter: "blur(8px)",
        maxWidth: "140px",
      }}
    >
      {[
        { color: "#ef4444", label: "Critical (9.0+)" },
        { color: "#f97316", label: "High (7.0-8.9)" },
        { color: "#eab308", label: "Medium (4.0-6.9)" },
        { color: "#06b6d4", label: "Spawn root" },
        { color: "#22c55e", label: "Visited" },
        { color: "#1e2d3d", label: "Unscanned" },
      ].map(({ color, label }) => (
        <div
          key={label}
          style={{ display: "flex", alignItems: "center", gap: "7px" }}
        >
          <div
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "2px",
              background: color,
              boxShadow: `0 0 4px ${color}`,
              flexShrink: 0,
            }}
          />
          <span style={{ fontSize: "9.5px", color: "#64748b" }}>{label}</span>
        </div>
      ))}
    </div>
  );

  // ── toolbar ───────────────────────────────────────────────────────────────

  const btnStyle = {
    fontSize: "11px",
    padding: "4px 10px",
    borderRadius: "6px",
    border: "1px solid #1e2d3d",
    background: "rgba(13,17,23,0.9)",
    color: "#94a3b8",
    cursor: "pointer",
    backdropFilter: "blur(6px)",
    transition: "border-color 0.15s, color 0.15s",
  };

  // ── empty / loading states ────────────────────────────────────────────────

  if (loading && graphState.nodes.size === 0) {
    return (
      <div
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "16px",
          color: "#64748b",
        }}
      >
        <div
          style={{
            width: "40px",
            height: "40px",
            borderRadius: "50%",
            border: "2px solid #1e2d3d",
            borderTop: "2px solid #06b6d4",
            animation: "depgraph-spin 0.8s linear infinite",
          }}
        />
        <span style={{ fontSize: "13px" }}>Building dependency graph…</span>
      </div>
    );
  }

  if (graphState.nodes.size === 0) {
    return (
      <div
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "12px",
          color: "#334155",
          padding: "24px",
          textAlign: "center",
        }}
      >
        <div style={{ fontSize: "32px", opacity: 0.3 }}>⬡</div>
        <p style={{ fontSize: "13px", lineHeight: "1.6", maxWidth: "280px" }}>
          Enter a GitHub repository URL above and click{" "}
          <span style={{ color: "#06b6d4" }}>Investigate</span> to render the
          risk-filtered dependency graph.
        </p>
      </div>
    );
  }

  // ── main render ───────────────────────────────────────────────────────────

  return (
    <div ref={containerRef} style={{ position: "relative", height: "100%", width: "100%" }}>
      {/* Toolbar */}
      <div
        style={{
          position: "absolute",
          top: "10px",
          left: "10px",
          zIndex: 10,
          display: "flex",
          gap: "6px",
        }}
      >
        <button style={btnStyle} onClick={() => rf?.zoomIn({ duration: 200 })}>+</button>
        <button style={btnStyle} onClick={() => rf?.zoomOut({ duration: 200 })}>−</button>
        <button style={btnStyle} onClick={() => rf?.fitView({ padding: 0.18, duration: 400 })}>Fit</button>
        <button
          style={{
            ...btnStyle,
            color: showVisitedOnly ? "#06b6d4" : "#94a3b8",
            borderColor: showVisitedOnly ? "#06b6d4" : "#1e2d3d",
          }}
          onClick={onToggleVisited}
        >
          {showVisitedOnly ? "All nodes" : "Visited only"}
        </button>
      </div>

      <GraphHUD stats={stats} running={running} />

      {/* Hover tooltip */}
      {hoverNode && (
        <div
          style={{
            position: "absolute",
            left: tipPos.x,
            top: tipPos.y,
            zIndex: 50,
            pointerEvents: "none",
          }}
        >
          <NodeTooltip node={hoverNode} />
        </div>
      )}

      <Legend />

      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(ellipse at 50% 30%, rgba(6,182,212,0.03) 0%, transparent 70%)",
          pointerEvents: "none",
          zIndex: 1,
        }}
      />

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onInit={onInit}
        onNodeMouseEnter={onNodeMouseEnter}
        onNodeMouseLeave={onNodeMouseLeave}
        nodeTypes={graphNodeTypes}
        minZoom={0.04}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
      >
        <Background
          variant={BackgroundVariant.Lines}
          color="#0d1a26"
          gap={28}
        />
        <Controls
          style={{
            button: {
              background: "rgba(13,17,23,0.9)",
              border: "1px solid #1e2d3d",
              color: "#64748b",
            },
          }}
        />
        <MiniMap
          nodeColor={(n) => {
            const cvss = Number(n.data?.cvss_score || 0);
            const hasCVE = (n.data?.cve_count || 0) > 0;
            if (hasCVE || cvss >= 4) {
              const sev = cvss > 0 ? severityFromCvss(cvss) : n.data?.severity || "CLEAN";
              return SEVERITY_COLORS[sev]?.border || SEVERITY_COLORS.CLEAN.border;
            }
            if (n.data?.isSpawnRoot) return SEVERITY_COLORS.SPAWN.border;
            if (n.data?.visited) return SEVERITY_COLORS.VISITED.border;
            return SEVERITY_COLORS.CLEAN.border;
          }}
          maskColor="rgba(5,9,18,0.88)"
          style={{
            background: "rgba(10,15,26,0.95)",
            border: "1px solid #1e2d3d",
            borderRadius: "8px",
          }}
          pannable
          zoomable
        />
      </ReactFlow>
    </div>
  );
}