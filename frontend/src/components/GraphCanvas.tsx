import { useMemo } from "react";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import PackageNodeCard from "./PackageNode";
import { toFlowElements } from "../layout";
import type { GraphEdge, PackageNode } from "../types";

const nodeTypes: NodeTypes = { package: PackageNodeCard };

type Props = {
  packages: PackageNode[];
  edges: GraphEdge[];
};

export default function GraphCanvas({ packages, edges }: Props) {
  const { nodes, edges: flowEdges } = useMemo(
    () => toFlowElements(packages, edges),
    [packages, edges]
  );

  if (packages.length === 0) {
    return (
      <div className="graph-empty">
        Run an investigation to visualize the autonomous traversal path.
      </div>
    );
  }

  return (
    <div className="graph-panel">
      <ReactFlow
        nodes={nodes.map((n) => ({ ...n, type: "package" }))}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.2}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#21262d" gap={20} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            const cvss = (n.data as { maxCvss?: number }).maxCvss ?? 0;
            if (cvss >= 9) return "#f85149";
            if (cvss >= 7) return "#f0883e";
            if (cvss > 0) return "#58a6ff";
            return "#30363d";
          }}
          maskColor="rgba(11,15,20,0.85)"
        />
      </ReactFlow>
    </div>
  );
}
