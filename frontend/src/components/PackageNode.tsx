import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

type PkgData = {
  label: string;
  version: string;
  maxCvss: number;
  cveCount: number;
  topCve: string;
  spawned: boolean;
};

function PackageNodeCard({ data }: NodeProps) {
  const d = data as PkgData;
  return (
    <div>
      <Handle type="target" position={Position.Top} style={{ opacity: 0.4 }} />
      <div style={{ fontWeight: 600 }}>{d.label}</div>
      {d.version ? (
        <div style={{ color: "#8b949e", fontSize: 11 }}>@{d.version}</div>
      ) : null}
      {d.maxCvss > 0 ? (
        <div style={{ color: "#f0883e", fontSize: 11, marginTop: 4 }}>
          CVSS {d.maxCvss.toFixed(1)}
          {d.cveCount > 0 ? ` · ${d.cveCount} CVE` : ""}
        </div>
      ) : (
        <div style={{ color: "#6e7681", fontSize: 11, marginTop: 4 }}>
          {d.spawned ? "spawn root" : "investigated"}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0.4 }} />
    </div>
  );
}

export default memo(PackageNodeCard);
