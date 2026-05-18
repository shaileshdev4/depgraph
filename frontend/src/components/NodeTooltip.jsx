export default function NodeTooltip({ node }) {
  if (!node) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-xl">
      <div className="font-semibold text-white">{node.name}</div>
      <div className="text-gray-400">@{node.version}</div>
      <div className="mt-1 text-gray-300">Depth {node.depth}</div>
      {node.cvss_score > 0 && (
        <div className="text-orange-400">CVSS {node.cvss_score.toFixed(1)}</div>
      )}
      {node.cve_count > 0 && (
        <div className="text-red-400">{node.cve_count} CVE(s)</div>
      )}
    </div>
  );
}
