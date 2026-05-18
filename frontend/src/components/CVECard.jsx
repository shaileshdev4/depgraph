const SEV_STYLES = {
  CRITICAL: "bg-red-600/20 text-red-400 border-red-500",
  HIGH: "bg-orange-600/20 text-orange-400 border-orange-500",
  MEDIUM: "bg-yellow-600/20 text-yellow-300 border-yellow-600",
  LOW: "bg-blue-600/20 text-blue-300 border-blue-500",
};

export default function CVECard({ finding }) {
  const sev = finding.severity || "LOW";
  const pill = SEV_STYLES[sev] || SEV_STYLES.LOW;
  const cveLink = finding.top_cve
    ? `https://nvd.nist.gov/vuln/detail/${finding.top_cve}`
  : null;

  return (
    <li className="rounded-lg border border-border bg-card p-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-semibold text-white text-sm">
            {finding.package}
            <span className="text-gray-500 font-normal">@{finding.version}</span>
          </div>
          <div className="text-xs text-gray-500 mt-0.5">depth {finding.depth ?? "?"}</div>
        </div>
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${pill}`}>
          {sev}
        </span>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold text-orange-400">
          {Number(finding.max_cvss).toFixed(1)}
        </span>
        <span className="text-xs text-gray-500">CVSS</span>
      </div>
      <p className="text-xs text-gray-400 mt-1">
        {finding.cve_count} CVE(s) · {finding.source || "osv"}
      </p>
      {cveLink && (
        <a
          href={cveLink}
          target="_blank"
          rel="noreferrer"
          className="text-xs text-blue-400 hover:underline mt-2 inline-block"
        >
          {finding.top_cve}
        </a>
      )}
      {finding.deep_dive_triggered && (
        <span className="mt-2 inline-block text-[10px] font-semibold text-red-400 border border-red-500/50 rounded px-2 py-0.5">
          Deep Dive triggered
        </span>
      )}
      {finding.fixed_version && (
        <p className="text-xs text-green-400 mt-1">Fix: {finding.fixed_version}</p>
      )}
    </li>
  );
}
