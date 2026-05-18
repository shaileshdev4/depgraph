import type { Finding } from "../types";

function severityLabel(cvss: number): string {
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "INFO";
}

type Props = {
  findings: Finding[];
  summary: string;
};

export default function CVEPanel({ findings, summary }: Props) {
  return (
    <aside className="cve-panel">
      <h2>Vulnerable packages</h2>
      {findings.length === 0 ? (
        <p className="muted">No CVE matches in scanned subtrees.</p>
      ) : (
        <ul className="cve-list">
          {findings.map((f) => (
            <li
              key={`${f.package}@${f.version}`}
              className={`cve-card severity-${severityLabel(f.max_cvss).toLowerCase()}`}
            >
              <div className="cve-pkg">
                {f.package}@{f.version}
              </div>
              <span className="cve-badge">{severityLabel(f.max_cvss)}</span>
              <p className="cve-meta">
                {f.cve_count} CVE(s) · CVSS {f.max_cvss.toFixed(1)}
              </p>
              <a
                className="cve-link"
                href={`https://nvd.nist.gov/vuln/detail/${f.top_cve}`}
                target="_blank"
                rel="noreferrer"
              >
                {f.top_cve}
              </a>
            </li>
          ))}
        </ul>
      )}
      {summary ? (
        <>
          <h2>Executive summary</h2>
          <pre className="summary-block">{summary}</pre>
        </>
      ) : null}
    </aside>
  );
}
