import type { InvestigationResult, ReportEvent } from "./types";
import { parseInvestigationReports } from "./parseReports";

type WalkerResponse = {
  reports?: ReportEvent[];
  result?: { reports?: ReportEvent[] };
};

export async function startInvestigation(
  repoUrl: string
): Promise<InvestigationResult> {
  const res = await fetch("/walker/start_investigation", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo_url: repoUrl.trim(),
      ecosystem: "npm",
      max_direct_deps: 8,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Investigation failed (${res.status})`);
  }

  const data = (await res.json()) as WalkerResponse;
  const reports =
    data.reports ??
    data.result?.reports ??
    [];

  return parseInvestigationReports(reports);
}
