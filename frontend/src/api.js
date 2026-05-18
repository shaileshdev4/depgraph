import axios from "axios";

const client = axios.create({
  headers: { "Content-Type": "application/json" },
});

export function extractReports(payload) {
  const nested = payload?.data;
  const reports =
    nested?.reports ??
    payload?.reports ??
    nested?.result?.reports ??
    payload?.result?.reports ??
    [];
  return Array.isArray(reports) ? reports : [];
}

export async function startInvestigation(repoUrl) {
  const { data } = await client.post("/walker/start_investigation", {
    repo_url: repoUrl.trim(),
    ecosystem: "npm",
    max_direct_deps: 8,
  });
  if (data?.ok === false || data?.error) {
    throw new Error(String(data.error || "Investigation failed"));
  }
  const reports = extractReports(data);
  if (!reports.length) {
    throw new Error(
      "No reports from server — is jac start running on port 8001?"
    );
  }
  return reports;
}
