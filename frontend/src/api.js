import axios from "axios";

/** Production (Vercel): set VITE_API_URL to your Railway Jac host, no trailing slash. */
const apiBase = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

const client = axios.create({
  baseURL: apiBase,
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

export function extractPollSnapshot(payload) {
  const reports = extractReports(payload);
  if (reports.length > 0) {
    return reports[0];
  }
  if (payload?.data && typeof payload.data === "object") {
    return payload.data;
  }
  return payload;
}

export async function startInvestigationAsync(repoUrl, ecosystem = "auto") {
  const { data } = await client.post("/walker/start_investigation_async", {
    repo_url: repoUrl.trim(),
    ecosystem: ecosystem || "auto",
    max_direct_deps: 8,
  });
  if (data?.ok === false || data?.error) {
    throw new Error(String(data.error || "Failed to start investigation"));
  }
  const reports = extractReports(data);
  const created = reports.find((r) => r.event === "session_created");
  if (created?.session_id) {
    return created.session_id;
  }
  throw new Error("No session_id returned from async start");
}

export async function pollInvestigation(sessionId, since = 0) {
  const { data } = await client.post("/walker/investigation_status", {
    session_id: sessionId,
    since,
  });
  return extractPollSnapshot(data);
}

/** Sync fallback — blocks until complete */
export async function startInvestigation(repoUrl, sessionId = "", ecosystem = "auto") {
  const { data } = await client.post("/walker/start_investigation", {
    repo_url: repoUrl.trim(),
    ecosystem: ecosystem || "auto",
    max_direct_deps: 8,
    session_id: sessionId,
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
