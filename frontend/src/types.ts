export type ReportEvent = {
  event: string;
  [key: string]: unknown;
};

export type Finding = {
  package: string;
  version: string;
  cve_count: number;
  max_cvss: number;
  top_cve: string;
};

export type PackageNode = {
  id: string;
  label: string;
  version: string;
  maxCvss: number;
  cveCount: number;
  topCve: string;
  spawned: boolean;
  investigated: boolean;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  animated?: boolean;
};

export type InvestigationResult = {
  reports: ReportEvent[];
  findings: Finding[];
  summary: string;
  logLines: string[];
};
