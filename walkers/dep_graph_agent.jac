"""Main orchestrator — manifest ingest, graph build, spawn subtree walkers."""

import from graph.nodes { InvestigationSession, Package }

walker:pub DepGraphAgent {
    has repo_url: str;
    has ecosystem: str = "npm";
    has reports: list[dict] = [];

    can start with Root entry {
        session = InvestigationSession(
            repo_url=self.repo_url,
            ecosystem=self.ecosystem,
            status="running"
        );
        root ++> session;
        report {
            "event": "session_started",
            "repo_url": self.repo_url,
            "ecosystem": self.ecosystem
        };
        # TODO: lockfile parse → build Package graph → spawn SubtreeWalker per direct dep
        session.status = "graph_pending";
    }
}
