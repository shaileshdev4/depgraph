"""Spawned when a critical CVE is found — shallow transitive follow-up."""

import from graph.nodes { Package }

walker DeepDiveWalker {
    has target_name: str;
    has target_version: str;
    has cve_id: str;
    has cvss_score: float = 0.0;
    has max_visits: int = 3;
    has visit_count: int = 0;

    can analyze with Package entry {
        if self.visit_count >= self.max_visits {
            disengage;
        }
        self.visit_count += 1;

        report {
            "event": "deep_dive",
            "package": here.name,
            "version": here.version,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "depth": here.depth,
            "message": "Investigating transitive deps of critical finding"
        };

        if self.visit_count >= self.max_visits {
            disengage;
        }
        visit [here-->][?:Package];
    }
}
