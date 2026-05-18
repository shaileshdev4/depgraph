"""Traverse a dependency subtree and attach CVE nodes from NVD."""

import from graph.nodes { Package, CVE }
import from tools.nvd_api { nvd_search_cve }

walker SubtreeWalker {
    has reports: list[dict] = [];

    can scan with Package entry {
        report {
            "event": "nvd_lookup",
            "package": here.name,
            "version": here.version,
            "depth": here.depth
        };

        cves = nvd_search_cve(here.name, here.version);
        max_cvss = 0.0;
        has_critical = False;
        for cve_data in cves {
            cve_node = CVE(
                cve_id=cve_data["cve_id"],
                cvss_score=cve_data["cvss_score"],
                severity=cve_data["severity"],
                description=cve_data["description"],
                fixed_version=cve_data["fixed_version"]
            );
            here ++> cve_node;
            if cve_data["cvss_score"] >= 9.0 {
                has_critical = True;
            }
            if cve_data["cvss_score"] > max_cvss {
                max_cvss = cve_data["cvss_score"];
            }
        }

        report {
            "event": "nvd_result",
            "package": here.name,
            "cve_count": len(cves),
            "max_cvss": max_cvss,
            "critical": has_critical
        };
    }
}
