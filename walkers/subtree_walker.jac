"""Traverse a dependency subtree: NVD/OSV lookup + LLM Route for next hop."""

import from graph.nodes { Package, CVE }
import from models.llm_config { routing_llm }
import from tools.cve_lookup { lookup_package_cves }

walker SubtreeWalker {
    has depth_limit: int = 3;
    has max_visits: int = 5;
    has visit_count: int = 0;
    has reports: list[dict] = [];

    can scan with Package entry {
        if here.depth > self.depth_limit {
            disengage;
        }
        if self.visit_count >= self.max_visits {
            disengage;
        }
        self.visit_count += 1;

        report {
            "event": "nvd_lookup",
            "package": here.name,
            "version": here.version,
            "depth": here.depth
        };

        cves = lookup_package_cves(here.name, here.version, "npm");
        max_cvss = 0.0;
        has_critical = False;
        source = "osv";
        for cve_data in cves {
            if cve_data.get("source", "") == "nvd" {
                source = "nvd";
            }
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
            "critical": has_critical,
            "source": source
        };

        if self.visit_count >= self.max_visits {
            disengage;
        }

        neighbors = [here-->][?:Package];
        neighbor_cnt = 0;
        for _n in neighbors {
            neighbor_cnt += 1;
        }
        if neighbor_cnt == 0 {
            disengage;
        }

        report {
            "event": "route_decision",
            "package": here.name,
            "neighbor_count": neighbor_cnt,
            "max_cvss": max_cvss,
            "message": "LLM selecting next dependency to investigate"
        };

        visit [-->][?:Package] by llm(
            incl_info={
                "current_package": here.name,
                "current_version": here.version,
                "cve_count": len(cves),
                "max_cvss": max_cvss,
                "critical": has_critical,
                "instruction": (
                    "You are routing a security investigation through a dependency "
                    "graph. Visit the outgoing Package neighbor that is most likely "
                    "to expose production risk (higher CVSS, auth/data paths, or "
                    "transitive exposure). Skip dev-only or already-safe branches."
                )
            },
            model=routing_llm
        );
    }
}
