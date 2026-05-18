"""Traverse a dependency subtree: OSV lookup + LLM Route for next hop."""

import from graph.nodes { Package, CVE }
import from tools.cve_lookup { lookup_package_cves }
import from tools.jac_coerce { as_list }
import from walkers.deep_dive_walker { DeepDiveWalker }
import from walkers.route_util { choose_neighbor_indexes }

def neighbor_max_cvss(pkg_node: Package) -> float {
    best = pkg_node.cvss_score;
    for cve_node in [pkg_node-->][?:CVE] {
        if cve_node.cvss_score > best {
            best = cve_node.cvss_score;
        }
    }
    return best;
}

def pick_highest_cvss_neighbor_index(neighbor_list: list[Package]) -> int {
    best_idx = 0;
    best_cvss = -1.0;
    idx = 0;
    for pkg_node in neighbor_list {
        pkg_cvss = neighbor_max_cvss(pkg_node);
        if pkg_cvss > best_cvss {
            best_cvss = pkg_cvss;
            best_idx = idx;
        }
        idx += 1;
    }
    return best_idx;
}

walker SubtreeWalker {
    has depth_limit: int = 3;
    has max_visits: int = 5;
    has visit_count: int = 0;
    has osv_lookup_count: int = 0;
    has reports: list[dict] = [];

    can scan with Package entry {
        if here.depth > self.depth_limit {
            disengage;
        }
        if self.visit_count >= self.max_visits {
            disengage;
        }
        self.visit_count += 1;

        self.osv_lookup_count += 1;
        report {
            "event": "nvd_lookup",
            "package": here.name,
            "version": here.version,
            "depth": here.depth
        };

        cves = lookup_package_cves(here.name, here.version, "npm");
        max_cvss = 0.0;
        has_critical = False;
        top_cve_id = "";
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
                top_cve_id = str(cve_data["cve_id"]);
            }
        }

        if has_critical and top_cve_id {
            dive = DeepDiveWalker(
                target_name=here.name,
                target_version=here.version,
                cve_id=top_cve_id,
                cvss_score=max_cvss
            ) spawn here;
            for entry in dive.reports {
                report entry;
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

        neighbor_list: list[Package] = as_list([here-->][?:Package]);
        neighbor_cnt = len(neighbor_list);
        if neighbor_cnt == 0 {
            disengage;
        }

        descriptions = "";
        slot = 0;
        for pkg_node in neighbor_list {
            n_cvss = neighbor_max_cvss(pkg_node);
            descriptions = (
                f"{descriptions}{slot}) {pkg_node.name}@"
                f"{pkg_node.version} (known_cvss={n_cvss})\n"
            );
            slot += 1;
        }

        report {
            "event": "route_decision",
            "package": here.name,
            "neighbor_count": neighbor_cnt,
            "max_cvss": max_cvss,
            "cve_count": len(cves),
            "message": "LLM selecting next dependency to investigate"
        };

        fallback_idx = pick_highest_cvss_neighbor_index(neighbor_list);
        pick_indexes: list[int] = [fallback_idx];
        route_mode = "fallback";

        try {
            raw_picks = choose_neighbor_indexes(
                here.name,
                max_cvss,
                len(cves),
                descriptions
            );
            if raw_picks and len(raw_picks) == 1 {
                only = raw_picks[0];
                if only >= 0 and only < neighbor_cnt {
                    pick_indexes = [only];
                    route_mode = "llm";
                }
            } elif raw_picks and len(raw_picks) > 1 {
                route_mode = "fallback_multi";
            }
        } except Exception {
            route_mode = "fallback";
        }

        to_visit: list = [];
        for pick in pick_indexes {
            if pick >= 0 and pick < neighbor_cnt {
                to_visit.append(neighbor_list[pick]);
            }
        }
        if not to_visit {
            to_visit.append(neighbor_list[fallback_idx]);
            route_mode = "fallback";
            pick_indexes = [fallback_idx];
        }

        picked_names = "";
        for pkg_node in to_visit {
            picked_names = f"{picked_names}{pkg_node.name} ";
        }
        report {
            "event": "route_chosen",
            "from_package": here.name,
            "mode": route_mode,
            "indexes": pick_indexes,
            "targets": picked_names.strip()
        };

        visit to_visit;
    }
}
