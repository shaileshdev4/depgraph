"""Main orchestrator — manifest ingest, graph build, spawn subtree walkers."""

import from graph.nodes { InvestigationSession, Package, CVE }
import from graph.builder { build_package_graph }
import from tools.github_api { fetch_github_npm_manifest }
import from tools.jac_coerce { as_list }
import from tools.lockfile_parser { parse_npm_lockfile, parse_npm_package_json }
import from tools.risk_scorer { package_risk_score }
import from walkers.report_util { generate_executive_summary }
import from walkers.route_util { select_spawn_root_indexes }
import from walkers.subtree_walker { SubtreeWalker }

def _spawn_roots_fallback(candidates: list[Package], pick_count: int) -> list[Package] {
    if len(candidates) <= pick_count {
        return candidates;
    }
    selected: list[Package] = [];
    selected_names: dict = {};
    picks = 0;
    while picks < pick_count {
        best_idx = -1;
        best_score = -1;
        idx = 0;
        for pkg_node in candidates {
            if pkg_node.name in selected_names {
                idx += 1;
                continue;
            }
            score = package_risk_score(
                pkg_node.name,
                pkg_node.version,
                pkg_node.depth,
                pkg_node.is_direct
            );
            if score > best_score {
                best_score = score;
                best_idx = idx;
            }
            idx += 1;
        }
        if best_idx < 0 {
            break;
        }
        chosen = candidates[best_idx];
        selected.append(chosen);
        selected_names[chosen.name] = True;
        picks += 1;
    }
    return selected;
}

walker:pub DepGraphAgent {
    has repo_url: str;
    has ecosystem: str = "npm";
    has max_direct_deps: int = 8;
    has max_graph_packages: int = 200;
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

        if self.ecosystem != "npm" {
            report {
                "event": "error",
                "message": "Only npm is supported in this MVP"
            };
            disengage;
        }

        manifest_result = fetch_github_npm_manifest(self.repo_url);
        if not manifest_result["ok"] {
            report {"event": "error", "message": manifest_result["error"]};
            disengage;
        }

        manifest_kind = str(manifest_result.get("manifest_kind", "lockfile"));
        report {
            "event": "lockfile_fetched",
            "owner": manifest_result["owner"],
            "repo": manifest_result["repo"],
            "filename": manifest_result["filename"],
            "manifest_kind": manifest_kind
        };

        manifest_text: str = str(manifest_result["text"]);
        report {
            "event": "manifest_parsing",
            "filename": manifest_result["filename"],
            "bytes": len(manifest_text)
        };
        if manifest_kind == "package_json" {
            parsed = parse_npm_package_json(manifest_text);
        } else {
            parsed = parse_npm_lockfile(
                manifest_text,
                max_packages=self.max_graph_packages
            );
        }
        if not parsed["ok"] {
            report {"event": "error", "message": parsed["error"]};
            disengage;
        }
        truncated = False;
        if "truncated" in parsed {
            truncated = parsed["truncated"];
        }
        filter_method = "none";
        if "filter_method" in parsed {
            filter_method = str(parsed["filter_method"]);
        }
        original_cnt = parsed["package_count"];
        if "original_package_count" in parsed {
            original_cnt = parsed["original_package_count"];
        }
        report {
            "event": "manifest_parsed",
            "package_count": parsed["package_count"],
            "truncated": truncated,
            "original_package_count": original_cnt,
            "filter_method": filter_method
        };

        pkg_count = build_package_graph(session, parsed);
        edge_list = as_list(parsed.get("edges", []));
        edge_cnt = 0;
        for _x in edge_list {
            edge_cnt += 1;
        }
        report {
            "event": "graph_built",
            "package_count": pkg_count,
            "edge_count": edge_cnt,
            "truncated": truncated,
            "filter_method": filter_method
        };

        candidates: list[Package] = [];
        for pkg_node in [session-->][?:Package] {
            if pkg_node.is_direct and pkg_node.depth <= 1 {
                candidates.append(pkg_node);
            }
        }
        if not candidates {
            for pkg_node in [session-->][?:Package] {
                if pkg_node.depth == 0 {
                    continue;
                }
                candidates.append(pkg_node);
            }
        }

        descriptions = "";
        slot = 0;
        for pkg_node in candidates {
            risk = package_risk_score(
                pkg_node.name,
                pkg_node.version,
                pkg_node.depth,
                pkg_node.is_direct
            );
            descriptions = (
                f"{descriptions}{slot}) {pkg_node.name}@"
                f"{pkg_node.version} (risk={risk})\n"
            );
            slot += 1;
        }

        spawn_targets: list[Package] = [];
        spawn_mode = "fallback";
        report {
            "event": "spawn_decision",
            "candidate_count": len(candidates),
            "pick_count": self.max_direct_deps,
            "message": "LLM selecting subtree spawn roots"
        };
        try {
            raw_spawn = select_spawn_root_indexes(
                descriptions,
                self.max_direct_deps
            );
            if raw_spawn {
                spawn_mode = "llm";
                for pick in raw_spawn {
                    if pick >= 0 and pick < len(candidates) {
                        spawn_targets.append(candidates[pick]);
                    }
                    if len(spawn_targets) >= self.max_direct_deps {
                        break;
                    }
                }
            }
        } except Exception {
            spawn_mode = "fallback";
        }
        if not spawn_targets {
            spawn_targets = _spawn_roots_fallback(
                candidates,
                self.max_direct_deps
            );
            spawn_mode = "fallback";
        }

        spawned_names = "";
        for pkg_node in spawn_targets {
            spawned_names = f"{spawned_names}{pkg_node.name} ";
        }
        report {
            "event": "spawn_chosen",
            "mode": spawn_mode,
            "targets": spawned_names.strip(),
            "count": len(spawn_targets)
        };

        spawned = 0;
        lookup_count = 0;
        for pkg_node in spawn_targets {
            subtree = SubtreeWalker(
                depth_limit=3,
                max_visits=5
            ) spawn pkg_node;
            sub_lookups = subtree.osv_lookup_count;
            for entry in subtree.reports {
                report entry;
                if sub_lookups == 0 and "event" in entry {
                    if entry["event"] == "nvd_lookup" {
                        sub_lookups += 1;
                    }
                }
            }
            lookup_count += sub_lookups;
            spawned += 1;
        }

        report {
            "event": "subtrees_spawned",
            "spawn_count": spawned,
            "max_direct_deps": self.max_direct_deps,
            "spawn_mode": spawn_mode
        };

        findings: list[dict] = [];
        for pkg_node in [session-->][?:Package] {
            cve_nodes = [pkg_node-->][?:CVE];
            if not cve_nodes {
                continue;
            }
            max_cvss = 0.0;
            top_cve = "";
            for cve_node in cve_nodes {
                if cve_node.cvss_score > max_cvss {
                    max_cvss = cve_node.cvss_score;
                    top_cve = cve_node.cve_id;
                }
            }
            findings.append(
                {
                    "package": pkg_node.name,
                    "version": pkg_node.version,
                    "cve_count": len(cve_nodes),
                    "max_cvss": max_cvss,
                    "top_cve": top_cve
                }
            );
        }

        findings_lines = "";
        for item in findings {
            findings_lines = (
                f"{findings_lines}{item['package']}@{item['version']} "
                f"cvss={item['max_cvss']} ({item['top_cve']})\n"
            );
        }
        if not findings_lines {
            findings_lines = "No vulnerable packages in scanned subtrees.";
        }
        report {"event": "report_generating"};
        summary = "";
        try {
            summary = generate_executive_summary(
                self.repo_url,
                findings_lines,
                lookup_count,
                len(findings)
            );
        } except Exception {
            summary = (
                f"Scanned {lookup_count} packages across {spawned} subtrees. "
                f"Found {len(findings)} vulnerable package(s)."
            );
        }
        report {
            "event": "report_generated",
            "summary": summary
        };

        report {
            "event": "investigation_complete",
            "packages_scanned": lookup_count,
            "subtrees_spawned": spawned,
            "vulnerable_count": len(findings),
            "findings": findings,
            "executive_summary": summary
        };
    }
}
