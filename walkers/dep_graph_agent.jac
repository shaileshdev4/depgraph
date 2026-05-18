"""Main orchestrator — manifest ingest, graph build, spawn subtree walkers."""

import from graph.nodes { InvestigationSession, Package, CVE, UsageContext }
import from graph.builder { build_package_graph }
import from graph.snapshot_util {
    build_graph_snapshot,
    pkg_node_id,
    severity_from_cvss
}
import from tools.github_api {
    fetch_github_npm_manifest,
    parse_github_repo_url,
    search_github_package_imports
}
import from tools.jac_coerce { as_list }
import from tools.lockfile_parser { parse_npm_lockfile, parse_npm_package_json }
import from tools.risk_scorer { package_risk_score }
import from walkers.extract_walker { extract_usage_context }
import from walkers.remediation_walker { RemediationWalker }
import from walkers.report_util { generate_executive_summary }
import from walkers.route_util { select_spawn_root_index }
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

def _top_risk_candidates(
    candidates: list[Package],
    limit: int
) -> list[Package] {
    if len(candidates) <= limit {
        return candidates;
    }
    return _spawn_roots_fallback(candidates, limit);
}

walker:pub DepGraphAgent {
    has repo_url: str;
    has ecosystem: str = "npm";
    has max_direct_deps: int = 8;
    has max_graph_packages: int = 200;
    has max_spawn_llm_pool: int = 30;
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

        session_packages: list[Package] = [];
        for pkg_node in [session-->][?:Package] {
            session_packages.append(pkg_node);
        }
        snapshot = build_graph_snapshot(session_packages, parsed, []);
        report {
            "event": "graph_snapshot",
            "nodes": snapshot["nodes"],
            "edges": snapshot["edges"],
            "package_count": pkg_count,
            "edge_count": edge_cnt
        };

        owner_name = str(manifest_result["owner"]);
        repo_name = str(manifest_result["repo"]);
        for pkg_node in session_packages {
            if not pkg_node.is_direct or pkg_node.depth > 1 {
                continue;
            }
            paths = search_github_package_imports(
                owner_name,
                repo_name,
                pkg_node.name
            );
            path_text = "";
            for p in paths {
                path_text = f"{path_text}{p}\n";
            }
            if not path_text {
                path_text = "(no import paths found via GitHub search)";
            }
            usage_summary = "unknown";
            is_prod = True;
            try {
                ctx = extract_usage_context(pkg_node.name, path_text);
                if ctx and "risk_surface" in ctx {
                    usage_summary = str(ctx["risk_surface"]);
                }
                if ctx and "is_reachable_in_prod" in ctx {
                    is_prod = bool(ctx["is_reachable_in_prod"]);
                }
            } except Exception {
                usage_summary = "unknown";
            }
            usage_node = UsageContext(
                risk_surface=usage_summary,
                is_reachable_in_prod=is_prod,
                called_from_modules=paths
            );
            pkg_node ++> usage_node;
            report {
                "event": "usage_context",
                "package": pkg_node.name,
                "version": pkg_node.version,
                "risk_surface": usage_summary,
                "is_reachable_in_prod": is_prod,
                "import_file_count": len(paths)
            };
        }

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

        spawn_pool = _top_risk_candidates(
            candidates,
            self.max_spawn_llm_pool
        );

        spawn_targets: list[Package] = [];
        spawn_mode = "fallback";
        llm_spawn_picks = 0;
        spawn_llm_failures = 0;
        remaining_pool: list[Package] = [];
        for pkg_node in spawn_pool {
            remaining_pool.append(pkg_node);
        }

        report {
            "event": "spawn_decision",
            "candidate_count": len(candidates),
            "llm_pool_count": len(spawn_pool),
            "pick_count": self.max_direct_deps,
            "message": "LLM selecting subtree spawn roots from top risk pool"
        };

        while (
            len(spawn_targets) < self.max_direct_deps
            and len(remaining_pool) > 0
        ) {
            descriptions = "";
            slot = 0;
            for pkg_node in remaining_pool {
                descriptions = (
                    f"{descriptions}{slot}) {pkg_node.name}\n"
                );
                slot += 1;
            }

            picked_idx = -1;
            spawn_err = "";
            attempts = 0;
            while attempts < 2 and picked_idx < 0 {
                attempts += 1;
                try {
                    raw_spawn = select_spawn_root_index(descriptions);
                    if raw_spawn and len(raw_spawn) >= 1 {
                        pick = raw_spawn[0];
                        if pick >= 0 and pick < len(remaining_pool) {
                            picked_idx = pick;
                        }
                    }
                } except Exception as e {
                    spawn_err = str(e);
                }
            }
            if picked_idx < 0 {
                spawn_llm_failures += 1;
                risk_one = _spawn_roots_fallback(remaining_pool, 1);
                if not risk_one {
                    break;
                }
                chosen = risk_one[0];
            } else {
                chosen = remaining_pool[picked_idx];
                llm_spawn_picks += 1;
            }
            spawn_targets.append(chosen);
            next_pool: list[Package] = [];
            for pkg_node in remaining_pool {
                if pkg_node.name != chosen.name {
                    next_pool.append(pkg_node);
                }
            }
            remaining_pool = next_pool;
        }

        if llm_spawn_picks > 0 {
            spawn_mode = "llm";
        }
        if spawn_llm_failures > 0 and llm_spawn_picks == 0 {
            report {
                "event": "spawn_llm_failed",
                "reason": "All spawn LLM picks failed",
                "failures": spawn_llm_failures
            };
        } elif spawn_llm_failures > 0 {
            report {
                "event": "spawn_llm_partial",
                "llm_picks": llm_spawn_picks,
                "risk_picks": spawn_llm_failures,
                "message": "Some spawn picks used risk fallback after LLM empty response"
            };
        }
        if len(spawn_targets) < self.max_direct_deps {
            picked_names: dict = {};
            for pkg_node in spawn_targets {
                picked_names[pkg_node.name] = True;
            }
            extra_pool: list[Package] = [];
            for pkg_node in candidates {
                if pkg_node.name not in picked_names {
                    extra_pool.append(pkg_node);
                }
            }
            need = self.max_direct_deps - len(spawn_targets);
            extras = _spawn_roots_fallback(extra_pool, need);
            for pkg_node in extras {
                spawn_targets.append(pkg_node);
            }
            if llm_spawn_picks == 0 {
                spawn_mode = "fallback";
            }
        }

        spawned_names = "";
        for pkg_node in spawn_targets {
            spawned_names = f"{spawned_names}{pkg_node.name} ";
        }
        spawn_root_ids: list[str] = [];
        for pkg_node in spawn_targets {
            spawn_root_ids.append(pkg_node_id(pkg_node.name, pkg_node.version));
        }
        snapshot_after = build_graph_snapshot(
            session_packages,
            parsed,
            spawn_root_ids
        );
        report {
            "event": "spawn_roots",
            "roots": spawn_root_ids
        };
        report {
            "event": "graph_snapshot",
            "nodes": snapshot_after["nodes"],
            "edges": snapshot_after["edges"],
            "package_count": pkg_count,
            "edge_count": edge_cnt
        };

        report {
            "event": "spawn_chosen",
            "mode": spawn_mode,
            "targets": spawned_names.strip(),
            "count": len(spawn_targets),
            "llm_picks": llm_spawn_picks,
            "risk_picks": spawn_llm_failures
        };

        spawned = 0;
        lookup_count = 0;
        route_llm_count = 0;
        route_fallback_count = 0;
        deep_dive_names: dict = {};
        for pkg_node in spawn_targets {
            subtree = SubtreeWalker(
                depth_limit=3,
                max_visits=5
            ) spawn pkg_node;
            sub_lookups = subtree.osv_lookup_count;
            for entry in subtree.reports {
                report entry;
                if "event" in entry {
                    ev_name = str(entry["event"]);
                    if ev_name == "route_chosen" {
                        rmode = str(entry.get("mode", "fallback"));
                        if rmode == "llm" {
                            route_llm_count += 1;
                        } else {
                            route_fallback_count += 1;
                        }
                    }
                    if ev_name == "deep_dive" {
                        dp = str(entry.get("package", ""));
                        if dp {
                            deep_dive_names[dp] = True;
                        }
                    }
                }
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
            fixed_version = "";
            for cve_node in cve_nodes {
                if cve_node.cvss_score > max_cvss {
                    max_cvss = cve_node.cvss_score;
                    top_cve = cve_node.cve_id;
                }
                if cve_node.fixed_version and not fixed_version {
                    fixed_version = str(cve_node.fixed_version);
                }
            }
            findings.append(
                {
                    "package": pkg_node.name,
                    "version": pkg_node.version,
                    "cve_count": len(cve_nodes),
                    "max_cvss": max_cvss,
                    "top_cve": top_cve,
                    "severity": severity_from_cvss(max_cvss),
                    "depth": pkg_node.depth,
                    "is_direct": pkg_node.is_direct,
                    "deep_dive_triggered": pkg_node.name in deep_dive_names,
                    "fixed_version": fixed_version
                }
            );
        }

        for pkg_node in [session-->][?:Package] {
            cve_nodes = [pkg_node-->][?:CVE];
            if not cve_nodes {
                continue;
            }
            remed = RemediationWalker() spawn pkg_node;
            for entry in remed.reports {
                report entry;
            }
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
        critical_count = 0;
        for item in findings {
            if item["max_cvss"] >= 9.0 {
                critical_count += 1;
            }
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
            "packages_in_graph": pkg_count,
            "subtrees_spawned": spawned,
            "vulnerable_count": len(findings),
            "critical_count": critical_count,
            "spawn_mode": spawn_mode,
            "route_llm_count": route_llm_count,
            "route_fallback_count": route_fallback_count,
            "truncated": truncated,
            "original_package_count": original_cnt,
            "findings": findings,
            "executive_summary": summary
        };
    }
}
