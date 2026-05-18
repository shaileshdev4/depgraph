"""Main orchestrator — manifest ingest, graph build, spawn subtree walkers."""

import from graph.nodes { InvestigationSession, Package }
import from graph.builder { build_package_graph }
import from tools.github_api { fetch_github_lockfile }
import from tools.jac_coerce { as_list }
import from tools.lockfile_parser { parse_npm_lockfile }
import from walkers.subtree_walker { SubtreeWalker }

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

        if self.ecosystem != "npm" {
            report {
                "event": "error",
                "message": "Only npm is supported in this MVP"
            };
            disengage;
        }

        lock_result = fetch_github_lockfile(self.repo_url);
        if not lock_result["ok"] {
            report {"event": "error", "message": lock_result["error"]};
            disengage;
        }

        report {
            "event": "lockfile_fetched",
            "owner": lock_result["owner"],
            "repo": lock_result["repo"],
            "filename": lock_result["filename"]
        };

        lock_text: str = str(lock_result["text"]);
        parsed = parse_npm_lockfile(lock_text);
        if not parsed["ok"] {
            report {"event": "error", "message": parsed["error"]};
            disengage;
        }

        pkg_count = build_package_graph(session, parsed);
        edge_list = as_list(parsed.get("edges", []));
        edge_cnt = 0;
        for _x in edge_list {
            edge_cnt += 1;
        }
        report {
            "event": "graph_built",
            "package_count": pkg_count,
            "edge_count": edge_cnt
        };

        spawned = 0;
        for pkg_node in [session-->][?:Package] {
            if pkg_node.is_direct and pkg_node.depth <= 1 {
                SubtreeWalker() spawn pkg_node;
                spawned += 1;
            }
        }
        if spawned == 0 {
            for pkg_node in [session-->][?:Package] {
                SubtreeWalker() spawn pkg_node;
                spawned += 1;
                break;
            }
        }

        report {"event": "subtrees_spawned", "spawn_count": spawned};
    }
}
