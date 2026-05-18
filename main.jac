"""DepGraph — JacHacks 2026 entry point."""

import from walkers.dep_graph_agent { DepGraphAgent }

walker:pub start_investigation {
    has repo_url: str;
    has ecosystem: str = "npm";
    has reports: list[dict] = [];

    can run with Root entry {
        result = DepGraphAgent(
            repo_url=self.repo_url, ecosystem=self.ecosystem
        ) spawn root;
        report {
            "event": "investigation_complete",
            "reports": result.reports
        };
    }
}

to cl:

def:pub app -> JsxElement {
    has repo_url: str = "";

    return
        <div
            style={{
                "minHeight": "100vh",
                "background": "#0b0f14",
                "color": "#e6edf3",
                "padding": "2.5rem",
                "fontFamily": "system-ui, sans-serif"
            }}
        >
            <h1 style={{"margin": 0, "fontSize": "2rem"}}>DepGraph</h1>
            <p style={{"color": "#8b949e", "marginTop": "0.5rem"}}>
                Autonomous dependency vulnerability investigation
            </p>
            <input
                type="text"
                placeholder="https://github.com/owner/repo"
                value={repo_url}
                onChange={lambda e: ChangeEvent { repo_url = str(e.target.value); }}
                style={{
                    "width": "100%",
                    "maxWidth": "32rem",
                    "marginTop": "1.5rem",
                    "padding": "0.75rem 1rem",
                    "borderRadius": "8px",
                    "border": "1px solid #30363d",
                    "background": "#161b22",
                    "color": "#e6edf3"
                }}
            />
            <p style={{"color": "#6e7681", "marginTop": "1rem", "fontSize": "0.875rem"}}>
                Backend walkers wired — connect Investigate button in next commit.
            </p>
        </div>;
}
