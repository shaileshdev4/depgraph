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
        for entry in result.reports {
            report entry;
        }
    }
}

to cl:

def:pub app -> JsxElement {
    has repo_url: str = "https://github.com/expressjs/express";
    has status: str = "idle";
    has log_text: str = "";
    has error: str = "";

    async def run_investigation() -> None {
        if not repo_url.strip() {
            error = "Enter a GitHub repository URL";
            return;
        }
        status = "running";
        error = "";
        log_text = "";
        try {
            result = root spawn start_investigation(
                repo_url=repo_url.strip(),
                ecosystem="npm"
            );
            if result.reports {
                lines = "";
                for entry in result.reports {
                    ev: str = str(entry["event"]) if "event" in entry else str(entry);
                    lines = f"{lines}- {ev}\n";
                }
                log_text = lines;
            }
            status = "done";
        } except Exception as e {
            error = str(e);
            status = "error";
        }
    }

    return
        <div
            style={{
                "minHeight": "100vh",
                "background": "#0b0f14",
                "color": "#e6edf3",
                "padding": "2.5rem",
                "fontFamily": "system-ui, sans-serif",
                "maxWidth": "48rem"
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
                    "marginTop": "1.5rem",
                    "padding": "0.75rem 1rem",
                    "borderRadius": "8px",
                    "border": "1px solid #30363d",
                    "background": "#161b22",
                    "color": "#e6edf3"
                }}
            />
            <button
                onClick={run_investigation}
                disabled={status == "running"}
                style={{
                    "marginTop": "1rem",
                    "padding": "0.65rem 1rem",
                    "borderRadius": "8px",
                    "border": "none",
                    "background": "#238636",
                    "color": "#fff",
                    "cursor": "pointer"
                }}
            >
                Investigate
            </button>
            <p style={{"color": "#f85149", "marginTop": "1rem"}}>
                {error}
            </p>
            <pre
                style={{
                    "marginTop": "1.5rem",
                    "padding": "1rem",
                    "background": "#161b22",
                    "border": "1px solid #30363d",
                    "borderRadius": "8px",
                    "fontSize": "0.8rem",
                    "whiteSpace": "pre-wrap"
                }}
            >
                {log_text}
            </pre>
        </div>;
}
