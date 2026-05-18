"""GitHub API helpers for fetching package manifests."""

import from tools.env_util { ensure_dotenv_loaded }

sem parse_github_repo_url = "Parse owner and repo from a github.com URL.";
sem fetch_github_lockfile = "Fetch package-lock.json text from a public or token-accessible repo.";

def parse_github_repo_url(repo_url: str) -> dict {
    url = repo_url.strip().rstrip("/");
    if url.endswith(".git") {
        url = url[0:-4];
    }
    marker = "github.com/";
    if marker not in url {
        return {"ok": False, "error": "Not a github.com URL"};
    }
    path = url.split(marker, 1)[1];
    parts = [p for p in path.split("/") if p];
    if len(parts) < 2 {
        return {"ok": False, "error": "Expected https://github.com/owner/repo"};
    }
    return {"ok": True, "owner": parts[0], "repo": parts[1]};
}

def fetch_github_lockfile(
    repo_url: str,
    filename: str = "package-lock.json"
) -> dict {
    ensure_dotenv_loaded();
    import base64;
    import os;
    import requests;

    parsed = parse_github_repo_url(repo_url);
    if not parsed["ok"] {
        return parsed;
    }
    owner = parsed["owner"];
    repo = parsed["repo"];
    token = os.environ.get("GITHUB_TOKEN", "");
    headers = {"Accept": "application/vnd.github+json"};
    if token {
        headers["Authorization"] = f"Bearer {token}";
    }
    api_url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    );
    resp = requests.get(api_url, headers=headers, timeout=45);
    if resp.status_code == 404 {
        return {
            "ok": False,
            "error": f"{filename} not found on default branch",
            "owner": owner,
            "repo": repo
        };
    }
    if resp.status_code != 200 {
        return {
            "ok": False,
            "error": f"GitHub API {resp.status_code}: {resp.text[:200]}",
            "owner": owner,
            "repo": repo
        };
    }
    payload = resp.json();
    if isinstance(payload, list) {
        return {
            "ok": False,
            "error": f"{filename} is a directory, not a file",
            "owner": owner,
            "repo": repo
        };
    }
    content_b64 = str(payload.get("content", ""));
    if not content_b64 {
        return {"ok": False, "error": "Empty file content", "owner": owner, "repo": repo};
    }
    text = base64.b64decode(content_b64).decode("utf-8", errors="replace");
    return {
        "ok": True,
        "owner": owner,
        "repo": repo,
        "filename": filename,
        "text": text
    };
}
