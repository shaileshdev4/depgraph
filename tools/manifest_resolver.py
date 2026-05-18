"""Fetch and parse GitHub dependency manifests for multiple ecosystems."""

from __future__ import annotations

import base64
import os
from typing import Any

import requests

from tools.ecosystem_util import (
    AUTO_DETECT_ORDER,
    MANIFEST_CANDIDATES,
    normalize_ecosystem,
)
from tools.manifest_parsers import parse_manifest

try:
    from tools.env_util import ensure_dotenv_loaded  # type: ignore
except ImportError:

    def ensure_dotenv_loaded() -> None:
        pass


def parse_github_repo_url(repo_url: str) -> dict[str, Any]:
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    marker = "github.com/"
    if marker not in url:
        return {"ok": False, "error": "Not a github.com URL"}
    path = url.split(marker, 1)[1]
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return {"ok": False, "error": "Expected https://github.com/owner/repo"}
    return {"ok": True, "owner": parts[0], "repo": parts[1]}


def _github_headers(token: str) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _default_branch(owner: str, repo: str, headers: dict[str, str]) -> str:
    branch = "main"
    repo_api = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        resp = requests.get(repo_api, headers=headers, timeout=45)
        if resp.status_code == 200:
            body = resp.json()
            if isinstance(body, dict) and body.get("default_branch"):
                branch = str(body["default_branch"])
    except requests.RequestException:
        pass
    return branch


def fetch_github_file(
    repo_url: str,
    filename: str,
) -> dict[str, Any]:
    """Fetch a single file from a GitHub repo (raw URL, then Contents API)."""
    ensure_dotenv_loaded()
    parsed = parse_github_repo_url(repo_url)
    if not parsed["ok"]:
        return parsed

    owner = str(parsed["owner"])
    repo = str(parsed["repo"])
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = _github_headers(token)
    branch = _default_branch(owner, repo, headers)

    raw_url = (
        f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
    )
    try:
        resp = requests.get(raw_url, headers=headers, timeout=120)
        if resp.status_code == 200 and resp.text:
            return {
                "ok": True,
                "owner": owner,
                "repo": repo,
                "filename": filename,
                "text": resp.text,
                "branch": branch,
                "source": "raw",
            }
        if resp.status_code != 404:
            return {
                "ok": False,
                "error": f"raw fetch {resp.status_code}: {resp.text[:200]}",
                "owner": owner,
                "repo": repo,
            }
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc), "owner": owner, "repo": repo}

    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
    try:
        resp = requests.get(api_url, headers=headers, timeout=45)
        if resp.status_code == 404:
            return {
                "ok": False,
                "error": f"{filename} not found on default branch",
                "owner": owner,
                "repo": repo,
            }
        if resp.status_code != 200:
            return {
                "ok": False,
                "error": f"GitHub API {resp.status_code}: {resp.text[:200]}",
                "owner": owner,
                "repo": repo,
            }
        payload = resp.json()
        if isinstance(payload, list):
            return {
                "ok": False,
                "error": f"{filename} is a directory, not a file",
                "owner": owner,
                "repo": repo,
            }
        content_b64 = str(payload.get("content", "")).strip()
        text = ""
        if content_b64:
            text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        if not text:
            download_url = str(payload.get("download_url", "")).strip()
            if download_url:
                raw_resp = requests.get(download_url, headers=headers, timeout=120)
                if raw_resp.status_code == 200 and raw_resp.text:
                    text = raw_resp.text
        if not text:
            return {
                "ok": False,
                "error": f"{filename} empty via Contents API",
                "owner": owner,
                "repo": repo,
            }
        return {
            "ok": True,
            "owner": owner,
            "repo": repo,
            "filename": filename,
            "text": text,
            "source": "contents_api",
        }
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc), "owner": owner, "repo": repo}


def fetch_ecosystem_manifest(repo_url: str, ecosystem: str) -> dict[str, Any]:
    """Fetch the best manifest for a given ecosystem."""
    eco = normalize_ecosystem(ecosystem)
    if eco == "auto":
        return detect_and_fetch_manifest(repo_url)

    candidates = MANIFEST_CANDIDATES.get(eco, [])
    if not candidates:
        return {"ok": False, "error": f"Unsupported ecosystem: {ecosystem}"}

    errors: list[str] = []
    owner = ""
    repo = ""
    for filename, manifest_kind in candidates:
        result = fetch_github_file(repo_url, filename)
        owner = str(result.get("owner", owner))
        repo = str(result.get("repo", repo))
        if result.get("ok") and result.get("text"):
            result["manifest_kind"] = manifest_kind
            result["ecosystem"] = eco
            return result
        errors.append(f"{filename}: {result.get('error', 'missing')}")

    return {
        "ok": False,
        "error": (
            f"No manifest found for ecosystem '{eco}'. Tried: "
            + "; ".join(errors)
        ),
        "owner": owner,
        "repo": repo,
        "ecosystem": eco,
    }


def detect_and_fetch_manifest(repo_url: str) -> dict[str, Any]:
    """Auto-detect ecosystem by probing known manifest files."""
    errors: list[str] = []
    owner = ""
    repo = ""
    for eco in AUTO_DETECT_ORDER:
        for filename, manifest_kind in MANIFEST_CANDIDATES[eco]:
            result = fetch_github_file(repo_url, filename)
            owner = str(result.get("owner", owner))
            repo = str(result.get("repo", repo))
            if result.get("ok") and result.get("text"):
                result["manifest_kind"] = manifest_kind
                result["ecosystem"] = eco
                result["detected"] = True
                return result
            errors.append(f"{eco}/{filename}: {result.get('error', 'missing')}")
    return {
        "ok": False,
        "error": "Could not detect ecosystem — no known manifest found. " + "; ".join(
            errors[:8]
        ),
        "owner": owner,
        "repo": repo,
    }


def parse_ecosystem_manifest(
    manifest_text: str,
    ecosystem: str,
    manifest_kind: str,
    max_packages: int = 300,
) -> dict[str, Any]:
    return parse_manifest(manifest_text, ecosystem, manifest_kind, max_packages)
