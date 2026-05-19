"""Background investigation runner + session helpers for Jac."""

from __future__ import annotations

import os
import threading
from typing import Any

import requests

from tools.session_store import (
    append_event,
    create_session,
    finish_session,
    get_events,
    session_push,
)
from tools.summary_util import sanitize_executive_summary  # re-exported in __all__

_TIMEOUT = 900


def _resolve_api_base() -> str:
    """Local dev: PORT unset → 8001. Railway: PORT=8080 → loopback on same container."""
    explicit = os.environ.get("DEPGRAPH_API_BASE", "").strip()
    if explicit:
        return explicit.rstrip("/")
    port = os.environ.get("PORT", "").strip()
    if port:
        return f"http://127.0.0.1:{port}"
    return "http://127.0.0.1:8001"


def begin_async_investigation(
    repo_url: str,
    ecosystem: str = "npm",
    max_direct_deps: int = 8,
    api_base: str | None = None,
) -> str:
    base = (api_base or _resolve_api_base()).rstrip("/")
    start_url = f"{base}/walker/start_investigation"
    sid = create_session(repo_url)
    thread = threading.Thread(
        target=_run_investigation,
        args=(sid, repo_url, ecosystem, max_direct_deps, start_url),
        daemon=True,
    )
    thread.start()
    return sid


def _run_investigation(
    sid: str,
    repo_url: str,
    ecosystem: str,
    max_direct_deps: int,
    start_url: str,
) -> None:
    try:
        resp = requests.post(
            start_url,
            json={
                "repo_url": repo_url,
                "ecosystem": ecosystem,
                "max_direct_deps": max_direct_deps,
                "session_id": sid,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        finish_session(sid, "done")
    except Exception as exc:
        append_event(
            sid,
            {
                "event": "error",
                "message": str(exc),
            },
        )
        finish_session(sid, "error")


def _extract_reports(payload: dict[str, Any]) -> list[dict]:
    nested = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(nested, dict):
        reports = nested.get("reports")
        if isinstance(reports, list):
            return reports
        result = nested.get("result")
        if isinstance(result, dict) and isinstance(result.get("reports"), list):
            return result["reports"]
    if isinstance(payload.get("reports"), list):
        return payload["reports"]
    return []


def poll_status(session_id: str, since: int = 0) -> dict:
    return get_events(session_id, since)


__all__ = [
    "begin_async_investigation",
    "poll_status",
    "session_push",
    "create_session",
    "append_event",
    "finish_session",
    "sanitize_executive_summary",
]
