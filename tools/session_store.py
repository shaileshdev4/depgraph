"""In-memory investigation sessions for live frontend polling."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any

_lock = threading.Lock()
_sessions: dict[str, dict[str, Any]] = {}


def create_session(repo_url: str) -> str:
    sid = str(uuid.uuid4())
    with _lock:
        _sessions[sid] = {
            "session_id": sid,
            "repo_url": repo_url,
            "status": "running",
            "events": [],
            "created_at": time.time(),
            "updated_at": time.time(),
        }
    return sid


def append_event(session_id: str, event: dict) -> None:
    if not session_id:
        return
    with _lock:
        session = _sessions.get(session_id)
        if not session:
            return
        row = dict(event)
        row["_idx"] = len(session["events"])
        row["_ts"] = time.time()
        session["events"].append(row)
        session["updated_at"] = time.time()
        if row.get("event") == "investigation_complete":
            session["status"] = "done"
        if row.get("event") == "error":
            session["status"] = "error"


def finish_session(session_id: str, status: str = "done") -> None:
    with _lock:
        session = _sessions.get(session_id)
        if session:
            session["status"] = status
            session["updated_at"] = time.time()


def get_events(session_id: str, since: int = 0) -> dict:
    with _lock:
        session = _sessions.get(session_id)
        if not session:
            return {
                "ok": False,
                "status": "missing",
                "events": [],
                "since": since,
                "next": since,
            }
        events = session["events"]
        start = max(0, int(since))
        chunk = events[start:]
        next_idx = start + len(chunk)
        return {
            "ok": True,
            "session_id": session_id,
            "status": session["status"],
            "repo_url": session.get("repo_url", ""),
            "events": chunk,
            "since": start,
            "next": next_idx,
            "total": len(events),
        }


def session_push(session_id: str, event: dict) -> None:
    append_event(session_id, event)
