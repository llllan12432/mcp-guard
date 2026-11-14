"""Session state shared by every proxy process of one agent session.

An agent usually talks to several MCP servers, and each one gets its own proxy
process. The exfiltration chain crosses servers (read from `notes`, send with
`mail`), so "this session has read untrusted content" must be visible to all of
them. The state is therefore an append-only JSONL file of events:

    {"type": "taint",    "source": "notes.read_note", "reason": "..."}
    {"type": "pending",  "id": "ab12cd34", "tool": "mail.send_email", "arguments": {...}}
    {"type": "approved", "id": "ab12cd34"}
    {"type": "consumed", "id": "ab12cd34"}

Appending one short line is atomic on POSIX, so no locking is needed, and the
current state is always "replay the file". A session ends when the file is
deleted (`mcp-guard reset`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SessionState:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def _append(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    # -- taint -----------------------------------------------------------

    def add_taint(self, source: str, reason: str) -> None:
        self._append({"type": "taint", "source": source, "reason": reason})

    def taint(self) -> dict[str, Any] | None:
        """The first taint event, or None if the session is still clean. Taint never clears."""
        return next((event for event in self._events() if event["type"] == "taint"), None)

    # -- human approval of held calls -------------------------------------

    def add_pending(self, call_id: str, tool: str, arguments: dict[str, Any]) -> None:
        if call_id not in self.pending():
            self._append({"type": "pending", "id": call_id, "tool": tool, "arguments": arguments})

    def pending(self) -> dict[str, dict[str, Any]]:
        """Held calls that are still waiting for a decision, by approval id."""
        waiting: dict[str, dict[str, Any]] = {}
        for event in self._events():
            if event["type"] == "pending":
                waiting[event["id"]] = event
            elif event["type"] in ("approved", "consumed"):
                waiting.pop(event["id"], None)
        return waiting

    def approve(self, call_id: str) -> bool:
        """Approve one held call. Returns False if no such call is waiting."""
        if call_id not in self.pending():
            return False
        self._append({"type": "approved", "id": call_id})
        return True

    def consume_approval(self, call_id: str) -> bool:
        """True exactly once per approval: an approval allows a single call."""
        balance = 0
        for event in self._events():
            if event.get("id") == call_id:
                balance += {"approved": 1, "consumed": -1}.get(event["type"], 0)
        if balance <= 0:
            return False
        self._append({"type": "consumed", "id": call_id})
        return True

    def reset(self) -> None:
        self.path.unlink(missing_ok=True)
