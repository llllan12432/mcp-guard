"""Structured decision log: one JSON object per line (JSONL).

Every decision the guard makes is written here, allow as well as block, so the
log is a complete audit trail. Fields: ts, server, event, tool, detector,
verdict, reason (+ latency_ms / approval_id / arguments when relevant).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class DecisionLog:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None  # None = do not write (used by the eval harness)

    def write(self, *, server: str, event: str, tool: str, detector: str, verdict: str, reason: str, **extra: Any) -> None:
        if self.path is None:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "server": server,
            "event": event,  # tool_description | tool_call | tool_result
            "tool": tool,
            "detector": detector,
            "verdict": verdict,  # allow | flag | block
            "reason": reason,
            **extra,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
